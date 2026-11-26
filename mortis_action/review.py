"""Publish PR reviews and verify that suggested edits fit the current diff."""

import hashlib
import http.client
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .github import (
    BOT,
    COMMENT_BODY_LIMIT,
    GitHubForbidden,
    GitHubRequestError,
    evidence_digest,
    finding_metadata,
)
from .markdown import earlier_open_findings, overview, safe_text

SUMMARY_MARKER = "<!-- mortis-action:review -->"


def right_side_lines(patch):
    line = None
    hunk = 0
    for row in patch.split("\n"):
        if row.startswith("@@"):
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", row)
            line = int(match[1]) if match else None
            hunk += 1
        elif line is not None and row.startswith(("+", " ")):
            yield line, (hunk, row[1:].removesuffix("\r"), row.startswith("+"))
            line += 1


def suggested_change(finding, head, lines):
    if finding.get("source_sha") != head or not (finding.get("assessment") or {}).get("suggestion_supported"):
        return None
    existing = (finding.get("existing_code") or "").replace("\r\n", "\n").removesuffix("\n")
    replacement = (finding.get("suggestion_code") or "").replace("\r\n", "\n").removesuffix("\n")
    if not existing.strip() or not replacement.strip() or replacement == existing:
        return None
    if "\x00" in replacement or "\r" in replacement or any(
        line.lstrip().startswith("```") for line in replacement.splitlines()
    ):
        return None

    start, end = finding["start_line"], finding["end_line"]
    original = existing.split("\n")
    first = lines.get(start)
    if first is None or len(original) != end - start + 1:
        return None
    for number, text in enumerate(original, start):
        row = lines.get(number)
        if row is None or row[:2] != (first[0], text):
            return None
    return replacement


def valid_workflow_replacement(repo, python, head, finding, replacement):
    if repo is None or python is None:
        return False
    try:
        source = subprocess.check_output(
            ["git", "-C", repo, "cat-file", "blob", f"{head}:{finding['path']}"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8").replace("\r\n", "\n")
        lines = source.split("\n")
        start, end = finding["start_line"], finding["end_line"]
        existing = finding["existing_code"].replace("\r\n", "\n").removesuffix("\n")
        if "\n".join(lines[start - 1:end]) != existing:
            return False
        updated = "\n".join([*lines[:start - 1], replacement, *lines[end:]])
        validator = Path(__file__).with_name("validate_workflow.py")
        return subprocess.run(
            [python, "-I", validator], check=False, input=updated, encoding="utf-8", capture_output=True,
        ).returncode == 0
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return False


def finding_text(finding):
    location = f"{finding['path']}:{finding['start_line']}"
    return (
        f"**{safe_text(finding['severity'], 20)}** · {safe_text(location, 300)}"
        f" — {safe_text(finding['content'], 400)}"
    )


def finding_list(label, findings, limit):
    if not findings:
        return "", 0
    body = f"\n\n### {label}"
    for index, finding in enumerate(findings):
        item = "\n\n- " + finding_text(finding)
        if len((body + item).encode()) > limit - 100:
            return body + f"\n\n{len(findings) - index} additional findings are in the full report.", index
        body += item
    return body, len(findings)


@dataclass
class Delivery:
    counts: dict = field(default_factory=lambda: dict.fromkeys(
        ("inline-posted", "inline-existing", "summary-only", "inline-failed"), 0,
    ))
    warnings: list = field(default_factory=list)

    @property
    def summary(self):
        c = self.counts
        return (f"Inline delivery · {c['inline-posted']} posted · {c['inline-existing']} already present"
                f" · {c['summary-only']} summary only · {c['inline-failed']} failed"
                + "".join(f"\n\n{warning}" for warning in self.warnings))


API_ERRORS = (ValueError, OSError, http.client.HTTPException)
OVERVIEW_START = "<!-- mortis-action:overview "
OVERVIEW_END = "<!-- /mortis-action:overview -->"


def change_overview(report, previous):
    content = overview(report)
    comparison = report.get("comparison") or {}
    if not content and comparison.get("strategy") == "skipped_unchanged":
        # Only reuse the overview that described the compatible baseline.
        baseline = comparison.get("baseline_head_sha") or report["head_sha"]
        start = f"{OVERVIEW_START}{report['base_sha']} {baseline} -->"
        if start in previous:
            block, end, _ = previous.split(start, 1)[1].partition(OVERVIEW_END)
            if end:
                content = block.rstrip()
        elif OVERVIEW_START not in previous and "\n\nInline delivery ·" not in previous:
            # Before overview markers the narrative followed the status line and optional file lists.
            header = re.search(r"^\*\*\w+\*\* · Commit " + re.escape(baseline[:12]) + r" · [^\n]+$", previous, re.MULTILINE)
            if header:
                block = previous[header.end():].split("\n\n### Findings", 1)[0].split("\n\n### Earlier open findings", 1)[0]
                block = block.rpartition("</details>")[2]
                content = re.sub(r"^(?:\n\n(?:Set MORTIS_STATE_KEY|Review history could not|Mortis could not|"
                                 r"Some Mortis threads|The installed Mortis Engine)[^\n]+)+", "", block)
    if not content or len(content.encode()) > 24_000:
        return ""
    return f"\n\n{OVERVIEW_START}{report['base_sha']} {report['head_sha']} -->{content}\n{OVERVIEW_END}"


def existing_markers(api):
    return {
        row["body"].splitlines()[0]: row["body"]
        for row in api.pages(f"{api.pull}/comments")
        if (row.get("user") or {}).get("login") == BOT and not row.get("in_reply_to_id")
        and (row.get("body") or "").startswith("<!-- mortis-action:finding:")
    }


def finding_marker(identity):
    digest = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
    return f"<!-- mortis-action:finding:{digest} -->"


def post_inline(api, report, payload, marker):
    """Reconcile an ambiguous write before a single retry against the same head."""
    for _ in range(2):
        if not api.is_current(report):
            return "stale"
        try:
            row = api.request("POST", f"{api.pull}/comments", payload, allow_invalid_anchor=True)
            return "inline-posted" if row else "rejected"
        except API_ERRORS as error:
            if isinstance(error, GitHubForbidden) or (isinstance(error, GitHubRequestError) and error.status < 500):
                return "inline-failed"
            try:
                if marker in existing_markers(api):
                    return "inline-posted"
            except API_ERRORS:
                return "inline-failed"
    return "inline-failed"


def existing_thread(finding, line, threads):
    locations = ((finding["path"], line, line), (finding["path"], finding["start_line"], finding["end_line"]))
    content = " ".join(finding["content"].split())
    digest = evidence_digest(content)
    for prior in threads.values():
        if finding.get("id") and finding["id"] == prior["id"]:
            return True
        if prior.get("github_anchor") in locations:
            if "evidence_digest" in prior:
                if prior["evidence_digest"] == digest:
                    return True
            elif len(content) < 400 and prior.get("content") == content:
                return True
    return False


def deliver_inline(api, report, finding, lines, markers, threads, repo, workflow_python):
    head, path = report["head_sha"], finding["path"]
    if finding.get("source_sha", head) != head:
        return "summary-only"
    if lines is None:  # The PR files request failed.
        return "inline-failed"
    line = min((n for n, (_, _, added) in lines.items()
                if added and finding["start_line"] <= n <= finding["end_line"]), default=None)
    if line is None:
        return "summary-only"
    if existing_thread(finding, line, threads):
        return "inline-existing"
    if markers is None:  # GitHub could not confirm which comments have already been posted.
        return "inline-failed"
    identity = [head, path, line, finding.get("title") or finding["content"]]
    marker = finding_marker([*identity, finding["content"]])
    legacy = markers.get(finding_marker(identity), "")
    if marker in markers or (legacy and len(" ".join(finding["content"].split())) < 400 and finding_text(finding) in legacy):
        return "inline-existing"
    payload = {
        "body": f"{marker}\n{finding_metadata(finding, head)}{finding_text(finding)}",
        "commit_id": head, "path": path, "line": line, "side": "RIGHT",
    }
    replacement = suggested_change(finding, head, lines)
    if (replacement and Path(path).parent == Path(".github/workflows") and path.endswith((".yml", ".yaml"))
            and not valid_workflow_replacement(repo, workflow_python, head, finding, replacement)):
        replacement = None
    if replacement:
        body = payload["body"] + f"\n\n```suggestion\n{replacement}\n```"
        if len(body.encode()) <= COMMENT_BODY_LIMIT:
            start, end = finding["start_line"], finding["end_line"]
            suggested = {**payload, "body": body, "line": end}
            if start != end:
                suggested.update(start_line=start, start_side="RIGHT")
            outcome = post_inline(api, report, suggested, marker)
            if outcome != "rejected":
                if outcome == "inline-posted":
                    markers[marker] = body
                return outcome
    outcome = post_inline(api, report, payload, marker)
    if outcome == "inline-posted":
        markers[marker] = payload["body"]
    return "inline-failed" if outcome == "rejected" else outcome


def resolve_verified(api, report, threads, delivery):
    if (not threads or report["status"] not in {"completed", "skipped"}
            or report.get("workflow_status") != "completed" or report["coverage"].get("waived")):
        return True
    verified = {
        (row["id"], verification["original_sha"])
        for row in report.get("history", [])
        if row["status"] == "resolved" and (verification := row.get("verification"))
        and verification["status"] == "completed" and verification["verdict"] == "fixed"
        and verification["head_sha"] == report["head_sha"]
    }
    for thread_id, finding in threads.items():
        if (finding["id"], finding["source_sha"]) in verified:
            if not api.is_current(report):
                return False
            try:
                api.resolve_thread(thread_id)
            except GitHubForbidden:
                delivery.warnings.append("GitHub denied permission to resolve review threads. Verified fixes remain in the report.")
                break
    return True


ISSUES_START = "<!-- mortis-action:linked-issues -->"
ISSUES_END = "<!-- /mortis-action:linked-issues -->"


def previous_issues(previous):
    _, found, rest = previous.partition(ISSUES_START)
    content, end, _ = rest.partition(ISSUES_END)
    if not found or not end or len(content.encode()) > 16_384:
        return ""
    return ("\n\n<details><summary>Previous linked-issue assessment, pending refresh</summary>\n\n"
            + ISSUES_START + content + ISSUES_END + "\n</details>")


def publish(api, report, heading, *, repo=None, workflow_python=None, threads=None, auto_resolve=False, issue_section=None):
    if not api.is_current(report):
        return None
    existing = next((
        row for row in api.pages(api.issue)
        if (row.get("user") or {}).get("login") == BOT and (row.get("body") or "").startswith(SUMMARY_MARKER + "\n")
    ), None)
    previous = ""
    if existing and (issue_section or (report.get("comparison") or {}).get("strategy") == "skipped_unchanged"):
        trusted = api.trusted_summary_body(existing)
        if trusted.startswith(SUMMARY_MARKER + "\n"):
            previous = trusted

    delivery = Delivery()
    findings = report["findings"]
    failed, others = [], []
    if findings:
        paths = {finding["path"] for finding in findings}
        try:
            diff = {file["filename"]: dict(right_side_lines(file.get("patch") or ""))
                    for file in api.pages(f"{api.pull}/files") if file["filename"] in paths}
        except API_ERRORS:
            diff = None
        markers = None
        if diff:
            try:
                markers = existing_markers(api)
                if threads is None and markers:
                    threads = api.finding_threads()
            except API_ERRORS:
                markers = None
        for finding in findings:
            lines = None if diff is None else diff.get(finding["path"], {})
            outcome = deliver_inline(api, report, finding, lines, markers, threads or {}, repo, workflow_python)
            if outcome == "stale":
                return None
            delivery.counts[outcome] += 1
            (failed if outcome == "inline-failed" else others).append(finding)
    if failed:
        delivery.warnings.append("GitHub could not confirm delivery of all inline comments. See the PR summary for affected findings.")

    prefix = f"{SUMMARY_MARKER}\n{heading}" + change_overview(report, previous)
    prior = earlier_open_findings(report)

    def write_summary(extra, *, required=False):
        nonlocal existing
        body = prefix + "\n\n" + delivery.summary
        # Reserve room for an explicit overflow count. Failed inline findings have priority.
        remaining = COMMENT_BODY_LIMIT - len(body.encode()) - 240
        failures, shown = finding_list("Findings with failed inline delivery", failed, remaining)
        remaining -= len(failures.encode())
        if len(extra.encode()) > remaining:
            extra = "\n\nLinked-issue assessment omitted to fit the comment." if extra else ""
        remaining -= len(extra.encode())
        earlier, _ = finding_list("Earlier open findings", prior, remaining // 2 if others else remaining)
        current, _ = finding_list("Findings", others, remaining - len(earlier.encode()))
        omitted = len(failed) - shown
        overflow = f"\n\n{omitted} failed inline findings could not fit in the PR summary. See the full report." if omitted else ""
        body += failures + overflow + current + earlier + extra
        if len(body.encode()) > COMMENT_BODY_LIMIT or (omitted and not required):
            raise ValueError("The required Mortis PR summary exceeds the comment size limit.")
        if not api.is_current(report):
            return False
        if existing is None:
            existing = api.request("POST", api.issue, {"body": body})
        elif existing["body"] != body:
            api.request("PATCH", f"/issues/comments/{existing['id']}", {"body": body})
            existing = {**existing, "body": body}
        if omitted:
            raise ValueError(f"{omitted} failed inline findings could not fit in the PR summary. See the full report.")
        return True

    carry = previous_issues(previous) if issue_section else ""
    if not write_summary(carry, required=True):
        return None
    if auto_resolve:
        warnings = len(delivery.warnings)
        if not resolve_verified(api, report, threads, delivery):
            return None
        if warnings != len(delivery.warnings):
            try:
                if not write_summary(carry):
                    return None
            except API_ERRORS:
                delivery.warnings.append("The review was published, but GitHub could not add the thread-resolution warning to its summary.")
    if issue_section:
        try:
            if not api.is_current(report):
                return None
            section = issue_section(previous)
            extra = f"\n\n{ISSUES_START}{section}\n{ISSUES_END}" if section else ""
            if not write_summary(extra):
                return None
        except API_ERRORS:
            delivery.warnings.append("The review was published, but the linked-issue assessment could not be updated.")
    return delivery
