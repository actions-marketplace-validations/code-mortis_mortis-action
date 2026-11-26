"""Publish PR reviews and verify that suggested edits fit the current diff."""

import hashlib
import http.client
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from itertools import batched
from pathlib import Path

from .github import (
    BOT,
    COMMENT_BODY_LIMIT,
    GitHubForbidden,
    GitHubRequestError,
    evidence_digest,
    finding_metadata,
)
from .markdown import (
    SEVERITIES,
    contains_rendered_credential,
    earlier_open_findings,
    finding_entry,
    overview,
    safe_text,
    severity_order,
)

SUMMARY_MARKER = "<!-- mortis-action:review -->"
DELIVERY_OUTCOMES = ("inline-posted", "inline-existing", "summary-only", "inline-routed", "inline-failed")


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


def finding_sections(delivery, prior, head, limit):
    """Keep findings without an inline thread first. Send the remaining rows to the job."""
    by_outcome = delivery.findings
    failed = by_outcome["inline-failed"]
    needs_detail = [*failed, *by_outcome["summary-only"], *by_outcome["inline-routed"]]
    inline = [*by_outcome["inline-posted"], *by_outcome["inline-existing"]]
    sections = [
        ("Findings with failed inline delivery or no inline thread" if failed else "Findings without an inline thread",
         needs_detail, head, False),
        ("Earlier open findings", prior, None, False),
        ("Verified fixes with open discussions", delivery.protected_fixes, None, True),
        ("Findings already visible inline", inline, head, True),
    ]
    visible, overflow = [], []
    count = 0
    for title, findings, revision, compact in sections:
        section = f"\n\n### {title}\n"
        first_visible = first_overflow = True
        for finding in sorted(findings, key=severity_order):
            row = "\n" + finding_entry(finding, revision, compact=compact)
            entry = section + row if first_visible else row
            size = len(entry.encode())
            if not overflow and size <= limit:
                visible.append(entry)
                limit -= size
                first_visible = False
            else:
                overflow.append(section + row if first_overflow else row)
                first_overflow = False
                count += 1
    return "".join(visible), "".join(overflow).strip(), count


@dataclass
class Delivery:
    findings: dict = field(default_factory=lambda: {outcome: [] for outcome in DELIVERY_OUTCOMES})
    protected_fixes: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    overflow: str = ""

    @property
    def counts(self):
        return {outcome: len(rows) for outcome, rows in self.findings.items()}

    @property
    def summary(self):
        c = self.counts
        return (f"Inline delivery · {c['inline-posted']} posted · {c['inline-existing']} already present"
                f" · {c['summary-only']} summary only · {c['inline-routed']} routed by severity · {c['inline-failed']} failed"
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


@dataclass
class InlineComment:
    marker: str
    payload: dict
    plain: dict | None = None
    findings: list = field(default_factory=list)


def wait_for_rate_limit(error, attempt):
    if attempt or error.retry_after is None or error.retry_after > 60:
        return False
    time.sleep(error.retry_after)
    return True


def post_batch(api, report, batch, posted, *, fallback=False):
    """Submit one review, reconciling its individual markers if the response was lost."""
    for attempt in range(2):
        head = report["head_sha"]
        if fallback:
            path, data = f"{api.pull}/comments", {**batch[0].plain, "commit_id": head}
        else:
            path = f"{api.pull}/reviews"
            data = {"event": "COMMENT", "commit_id": head, "body": "Mortis review findings.",
                    "comments": [item.payload for item in batch]}
        attempted_write = False
        try:
            if not api.is_current(report):
                return "stale"
            attempted_write = True
            result = api.request("POST", path, data, allow_invalid_anchor=True)
        except API_ERRORS as error:
            if isinstance(error, GitHubRequestError) and error.retry_after is not None:
                if wait_for_rate_limit(error, attempt):
                    continue
                return "throttled"
            if not attempted_write or isinstance(error, GitHubForbidden) or (
                isinstance(error, GitHubRequestError) and error.status < 500
            ):
                return "failed"
            try:
                confirmed = existing_markers(api)
            except API_ERRORS:
                return "failed"
            posted.update(item.marker for item in batch if item.marker in confirmed)
            batch = [item for item in batch if item.marker not in posted]
            if not batch:
                return "posted"
            continue
        if result is not None:
            posted.update(item.marker for item in batch)
            return "posted"
        # Isolate a rejected anchor while keeping the other findings in native reviews.
        if len(batch) > 1:
            mid = len(batch) // 2
            first = post_batch(api, report, batch[:mid], posted)
            if first in {"stale", "throttled"}:
                return first
            return post_batch(api, report, batch[mid:], posted)
        if not fallback and batch[0].plain is not None:
            return post_batch(api, report, batch, posted, fallback=True)
        return "failed"
    return "failed"


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


def prepare_inline(report, finding, lines, markers, threads, repo, workflow_python, threshold):
    head, path = report["head_sha"], finding["path"]
    if finding.get("source_sha", head) != head:
        return "summary-only"
    if lines is None:  # The PR files request failed.
        return "inline-failed"
    line = min((n for n, (_, _, added) in lines.items()
                if added and finding["start_line"] <= n <= finding["end_line"]), default=None)
    if line is None:
        return "summary-only"
    if threads and existing_thread(finding, line, threads):
        return "inline-existing"
    if markers is None:  # GitHub could not confirm which comments have already been posted.
        return "inline-failed"
    identity = [head, path, line, finding.get("title") or finding["content"]]
    marker = finding_marker([*identity, finding["content"]])
    legacy = markers.get(finding_marker(identity), "")
    if marker in markers or (legacy and len(" ".join(finding["content"].split())) < 400 and finding_text(finding) in legacy):
        return "inline-existing"
    if threads is None:  # A thread on an earlier head could already represent this finding.
        return "inline-failed"
    if finding["severity"] in SEVERITIES[threshold + 1:]:
        return "inline-routed"
    payload = {
        "body": f"{marker}\n{finding_metadata(finding, head)}{finding_text(finding)}",
        "path": path, "line": line, "side": "RIGHT",
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
            return InlineComment(marker, suggested, payload)
    return InlineComment(marker, payload)


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
    unreadable = False
    for thread_id, finding in threads.items():
        if (finding["id"], finding["source_sha"]) in verified:
            if not api.is_current(report):
                return False
            try:
                resolved = api.resolve_thread(thread_id)
                if resolved is False:
                    delivery.protected_fixes.append(finding)
                elif resolved is None:
                    unreadable = True
            except GitHubForbidden:
                delivery.warnings.append("GitHub denied permission to resolve review threads. Verified fixes remain in the report.")
                break
    if unreadable:
        delivery.warnings.append("Mortis could not verify the reply count for some review threads and left them open.")
    return True


ISSUES_START = "<!-- mortis-action:linked-issues -->"
ISSUES_END = "<!-- /mortis-action:linked-issues -->"


def previous_issues(previous):
    _, found, rest = previous.partition(ISSUES_START)
    content, end, _ = rest.partition(ISSUES_END)
    if not found or not end or len(content.encode()) > 16_384 or contains_rendered_credential(content):
        return ""
    return ("\n\n<details><summary>Previous linked-issue assessment, pending refresh</summary>\n\n"
            + ISSUES_START + content + ISSUES_END + "\n</details>")


def publish(api, report, heading, *, repo=None, workflow_python=None, threads=None, auto_resolve=False, issue_section=None,
            inline_min_severity="low", delivery=None):
    if inline_min_severity not in SEVERITIES:
        raise ValueError("Set inline-min-severity to low, medium, high, or critical.")
    threshold = SEVERITIES.index(inline_min_severity)
    if not api.is_current(report):
        return None
    existing = next((
        row for row in api.pages(api.issue)
        if (row.get("user") or {}).get("login") == BOT and (row.get("body") or "").startswith(SUMMARY_MARKER + "\n")
    ), None)
    previous = ""
    unchanged = (report.get("comparison") or {}).get("strategy") == "skipped_unchanged"
    if existing and (issue_section or unchanged):
        trusted = api.trusted_summary_body(existing)
        if trusted is None and unchanged:
            # The skipped run has no fresh overview to replace a temporarily unreadable one.
            trusted = api.trusted_summary_body(existing)
            if trusted is None:
                raise ValueError("Could not verify the previous review overview. Retry the run to update the PR summary.")
        if trusted and trusted.startswith(SUMMARY_MARKER + "\n"):
            previous = trusted

    if delivery is None:
        delivery = Delivery()
    findings = report["findings"]
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
                if threads is None:
                    threads = api.finding_threads() if markers else {}
            except API_ERRORS:
                pass  # A failed thread lookup leaves the REST markers available.
        pending = {}
        for finding in findings:
            lines = None if diff is None else diff.get(finding["path"], {})
            route = prepare_inline(report, finding, lines, markers, threads, repo, workflow_python, threshold)
            if isinstance(route, InlineComment):
                pending.setdefault(route.marker, route).findings.append(finding)
            else:
                delivery.findings[route].append(finding)
        posted = set()
        for batch in batched(pending.values(), 25):
            outcome = post_batch(api, report, batch, posted)
            if outcome == "stale":
                return None
            if outcome == "throttled":
                break
        for item in pending.values():
            if item.marker in posted:
                delivery.findings["inline-posted"].append(item.findings[0])
                delivery.findings["inline-existing"].extend(item.findings[1:])
            else:
                delivery.findings["inline-failed"].extend(item.findings)
    if delivery.findings["inline-failed"]:
        delivery.warnings.append("GitHub could not confirm delivery of all inline comments. See the PR summary for affected findings.")

    prefix = f"{SUMMARY_MARKER}\n{heading}" + change_overview(report, previous)
    prior = earlier_open_findings(report)
    run_id = os.environ.get("GITHUB_RUN_ID")
    server, repository = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
    destination = (f"[workflow run summary]({server.rstrip('/')}/{repository}/actions/runs/{run_id}#summary)"
                   if server and repository and run_id else "workflow run summary")

    def write_summary(extra):
        nonlocal existing
        body = prefix + "\n\n" + delivery.summary
        notice = f" additional finding(s) are indexed in the {destination}."
        # Keep the assessment and its reusable cache in the PR comment when findings overflow.
        remaining = COMMENT_BODY_LIMIT - len((body + notice).encode()) - 24
        if extra and len(extra.encode()) > remaining:
            extra = "\n\nLinked-issue assessment omitted to fit the comment."
        visible, overflow, omitted = finding_sections(delivery, prior, report["head_sha"], remaining - len(extra.encode()))
        body += visible
        if omitted:
            body += f"\n\n{omitted}{notice}"
        body += extra
        if len(body.encode()) > COMMENT_BODY_LIMIT:
            raise ValueError("The required Mortis PR summary exceeds the comment size limit.")
        for attempt in range(2):
            try:
                if not api.is_current(report):
                    return False
                if existing is None:
                    existing = api.request("POST", api.issue, {"body": body})
                elif existing["body"] != body:
                    api.request("PATCH", f"/issues/comments/{existing['id']}", {"body": body})
                    existing = {**existing, "body": body}
                break
            except GitHubRequestError as error:
                if not wait_for_rate_limit(error, attempt):
                    raise
        delivery.overflow = "## Additional Mortis findings\n\n" + overflow if overflow else ""
        return True

    carry = previous_issues(previous) if issue_section else ""
    if not write_summary(carry):
        return None
    if auto_resolve:
        warnings = len(delivery.warnings)
        if not resolve_verified(api, report, threads, delivery):
            return None
        if warnings != len(delivery.warnings) or delivery.protected_fixes:
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
