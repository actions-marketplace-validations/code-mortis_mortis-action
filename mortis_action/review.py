"""Publish PR reviews and verify that suggested edits fit the current diff."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

from .github import BOT, COMMENT_BODY_LIMIT, finding_metadata
from .markdown import overview, safe_text

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


def publish(api, report, heading, *, repo=None, workflow_python=None, threads=None):
    if not api.is_current(report):
        return False
    findings = report["findings"]
    body = f"{SUMMARY_MARKER}\n{heading}" + overview(report)
    if findings:
        body += "\n\n### Findings"
    for finding in findings:
        item = "\n\n- " + finding_text(finding)
        if len((body + item).encode()) > COMMENT_BODY_LIMIT:
            body += "\n\nAdditional findings are available in the full report."
            break
        body += item

    existing = next(
        (
            row
            for row in api.pages(api.issue)
            if row["user"]["login"] == BOT and row["body"].startswith(SUMMARY_MARKER)
        ),
        None,
    )
    if not api.is_current(report):
        return False
    if existing is None:
        api.request("POST", api.issue, {"body": body})
    elif existing["body"] != body:
        api.request("PATCH", f"/issues/comments/{existing['id']}", {"body": body})

    threads = threads or {}
    if (
        threads and report["status"] in {"completed", "skipped"}
        and report.get("workflow_status") == "completed" and not report["coverage"].get("waived")
    ):
        verified = {
            (row["id"], verification["original_sha"])
            for row in report.get("history", [])
            if row["status"] == "resolved"
            and (verification := row.get("verification"))
            and verification["status"] == "completed"
            and verification["verdict"] == "fixed"
            and verification["head_sha"] == report["head_sha"]
        }
        for thread_id, finding in threads.items():
            if (finding["id"], finding["source_sha"]) in verified:
                if not api.is_current(report):
                    return False
                api.resolve_thread(thread_id)

    if not findings:
        return True
    tracked = {finding["id"] for finding in threads.values()}
    paths = {finding["path"] for finding in findings}
    diff = {
        file["filename"]: dict(right_side_lines(file.get("patch") or ""))
        for file in api.pages(f"{api.pull}/files")
        if file["filename"] in paths
    }
    comments = f"{api.pull}/comments"
    markers = {
        row["body"].splitlines()[0]
        for row in api.pages(comments)
        if row["user"]["login"] == BOT and row["body"].startswith("<!-- mortis-action:finding:")
    }
    for finding in findings:
        if finding.get("id") in tracked:
            continue
        path = finding["path"]
        lines = diff.get(path, {})
        line = min(
            (
                number
                for number, (_, _, added) in lines.items()
                if added and finding["start_line"] <= number <= finding["end_line"]
            ),
            default=None,
        )
        if line is None or finding.get("source_sha", report["head_sha"]) != report["head_sha"]:
            continue
        identity = [report["head_sha"], path, line, finding.get("title") or finding["content"]]
        digest = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        marker = f"<!-- mortis-action:finding:{digest} -->"
        if marker in markers:
            continue
        if not api.is_current(report):
            return False
        payload = {
            "body": f"{marker}\n{finding_metadata(finding, report['head_sha'])}{finding_text(finding)}",
            "commit_id": report["head_sha"],
            "path": path,
            "line": line,
            "side": "RIGHT",
        }
        replacement = suggested_change(finding, report["head_sha"], lines)
        workflow = Path(path).parent == Path(".github/workflows") and path.endswith((".yml", ".yaml"))
        if replacement and workflow and not valid_workflow_replacement(
            repo, workflow_python, report["head_sha"], finding, replacement,
        ):
            replacement = None
        suggestion = f"\n\n```suggestion\n{replacement}\n```" if replacement else ""
        posted = None
        if suggestion and len((payload["body"] + suggestion).encode()) <= COMMENT_BODY_LIMIT:
            start, end = finding["start_line"], finding["end_line"]
            suggested = {**payload, "body": payload["body"] + suggestion, "line": end}
            if start != end:
                suggested.update(start_line=start, start_side="RIGHT")
            posted = api.request("POST", comments, suggested, allow_invalid_anchor=True)
            if posted is None and not api.is_current(report):
                return False
        if posted is None:
            api.request("POST", comments, payload, allow_invalid_anchor=True)
        markers.add(marker)
    return True
