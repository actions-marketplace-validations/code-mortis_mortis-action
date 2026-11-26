"""Render shared review text, change overviews and workflow summaries."""

import os
import re


def redact_credentials(text):
    values = (os.environ.get(name) for name in ("MORTIS_API_KEY", "MORTIS_GITHUB_TOKEN", "MORTIS_STATE_KEY"))
    for secret in sorted(filter(None, values), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text


def safe_text(value, limit):
    text = " ".join(str(value).split())[:limit]
    return re.sub(r"[^\w ,:;!?'/\-]|_", lambda char: f"&#{ord(char[0])};", text)


def overview(report):
    result = ((report.get("summary") or {}).get("result") or {})
    narrative = result.get("narrative")
    body = f"\n\n{safe_text(narrative, 1200)}" if narrative else ""
    groups = result.get("groups") or []
    if groups:
        body += "\n\n### Changes"
        groups_text = ""
        for group in groups:
            paths = group["paths"]
            files = ", ".join(safe_text(path, 160) for path in paths[:6])
            if len(paths) > 6:
                files += f" and {len(paths) - 6} more"
            item = f"\n\n- **{safe_text(group['title'], 100)}** — {safe_text(group['description'], 280)}"
            if files:
                item += f"\n  ({files})"
            if len((groups_text + item).encode()) > 12_000:
                groups_text += "\n\nAdditional changes are available in the full report."
                break
            groups_text += item
        body += groups_text
    return body


def file_list(label, files):
    body = f"\n\n<details>\n<summary>{label} ({len(files)})</summary>\n"
    size = 0
    for file in files:
        item = f"\n- {safe_text(file['path'], 300)}"
        size += len(item.encode())
        if size > 6_000:
            body += "\n- See the JSON report for more files."
            break
        body += item
    return body + "\n\n</details>"


def earlier_open_findings(report):
    current = {finding.get("id") for finding in report["findings"]}
    return [
        item["snapshot"] for item in report.get("history", [])
        if item["status"] == "open" and item["id"] not in current and item.get("snapshot")
    ]


def summary(report, status, run_url, *, full_review=False):
    coverage = report["coverage"]
    details = ""
    findings = f"{len(report['findings'])} findings"
    if report["schema_version"] == "mortis.review/v1":
        done, selected = len(coverage["completed"]), len(coverage["selected"])
        label, revision = "review", report["head_sha"]
        reused = coverage.get("reused", [])
        comparison = report.get("comparison") or {}
        if full_review:
            details = "\n\nFull review requested manually."
        elif comparison:
            mode = safe_text(comparison["strategy"].replace("_", " "), 80)
            reason = safe_text((comparison.get("reason") or "").replace("_", " "), 160)
            details = f"\n\nReview mode **{mode}**" + (f" ({reason})" if reason else "") + "."
        elif report.get("mode") == "commits":
            details = "\n\nReview mode **full** (coverage reuse disabled)."
        if comparison:
            details += file_list("Files reviewed", coverage["completed"]) + file_list("Files reused", reused)
        done += len(reused)
        if earlier := earlier_open_findings(report):
            findings += f" · {len(earlier)} earlier open"
    else:
        done, selected = coverage["completed_files"], coverage["selected_files"]
        label, revision = "security scan", report["commit"]
    return (
        f"## Mortis {label}\n\n"
        f"**{status.capitalize()}** · Commit {revision[:12]} · {done}/{selected} files covered"
        f" · {findings} · [Workflow run]({run_url})"
        + details
    )
