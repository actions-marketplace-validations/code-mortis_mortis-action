"""Render shared review text, change overviews and workflow summaries."""

import html
import os
import re
from collections import Counter
from urllib.parse import quote, unquote

SEVERITIES = ("critical", "high", "medium", "low")
JOB_SUMMARY_BYTES = 1024 * 1024


def redact_credentials(text):
    values = (os.environ.get(name) for name in ("MORTIS_API_KEY", "MORTIS_GITHUB_TOKEN", "MORTIS_STATE_KEY"))
    for secret in sorted(filter(None, values), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text


def contains_rendered_credential(markdown):
    # Labels use HTML entities and citation URLs use percent-encoded paths.
    visible = html.unescape(markdown)
    return any(redact_credentials(text) != text for text in (markdown, visible, unquote(visible)))


def safe_text(value, limit):
    text = " ".join(str(value).split())[:limit]
    return re.sub(r"[^\w ,:;!?'/\-]|_", lambda char: f"&#{ord(char[0])};", text)


def finding_location(finding, commit):
    """Link only repository-relative paths at the revision where they were observed."""
    path = finding.get("path")
    if (not isinstance(path, str) or not path or contains_rendered_credential(path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or re.search(r"[\\\x00-\x1f\x7f]", path)):
        return "Location unavailable"
    sha = finding.get("source_sha") or commit
    first = finding.get("start_line")
    last = finding.get("end_line") or first
    if type(first) is int and type(last) is int and 0 < first <= last:
        lines = str(first) if first == last else f"{first}-{last}"
        anchor = f"#L{first}" if first == last else f"#L{first}-L{last}"
    else:
        lines = anchor = ""
    label = safe_text(path, 300) + (f":{lines}" if lines else "")
    server, repo = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
    if not server or not repo or not re.fullmatch(r"[a-f0-9]{40}", sha or ""):
        return label
    return f"[{label}]({server.rstrip('/')}/{repo}/blob/{sha}/{quote(path, safe='/')}{anchor})"


def severity(finding):
    level = finding.get("severity")
    return level if level in SEVERITIES else "unknown"


def severity_order(finding):
    return (*SEVERITIES, "unknown").index(severity(finding))


def finding_entry(finding, commit, *, compact=False, scan=False):
    location = finding_location(finding, commit)
    if scan and not finding.get("start_line"):
        # Code findings store their observed ranges in their citations.
        for citation in finding.get("evidence", []):
            if (isinstance(citation, dict) and citation.get("path") == finding.get("path")
                    and citation.get("revision", "current") == "current"):
                location = finding_location({**finding, "start_line": citation.get("start_line"),
                                             "end_line": citation.get("end_line")}, commit)
                break
    if scan:
        description = finding.get("title") or "Untitled finding"
    elif compact:
        description = finding.get("title") or finding.get("content") or "Finding"
    else:
        description = finding.get("content") or finding.get("title") or "Finding"
    description = redact_credentials(description)
    if contains_rendered_credential(description):
        description = "[redacted]"
    return f"- **{severity(finding)}** · {location} — {safe_text(description, 100 if compact else 400)}"


def scan_index(report):
    rows = sorted(report["findings"], key=severity_order)
    return f"## Scan findings ({len(rows)})\n\n" + "\n".join(
        finding_entry(row, report["commit"], scan=True) for row in rows
    )


def fit_job_index(heading, index, reports):
    if not index:
        return heading, None
    summary = f"{heading}\n\n{index}"
    if len(summary.encode()) + 1 <= JOB_SUMMARY_BYTES:
        return summary, None
    path = reports / "finding-index.md"
    path.write_text(index + "\n", encoding="utf-8")
    return heading + "\n\nThe remaining findings are in this run’s **finding-index.md** artifact.", path


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
        {**item["snapshot"], "source_sha": item["snapshot"].get("source_sha") or item.get("sha")}
        for item in report.get("history", [])
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
        counts = Counter(severity(row) for row in report["findings"])
        levels = [*SEVERITIES, "unknown"] if counts["unknown"] else SEVERITIES
        details = "\n\nSeverity · " + " · ".join(f"{counts[level]} {level}" for level in levels)
    return (
        f"## Mortis {label}\n\n"
        f"**{status.capitalize()}** · Commit {revision[:12]} · {done}/{selected} files covered"
        f" · {findings} · [Workflow run]({run_url})"
        + details
    )
