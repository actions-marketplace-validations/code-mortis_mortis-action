"""Publish the result of an authorized PR review on the recorded commit."""

import http.client
import json
import os
from pathlib import Path
from urllib.parse import quote

from .github import BOT, GitHubForbidden, GitHubRequestError
from .markdown import SEVERITIES

NAME = "Mortis Review"
NOTICE = "<!-- mortis-action:review-failure -->"
API_ERRORS = (ValueError, OSError, http.client.HTTPException)


def run_url():
    return f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"


def threshold():
    value = os.environ.get("MORTIS_FAIL_ON_SEVERITY", "none").strip().lower()
    if value not in (*SEVERITIES, "none"):
        raise ValueError("Choose none, low, medium, high or critical for fail-on-severity.")
    return value


def start(api, pr, minimum_severity):
    head = pr["head"]["sha"]
    name = (f"{NAME} (advisory)" if minimum_severity == "none"
            else f"{NAME} ({minimum_severity}) / {pr['base']['ref']}")
    identity = f"{os.environ['GITHUB_RUN_ID']}:{os.environ['GITHUB_RUN_ATTEMPT']}:{os.environ['GITHUB_JOB']}:{api.number}"
    data = {"name": name, "head_sha": head, "status": "in_progress", "details_url": run_url(), "external_id": identity}
    try:
        return int(api.request("POST", "/check-runs", data)["id"])
    except API_ERRORS as error:
        if isinstance(error, GitHubForbidden) or (isinstance(error, GitHubRequestError) and error.status < 500):
            raise
        # Recover a check GitHub accepted before the connection was lost.
        page = 1
        while True:
            query = f"check_name={quote(name, safe='')}&filter=all&per_page=100&page={page}"
            rows = api.request("GET", f"/commits/{head}/check-runs?{query}")["check_runs"]
            for row in rows:
                if row.get("external_id") == identity and (row.get("app") or {}).get("slug") == "github-actions":
                    return int(row["id"])
            if len(rows) < 100:
                raise
            page += 1


def report_counts(report):
    by_id = {
        row["id"]: (row.get("snapshot") or {}).get("severity")
        for row in report.get("history", []) if row["status"] == "open"
    }
    for index, finding in enumerate(report["findings"]):
        identity = finding.get("id") or index
        if finding.get("status", "open") == "open":
            by_id[identity] = finding.get("severity")
        else:
            by_id.pop(identity, None)
    counts = dict.fromkeys(SEVERITIES, 0)
    for severity in by_id.values():
        key = severity if severity in SEVERITIES else "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def verdict(report, status, threshold, revisions):
    """Return a Checks conclusion, severity-policy result, and safe check summary."""
    if report is None:
        if status == "skipped":
            if threshold != "none":
                return "failure", "unevaluated", "Review skipped before analysis. Run a full review to evaluate the merge policy."
            return "skipped", "unevaluated", "Review skipped before analysis."
        return "failure", "unevaluated", "The review failed before producing a report."
    if (not isinstance(report, dict) or report.get("schema_version") != "mortis.review/v1"
            or any(report.get(k) != v for k, v in revisions.items())):
        return "failure", "unevaluated", "The report does not match the requested PR revisions."
    counts = report_counts(report)
    coverage = report["coverage"]
    covered = len(coverage["completed"]) + len(coverage.get("reused", []))
    summary = f"Coverage: {covered}/{len(coverage['selected'])} selected files.\n\nOpen findings: " + ", ".join(
        f"{number} {level}" for level, number in counts.items()
    ) + "."
    reused = (report.get("comparison") or {}).get("strategy") == "skipped_unchanged"
    empty = (not coverage["selected"] and not report.get("affected_callers") and not report.get("errors")
             and not any(warning.get("type") == "review_limit_reached" for warning in report.get("warnings", [])))
    complete = status == "completed" or (status == "skipped" and (reused or empty))
    if (not complete or report.get("status") != status or report.get("workflow_status") != "completed" or coverage.get("waived")
            or covered != len(coverage["selected"])):
        return "failure", "unevaluated", summary + "\n\nReview coverage or publication is incomplete."
    if threshold == "none":
        return "success", "advisory", summary
    if counts.get("unknown"):
        return "failure", "unevaluated", summary + "\n\nAn open finding has unknown severity."
    blocked = any(counts[level] for level in SEVERITIES[:SEVERITIES.index(threshold) + 1])
    return ("failure", "blocked", summary) if blocked else ("success", "passed", summary)


def failure_notice(api, revisions, failed):
    existing = next((row for row in api.pages(api.issue) if (row.get("user") or {}).get("login") == BOT
                     and (row.get("body") or "").startswith(NOTICE + "\n")), None)
    if not (existing or failed) or not api.is_current(revisions):
        return
    if not failed:
        api.request("DELETE", f"/issues/comments/{existing['id']}", allow_missing=True)
        return
    body = (f"{NOTICE}\nThe Mortis review of `{revisions['head_sha'][:12]}` needs attention. "
            f"[View the workflow run]({run_url()}).")
    if existing:
        if existing["body"] != body:
            api.request("PATCH", f"/issues/comments/{existing['id']}", {"body": body})
    else:
        api.request("POST", api.issue, {"body": body})


def finish(api, revisions, *, check_id, threshold, status, report_path, superseded, upload_failed, cancelled, warn,
           history_unavailable=False):
    """Finalize after artifact uploads. Only numeric counts and fixed prose go into the check."""
    try:
        current = api.is_current(revisions)
    except API_ERRORS:
        current = None
    if cancelled or superseded or current is False:
        conclusion, policy, summary = "cancelled", "unevaluated", "Review cancelled or superseded."
    elif current is None:
        conclusion, policy, summary = "failure", "unevaluated", "Could not verify the current PR revisions."
    else:
        try:
            report = json.loads(Path(report_path).read_text()) if report_path else None
            conclusion, policy, summary = verdict(report, status, threshold, revisions)
        except (AttributeError, KeyError, TypeError, ValueError, OSError):
            conclusion, policy, summary = "failure", "unevaluated", "Could not read the review result."
        if threshold != "none" and history_unavailable:
            conclusion, policy = "failure", "unevaluated"
            summary += "\n\nEarlier open findings could not be checked. Restore access to the review history and rerun."
        if upload_failed:
            conclusion, policy = "failure", "unevaluated"
            summary += "\n\nAn artifact upload failed. See the workflow run."

    check_published = False
    if check_id:
        body = {"status": "completed", "conclusion": conclusion, "output": {
            "title": f"Mortis Review · {conclusion}", "summary": summary + f"\n\n[Workflow run]({run_url()})",
        }}
        # A PATCH to this check ID is idempotent, including after a lost response.
        for attempt in range(2):
            try:
                api.request("PATCH", f"/check-runs/{int(check_id)}", body)
                check_published = True
                break
            except API_ERRORS as error:
                if (attempt or isinstance(error, GitHubForbidden)
                        or (isinstance(error, GitHubRequestError) and error.status < 500)):
                    break
        if not check_published:
            warn("Could not finalize the Mortis Review check. Verify checks: write and retry the workflow.")

    operational_failure = conclusion == "failure" and policy != "blocked"
    if current and conclusion not in {"cancelled", "skipped"}:
        try:
            failed = not check_published and (operational_failure or bool(check_id) or threshold != "none")
            failure_notice(api, revisions, failed)
        except API_ERRORS:
            warn("Could not update the Mortis review failure notice.")
    if threshold != "none" and not check_published:
        warn("The configured merge policy requires a Mortis Review check. Grant checks: write and rerun.")
        return "unevaluated", 1, summary
    blocking_failure = threshold != "none" and conclusion == "failure"
    return policy, int(blocking_failure), summary
