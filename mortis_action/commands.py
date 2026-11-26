"""Prepare and publish the ask, describe and scope preview commands."""

import http.client
import json
import os
import re
from itertools import chain
from urllib.parse import quote

from .github import COMMENT_BODY_LIMIT
from .markdown import overview, redact_credentials, safe_text

DESCRIPTION_START = "<!-- mortis-action:description -->"
DESCRIPTION_END = "<!-- /mortis-action:description -->"


def pull_request_url(api):
    return f"{os.environ['GITHUB_SERVER_URL'].rstrip('/')}/{api.owner}/{api.name}/pull/{api.number}"


def question_with_history(api, request, anchor, question):
    comment = request["comment"]
    anchor_id = anchor.get("id")
    if not anchor_id or (request["inline"] and anchor_id == comment["id"]):
        return question
    prefix = "Earlier comments from this thread (quoted context):\n"
    suffix = "\n\nCurrent question:\n" + question
    budget = min(4000, 8000 - len(prefix) - len(suffix))
    if budget < 32:
        return question
    root = anchor.get("in_reply_to_id") or anchor_id
    quoted, seen = [], set()
    try:
        recent = api.pages(f"{api.pull}/comments?sort=created&direction=desc")
        for row in chain(recent, (anchor,)):
            key = row["id"]
            if row.get("pull_request_url") != anchor["pull_request_url"] or (row.get("in_reply_to_id") or key) != root:
                continue
            if key in seen or (request["inline"] and key >= comment["id"]):
                continue
            if comment.get("created_at") and row.get("created_at", "") > comment["created_at"]:
                continue
            body = re.sub(r"<!--.*?(?:-->|\Z)", "", row.get("body") or "", flags=re.DOTALL).strip()
            if body:
                item = json.dumps(redact_credentials(body)[:1000], ensure_ascii=False)
                if len(item) + 1 > budget:
                    break
                quoted.append(item)
                seen.add(key)
                budget -= len(item) + 1
            if key == root or len(quoted) == 6:
                break
    except (ValueError, OSError, http.client.HTTPException):
        return question
    return prefix + "\n".join(reversed(quoted)) + suffix if quoted else question


def ask_arguments(api, request, directory):
    comment = request["comment"]
    question = request["question"]
    lines = question.splitlines()
    link = lines[-1].strip()
    target = (comment.get("in_reply_to_id") or comment["id"]) if request["inline"] else None
    if not target and re.match(r"https?://\S+#discussion_r", link):
        match = re.fullmatch(re.escape(pull_request_url(api)) + r"(?:/files)?(?:\?[^\s#]*)?#discussion_r([1-9]\d*)", link)
        if not match:
            return None, "Use a review comment link from this pull request."
        target = int(match[1])
        question = "\n".join(lines[:-1]).strip()
    if not 0 < len(question) <= 8000:
        return None, "Supply a question of 1–8000 characters."
    arguments = []
    if target:
        anchor = api.request("GET", f"/pulls/comments/{int(target)}", allow_missing=True)
        expected = os.environ["GITHUB_API_URL"].rstrip("/") + api.repo + api.pull
        if not anchor or anchor.get("pull_request_url") != expected:
            return None, "The linked review comment is unavailable on this pull request."
        last, side = anchor.get("line"), anchor.get("side")
        first = anchor.get("start_line") or last
        if (
            not anchor.get("path") or type(first) is not int or type(last) is not int
            or not 1 <= first <= last or side not in {"LEFT", "RIGHT"}
            or anchor.get("start_side") not in {None, side}
        ):
            return None, "The selected lines are unavailable on the current pull request diff."
        arguments.extend([f"--path={anchor['path']}", "--line", f"{first}:{last}", "--side", side.lower()])
        question = question_with_history(api, request, anchor, question)
    path = directory / "question.txt"
    path.write_text(question, encoding="utf-8")
    return ["--question-file", path, *arguments], None


def reply_marker(command, request):
    return f"<!-- mortis-action:{command}:{int(request['comment']['id'])} -->"


def publish_preview(api, pr, request, report, exit_code):
    if (report.get("schema_version") != "mortis.review-preview/v1"
            or any(report.get(f"{side}_sha") != pr[side]["sha"] for side in ("base", "head"))):
        raise ValueError("Mortis returned an invalid preview for these PR revisions.")
    totals = report["totals"]
    batches = totals["planned_batches"]
    batch_label = "batch" if batches == 1 else "batches"
    body = (f"{reply_marker('preview', request)}\n### Mortis scope preview\n\n"
            f"Full comparison scope at {report['head_sha'][:12]} · {totals['selected_files']} selected · "
            f"{totals['excluded_files']} excluded · {batches} planned {batch_label}.\n\n"
            "The preview uses local Git data. Batch estimates cover the initial review before incremental reuse.")
    max_files = report["bounds"]["max_files"]
    if max_files:
        body += f" The configured file limit is {max_files}."
    for title, rows in (("Selected files", report["selected_files"]), ("Excluded files", report["excluded_files"])):
        if rows:
            body += f"\n\n**{title}**"
            for row in rows[:12]:
                path = safe_text(redact_credentials(row["path"]), 160)
                reason = safe_text(redact_credentials(row.get("reason") or ""), 80)
                body += f"\n- {path}" + (f" · {reason}" if reason else "")
            if len(rows) > 12:
                body += f"\n- {len(rows) - 12} more"
    problems = [report.get("limit_reason"), *(row["message"] for row in report.get("errors", [])[:3])]
    if (report.get("affected_callers") or {}).get("status") == "partial":
        problems.append("Caller analysis reached its limit.")
    if exit_code == 2:
        body += "\n\nPartial preview. " + " ".join(safe_text(redact_credentials(str(p)), 250) for p in problems if p)
    if not api.is_current(report):
        return 0, "skipped", "The PR changed during the scope preview. Run /mortis preview again."
    api.request("POST", api.issue, {"body": body})
    return exit_code, "partial" if exit_code == 2 else "completed", "Mortis posted the scope preview."


def publish_answer(api, request, report):
    comment = request["comment"]
    inline = request["inline"]
    if inline:
        root = int(comment.get("in_reply_to_id") or comment["id"])
        destination = f"{api.pull}/comments/{root}/replies"
    else:
        destination = api.issue
    anchor = "discussion_r" if inline else "issuecomment-"
    url = f"{pull_request_url(api)}#{anchor}{int(comment['id'])}"
    body = f"{reply_marker('ask', request)}\n### Mortis answer\n\n[Question]({url})\n\n"
    links = []
    if report["status"] == "insufficient_context":
        answer = safe_text(report["message"], 1000)
    else:
        result = report["result"]
        answer = "\n\n".join(safe_text(paragraph, 6000) for paragraph in result["answer"].split("\n\n"))
        server = os.environ["GITHUB_SERVER_URL"].rstrip("/")
        for citation in result["citations"]:
            path, sha = citation["path"], citation["sha"]
            first, last = citation["start_line"], citation["end_line"]
            line = f"L{first}" if first == last else f"L{first}-L{last}"
            link = f"{server}/{api.owner}/{api.name}/blob/{sha}/{quote(path, safe='/')}#{line}"
            links.append(f"\n- [{safe_text(path, 300)} · {line}]({link})")
    heading = "\n\n**Sources**"
    sources = heading + "".join(links) if links else ""
    footer = ""
    if report.get("limited_context"):
        footer = "\n\nThe answer uses the diff that fit within the configured context limit."
    if len((body + answer + sources + footer).encode()) > COMMENT_BODY_LIMIT:
        footer += "\n\nSome text or sources were omitted to fit GitHub's comment limit."
        available = COMMENT_BODY_LIMIT - len((body + footer).encode())
        encoded = answer.encode()
        # When sources alone are large, keep room for the answer.
        source_limit = available - min(len(encoded), available // 2)
        sources = ""
        for link in links:
            candidate = (sources or heading) + link
            if len(candidate.encode()) <= source_limit:
                sources = candidate
        answer = encoded[:available - len(sources.encode())].decode("utf-8", errors="ignore")
        answer = re.sub(r"&(?:#\d*)?$", "", answer).rstrip()
    api.request("POST", destination, {"body": body + answer + sources + footer})


def description_body(original, report):
    block = f"{DESCRIPTION_START}\n### Mortis summary" + overview({"summary": report})
    if report.get("limited_context"):
        block += "\n\nThis summary uses the diff that fit within the configured context limit."
    block += f"\n{DESCRIPTION_END}"
    first, last = original.find(DESCRIPTION_START), original.find(DESCRIPTION_END)
    if first == last == -1:
        body = original + ("\n\n" if original else "") + block
    elif 0 <= first < last and original.count(DESCRIPTION_START) == original.count(DESCRIPTION_END) == 1:
        body = original[:first] + block + original[last + len(DESCRIPTION_END):]
    else:
        raise ValueError("The existing Mortis description block is incomplete or duplicated.")
    if len(body) > 65_536:
        raise ValueError("The Mortis summary would exceed GitHub's description limit.")
    return body


def auto_describe(api, pr, report):
    summary = report.get("summary") or {}
    if (report.get("status") != "completed" or summary.get("status") != "completed"
            or not (summary.get("result") or {}).get("narrative")):
        return ""
    if any(report.get(f"{side}_sha") != pr[side]["sha"] for side in ("base", "head")):
        return "Skipped the PR description update because the review covers different revisions."
    original = pr.get("body") or ""
    try:
        body = description_body(original, summary)
    except ValueError as error:
        return str(error)
    if body == original:
        return ""
    try:
        current = api.current(report)
        if not current or (current.get("body") or "") != original:
            return "Skipped the PR description update because the PR changed during review."
        api.request("PATCH", api.pull, {"body": body})
    except (ValueError, OSError, http.client.HTTPException):
        return "Mortis could not update the PR description. Check the workflow's pull request permissions."
    return ""


def finish_pr_command(api, pr, request, command, report):
    if any(report[f"{side}_sha"] != pr[side]["sha"] for side in ("base", "head")):
        raise ValueError("Mortis returned a result for different PR revisions.")
    current = api.current(report)
    if not current:
        return 0, "skipped", "The PR changed while Mortis was working. Run the command again."
    if command == "ask":
        publish_answer(api, request, report)
        return 0, "completed", "Mortis posted the answer."
    if report["status"] == "insufficient_context":
        return 0, "skipped", report["message"]
    if any(current.get(key) != pr.get(key) for key in ("title", "body")):
        return 0, "skipped", "The PR title or description was edited. Run /mortis describe again."
    title = report["result"]["title"]
    body = description_body(pr.get("body") or "", report)
    if title != current.get("title") or body != (current.get("body") or ""):
        api.request("PATCH", api.pull, {"title": title, "body": body})
    return 0, "completed", "Mortis updated the PR title and description."
