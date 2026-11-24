"""Prepare and publish the ask and describe pull request commands."""

import os
import re
from urllib.parse import quote

from .github import COMMENT_BODY_LIMIT
from .markdown import overview, safe_text

DESCRIPTION_START = "<!-- mortis-action:description -->"
DESCRIPTION_END = "<!-- /mortis-action:description -->"


def pull_request_url(api):
    return f"{os.environ['GITHUB_SERVER_URL'].rstrip('/')}/{api.owner}/{api.name}/pull/{api.number}"


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
    path = directory / "question.txt"
    path.write_text(question, encoding="utf-8")
    return ["--question-file", path, *arguments], None


def ask_marker(request):
    return f"<!-- mortis-action:ask:{int(request['comment']['id'])} -->"


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
    body = f"{ask_marker(request)}\n### Mortis answer\n\n[Question]({url})\n\n"
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
    if DESCRIPTION_START not in original and DESCRIPTION_END not in original:
        return original + ("\n\n" if original else "") + block
    if original.count(DESCRIPTION_START) == original.count(DESCRIPTION_END) == 1:
        first, last = original.index(DESCRIPTION_START), original.index(DESCRIPTION_END)
        if first < last:
            return original[:first] + block + original[last + len(DESCRIPTION_END):]
    raise ValueError("The existing Mortis description block is incomplete or duplicated.")


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
    if len(body) > 65_536:
        raise ValueError("The Mortis summary would exceed GitHub's description limit.")
    if title != current.get("title") or body != (current.get("body") or ""):
        api.request("PATCH", api.pull, {"title": title, "body": body})
    return 0, "completed", "Mortis updated the PR title and description."
