"""Select eligible GitHub events and authorize manual PR commands."""

import os
import re

from .github import GitHubAPI
from .repository import resolve, review_range

COMMENT_EVENTS = {"issue_comment", "pull_request_review_comment"}
REMOTE_REVIEW_EVENTS = {"pull_request_target", *COMMENT_EVENTS}


def select_run(command, event_name, event, repo):
    if command not in {"review", "scan"}:
        raise ValueError("Set command to review or scan.")
    pr = event["pull_request"] if event_name == "pull_request" else None
    if pr:
        if pr["head"]["repo"] is None or pr["head"]["repo"]["full_name"] != pr["base"]["repo"]["full_name"]:
            return None, "Fork pull request"
        if pr["draft"]:
            return None, "Draft pull request"
        if "dependabot[bot]" in {pr["user"]["login"], event["sender"]["login"]}:
            return None, "Dependabot pull request"
    if command == "scan":
        revision = resolve(repo, os.environ.get("MORTIS_REF") or os.environ["GITHUB_SHA"])
        return ["scan", "--ref", revision], revision
    if pr:
        base, head = pr["base"]["sha"], pr["head"]["sha"]
    else:
        base, head = os.environ.get("MORTIS_BASE"), os.environ.get("MORTIS_HEAD")
        if not base or not head:
            raise ValueError("Supply base and head for a review outside a pull request.")
    return review_range(repo, resolve(repo, base), resolve(repo, head))


def comment_command(event_name, event):
    inline = event_name == "pull_request_review_comment"
    comment = event.get("comment", {})
    author = comment.get("user", {})
    if event.get("action") != "created" or author.get("type") != "User":
        return None
    if not inline and not event.get("issue", {}).get("pull_request"):
        return None
    body = comment.get("body", "")
    if not inline and body == "/mortis review":
        return "review", None
    if not inline and body == "/mortis review --full":
        return "review", "full"
    if not inline and body.strip() == "/mortis describe":
        return "describe", None
    if match := re.fullmatch(r"/mortis ask\s+(\S.*)", body.strip(), re.DOTALL):
        return "ask", match[1]
    return None


def remote_pull_request(event_name, event):
    repository = os.environ["GITHUB_REPOSITORY"]
    manual = event_name in COMMENT_EVENTS
    inline = event_name == "pull_request_review_comment"
    if manual:
        if not comment_command(event_name, event):
            return None, "No Mortis PR command"
        trigger = event["pull_request"] if inline else event["issue"]
        if inline and (trigger["head"]["repo"] or {}).get("full_name") != repository:
            return None, "Ask about fork PR lines from the conversation using a review comment link"
        api = GitHubAPI(repository, trigger["number"])
        author = event["comment"]["user"]
        if not api.can_review(author["login"]):
            return None, "Mortis commands require repository write access"
    else:
        trigger = event["pull_request"]
        api = GitHubAPI(repository, trigger["number"])

    pr = api.request("GET", api.pull)
    if pr["base"]["repo"]["full_name"] != repository:
        raise ValueError("The pull request targets a different repository.")
    if pr["state"] != "open" or pr["draft"]:
        return None, "Draft or closed pull request"
    if "dependabot[bot]" in {pr["user"]["login"], event["sender"]["login"]}:
        return None, "Dependabot pull request"
    if inline and (pr["head"]["repo"] or {}).get("full_name") != repository:
        return None, "Ask about fork PR lines from the conversation using a review comment link"
    if not manual:
        head_repo = pr["head"]["repo"] or {}
        allow_forks = os.environ.get("MORTIS_REVIEW_FORKS", "false").lower() == "true"
        if head_repo.get("full_name") != repository and not allow_forks:
            return None, "Automatic fork reviews are disabled"
        if any(pr[side]["sha"] != trigger[side]["sha"] for side in ("base", "head")):
            return None, "The PR changed after the event"
    return pr, None
