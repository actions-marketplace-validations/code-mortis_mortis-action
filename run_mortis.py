"""Run the pinned Mortis CLI and publish its results on GitHub."""

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit

SUMMARY_MARKER = "<!-- mortis-action:review -->"
BOT = "github-actions[bot]"
COMMENT_BODY_LIMIT = 55_000
FINDING_ID = re.compile(r"finding-[0-9a-f]{32}")
FINDING_METADATA = "<!-- mortis-action:prior-finding:v1:"
DESCRIPTION_START = "<!-- mortis-action:description -->"
DESCRIPTION_END = "<!-- /mortis-action:description -->"
COMMENT_EVENTS = {"issue_comment", "pull_request_review_comment"}
REMOTE_REVIEW_EVENTS = {"pull_request_target", *COMMENT_EVENTS}
TRIVY_VERSION = "0.76.0"
TRIVY_ASSETS = {
    "X64": ("64bit", "e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7"),
    "ARM64": ("ARM64", "aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c"),
}


def append(path, message):
    with Path(os.environ[path]).open("a", encoding="utf-8") as stream:
        stream.write(message + "\n")


def output(name, value):
    if "\n" in str(value) or "\r" in str(value):
        raise ValueError(f"Invalid multiline value for output {name}.")
    append("GITHUB_OUTPUT", f"{name}={value}")


def resolve(repo, ref, *, env=None):
    if not ref or ref.startswith("-"):
        raise ValueError("Supply a valid commit reference.")
    return subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        text=True,
        stderr=subprocess.DEVNULL,
        env=env,
    ).strip()


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


def review_range(repo, base, head, *, env=None):
    shallow = subprocess.check_output(["git", "-C", repo, "rev-parse", "--is-shallow-repository"], text=True, env=env)
    ancestor = subprocess.run(["git", "-C", repo, "merge-base", base, head], capture_output=True, env=env)
    if shallow.strip() == "true" or ancestor.returncode != 0:
        raise ValueError(
            "A review needs complete Git history and a common ancestor. Use checkout with fetch-depth: 0."
        )
    return ["review", "--base", base, "--head", head], base


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


def fetch_pull_request(repo, pr):
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    if any(re.fullmatch(r"[0-9a-f]{40}", sha) is None for sha in (base, head)):
        raise ValueError("GitHub did not return valid PR commit IDs.")
    number = int(pr["number"])
    url = f"{os.environ['GITHUB_SERVER_URL'].rstrip('/')}/{os.environ['GITHUB_REPOSITORY']}.git"
    token = base64.b64encode(f"x-access-token:{os.environ['MORTIS_GITHUB_TOKEN']}".encode()).decode()
    # Keep Git configuration and credentials scoped to this fetch.
    env = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    subprocess.run(["git", "init", "--bare", "--quiet", "--template=", repo], check=True, env=env)
    subprocess.run(
        ["git", "-C", repo, "-c", "http.followRedirects=false",
         "--config-env=http.extraHeader=MORTIS_GIT_AUTH", "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
         url, f"{base}:refs/mortis/base", f"refs/pull/{number}/head:refs/mortis/head"],
        check=True,
        env={**env, "MORTIS_GIT_AUTH": f"Authorization: Basic {token}"},
    )
    if resolve(repo, "refs/mortis/base", env=env) != base or resolve(repo, "refs/mortis/head", env=env) != head:
        return None, "The PR changed while fetching its commits"
    return review_range(repo, base, head, env=env)


def install_trivy(directory, environment):
    architecture = os.environ["RUNNER_ARCH"]
    if architecture not in TRIVY_ASSETS:
        raise ValueError("Scans require a Linux X64 or ARM64 runner.")
    arch, digest = TRIVY_ASSETS[architecture]
    asset = f"trivy_{TRIVY_VERSION}_Linux-{arch}.tar.gz"
    archive = directory / asset
    subprocess.run(
        [
            "curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "180",
            "--output",
            archive,
            f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{asset}",
        ],
        check=True,
        env=environment,
    )
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError("Trivy release checksum mismatch.")
    with tarfile.open(archive) as package:
        member = package.getmember("trivy")
        if not member.isfile():
            raise ValueError("Expected a regular Trivy binary.")
        binary = directory / "trivy"
        with package.extractfile(member) as source, binary.open("xb") as target:
            shutil.copyfileobj(source, target)
        binary.chmod(0o700)
    archive.unlink()


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
            [python, "-I", validator], input=updated, encoding="utf-8", capture_output=True,
        ).returncode == 0
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return False


def safe_text(value, limit):
    text = " ".join(str(value).split())[:limit]
    return re.sub(r"[^\w ,:;!?'/\-]|_", lambda char: f"&#{ord(char[0])};", text)


def finding_text(finding):
    location = f"{finding['path']}:{finding['start_line']}"
    return (
        f"**{safe_text(finding['severity'], 20)}** · {safe_text(location, 300)}"
        f" — {safe_text(finding['content'], 400)}"
    )


def finding_metadata(finding, head):
    identity = finding.get("id") or ""
    if not FINDING_ID.fullmatch(identity):
        return ""
    value = {key: finding[key] for key in ("id", "path", "start_line", "end_line", "severity")}
    value.update(source_sha=head, content=" ".join(finding["content"].split())[:400])
    encoded = base64.b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()
    return f"{FINDING_METADATA}{encoded} -->\n"


def tracked_finding(comment):
    author = comment.get("author") or {}
    if author.get("__typename") != "Bot" or author.get("login") not in {BOT, "github-actions"}:
        return None
    lines = comment["body"].split("\n", 2)
    if len(lines) != 3 or not lines[0].startswith("<!-- mortis-action:finding:"):
        return None
    marker = lines[1]
    if not marker.startswith(FINDING_METADATA) or not marker.endswith(" -->") or len(marker) > COMMENT_BODY_LIMIT:
        return None
    try:
        finding = json.loads(base64.b64decode(marker[len(FINDING_METADATA):-4], validate=True))
        if (
            set(finding) == {"id", "path", "start_line", "end_line", "severity", "source_sha", "content"}
            and FINDING_ID.fullmatch(finding["id"])
            and re.fullmatch(r"[0-9a-f]{40}", finding["source_sha"])
            and isinstance(finding["path"], str) and 0 < len(finding["path"]) <= 2000
            and type(finding["start_line"]) is int and type(finding["end_line"]) is int
            and 1 <= finding["start_line"] <= finding["end_line"]
            and finding["severity"] in {"low", "medium", "high", "critical"}
            and isinstance(finding["content"], str) and 0 < len(finding["content"]) <= 400
        ):
            return finding
    except (KeyError, TypeError, ValueError):
        return None
    return None


def summary(report, status, run_url):
    coverage = report["coverage"]
    if report["schema_version"] == "mortis.review/v1":
        done, selected = len(coverage["completed"]), len(coverage["selected"])
        label, revision = "review", report["head_sha"]
    else:
        done, selected = coverage["completed_files"], coverage["selected_files"]
        label, revision = "security scan", report["commit"]
    return (
        f"## Mortis {label}\n\n"
        f"**{status.capitalize()}** · Commit {revision[:12]} · {done}/{selected} files covered"
        f" · {len(report['findings'])} findings · [Workflow run]({run_url})"
    )


class GitHubAPI:
    def __init__(self, repository, number):
        self.endpoint = urlsplit(os.environ["GITHUB_API_URL"])
        self.owner, self.name = repository.split("/")
        self.number = int(number)
        self.repo = f"/repos/{repository}"
        self.pull = f"/pulls/{self.number}"
        self.issue = f"/issues/{self.number}/comments"

    def request(self, method, path, data=None, *, allow_invalid_anchor=False, allow_missing=False):
        return self._request(
            self.endpoint.netloc, method, self.endpoint.path.rstrip("/") + self.repo + path, data,
            allow_invalid_anchor=allow_invalid_anchor, allow_missing=allow_missing,
        )

    def _request(self, host, method, path, data, *, allow_invalid_anchor=False, allow_missing=False):
        connection = http.client.HTTPSConnection(host, timeout=30)
        try:
            connection.request(
                method,
                path,
                body=json.dumps(data) if data is not None else None,
                headers={
                    "Authorization": f"Bearer {os.environ['MORTIS_GITHUB_TOKEN']}",
                    "Accept": "application/vnd.github+json",
                    "Content-Type": "application/json",
                    "User-Agent": "mortis-action",
                },
            )
            response = connection.getresponse()
            body = response.read()
            if response.status == 404 and allow_missing:
                return None
            if response.status == 422 and allow_invalid_anchor:
                return
            if not 200 <= response.status < 300:
                raise ValueError(f"GitHub rejected the Mortis {method} request (HTTP {response.status}).")
            return json.loads(body)
        finally:
            connection.close()

    def graphql(self, query, variables):
        endpoint = urlsplit(os.environ["GITHUB_GRAPHQL_URL"])
        response = self._request(endpoint.netloc, "POST", endpoint.path, {"query": query, "variables": variables})
        if response.get("errors") or not response.get("data"):
            raise ValueError("GitHub could not read or resolve Mortis review threads. Check pull-requests permissions.")
        return response["data"]

    def finding_threads(self):
        query = """
            query($owner: String!, $name: String!, $number: Int!, $after: String) {
              repository(owner: $owner, name: $name) {
                pullRequest(number: $number) {
                  reviewThreads(first: 100, after: $after) {
                    nodes {
                      id
                      isResolved
                      comments(first: 1) { nodes { body author { login __typename } } }
                    }
                    pageInfo { hasNextPage endCursor }
                  }
                }
              }
            }
        """
        variables = {"owner": self.owner, "name": self.name, "number": self.number, "after": None}
        threads = {}
        while True:
            data = self.graphql(query, variables)
            if not (pr := (data.get("repository") or {}).get("pullRequest")):
                raise ValueError("GitHub did not return the pull request's review threads.")
            page = pr["reviewThreads"]
            for thread in page["nodes"]:
                comments = thread["comments"]["nodes"]
                if not thread["isResolved"] and comments and (finding := tracked_finding(comments[0])):
                    threads[thread["id"]] = finding
            if not page["pageInfo"]["hasNextPage"]:
                return threads
            variables = {**variables, "after": page["pageInfo"]["endCursor"]}

    def resolve_thread(self, thread_id):
        data = self.graphql("""
            mutation($id: ID!) {
              resolveReviewThread(input: {threadId: $id}) { thread { isResolved } }
            }
        """, {"id": thread_id})
        if not data["resolveReviewThread"]["thread"]["isResolved"]:
            raise ValueError("GitHub did not mark the Mortis thread as resolved.")

    def pages(self, path):
        page = 1
        while True:
            rows = self.request("GET", f"{path}?per_page=100&page={page}")
            yield from rows
            if len(rows) < 100:
                return
            page += 1

    def current(self, report):
        pr = self.request("GET", self.pull)
        if (
            pr["state"] == "open"
            and not pr["draft"]
            and pr["base"]["sha"] == report["base_sha"]
            and pr["head"]["sha"] == report["head_sha"]
        ):
            return pr
        return None

    def is_current(self, report):
        return self.current(report) is not None

    def can_review(self, login):
        url = f"/collaborators/{quote(login, safe='')}/permission"
        access = self.request("GET", url, allow_missing=True)
        return bool(access and access["permission"] in {"admin", "write", "maintain"})


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
    if report["status"] == "insufficient_context":
        body += safe_text(report["message"], 1000)
    else:
        result = report["result"]
        body += "\n\n".join(safe_text(paragraph, 6000) for paragraph in result["answer"].split("\n\n"))
        server = os.environ["GITHUB_SERVER_URL"].rstrip("/")
        if result["citations"]:
            body += "\n\n**Sources**"
        for citation in result["citations"]:
            path, sha = citation["path"], citation["sha"]
            first, last = citation["start_line"], citation["end_line"]
            line = f"L{first}" if first == last else f"L{first}-L{last}"
            link = f"{server}/{api.owner}/{api.name}/blob/{sha}/{quote(path, safe='/')}#{line}"
            body += f"\n- [{safe_text(path, 300)} · {line}]({link})"
    if report.get("limited_context"):
        body += "\n\nThe answer uses the diff that fit within the configured context limit."
    api.request("POST", destination, {"body": body})


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


def run_engine(args, repo, revision, pr, reports, directory, *, manual=False, request=None):
    command = args[0]
    api = GitHubAPI(os.environ["GITHUB_REPOSITORY"], pr["number"]) if pr and command != "scan" else None
    reason = None
    if command == "ask":
        marker = ask_marker(request)
        comments = f"{api.pull}/comments" if request["inline"] else api.issue
        if any((row.get("user") or {}).get("login") == BOT and row["body"].startswith(marker)
               for row in api.pages(comments)):
            return 0, "skipped", "Mortis has already answered this comment."
        question_args, reason = ask_arguments(api, request, directory)
        if question_args:
            args = [*args, *question_args]
    environment = {
        name: value
        for name, value in os.environ.items()
        if name not in {"MORTIS_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "MORTIS_API_KEY"}
    }
    environment.update(
        XDG_CONFIG_HOME=str(directory / "config"),
        XDG_STATE_HOME=str(directory / "state"),
        XDG_CACHE_HOME=str(directory / "cache"),
    )
    subprocess.run([sys.executable, "-I", "-m", "venv", directory / "venv"], check=True, env=environment)
    bin_dir = directory / "venv/bin"
    packages = ["mortis-engine==0.1.3"]
    if pr and args[0] == "review":
        packages.append("PyYAML==6.0.3")
    subprocess.run(
        [
            bin_dir / "python",
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-input",
            "--index-url",
            "https://pypi.org/simple",
            *packages,
        ],
        check=True,
        env=environment,
    )

    def mortis(*arguments):
        return subprocess.run(
            [bin_dir / "mortis", *arguments], cwd=directory, env=environment, text=True, capture_output=True
        )

    config = mortis("config", "show", "--repo", repo, "--base", revision)
    if config.returncode:
        raise ValueError("Invalid repository configuration. " + config.stderr.strip())
    settings = json.loads(config.stdout)["scan" if command == "scan" else "review"]["settings"]
    if api:
        if command == "review" and not manual and not settings["automatic"]:
            return 0, "skipped", "Automatic review disabled in mortis.toml"
        if pr["user"]["type"] == "Bot" and not settings["include_bot_prs"]:
            return 0, "skipped", "Bot reviews disabled in mortis.toml"
    if reason:
        report = {"status": "insufficient_context", "message": reason,
                  **{f"{side}_sha": pr[side]["sha"] for side in ("base", "head")}}
        return finish_pr_command(api, pr, request, command, report)
    if request and mortis(command, "--help").returncode:
        raise ValueError(f"The pinned Mortis Engine does not support {command}. Install a compatible release.")

    model = settings["model"] or os.environ["MORTIS_MODEL"].strip()
    if not model:
        raise ValueError("Set a model in mortis.toml or supply the model action input.")
    key = os.environ.get("MORTIS_API_KEY")
    if not key or not key.strip():
        raise ValueError("Set MORTIS_API_KEY from your provider secret.")
    if command == "scan":
        install_trivy(directory, environment)
        environment["PATH"] = str(directory) + os.pathsep + environment["PATH"]
    environment["MORTIS_API_KEY"] = key
    connection_args = [
        "connect",
        "ci",
        "--provider",
        os.environ["MORTIS_PROVIDER"],
        "--model",
        model,
        "--api-key-env",
        "MORTIS_API_KEY",
        "--non-interactive",
    ]
    for name, flag in (("MORTIS_PROTOCOL", "--protocol"), ("MORTIS_BASE_URL", "--base-url")):
        if override := os.environ.get(name, "").strip():
            connection_args.extend([flag, override])
    connection = mortis(*connection_args)
    if connection.returncode:
        raise ValueError("Provider connection failed. " + connection.stderr.strip())
    if request:
        result = mortis(*args, "--repo", repo, "--connection", "ci", "--format", "json")
        if result.returncode:
            raise ValueError(f"Mortis {command} failed. " + result.stderr.strip())
        report = json.loads(result.stdout)
        if report.get("schema_version") != f"mortis.{command}/v1" or report.get("status") not in {
            "completed", "insufficient_context",
        }:
            raise ValueError(f"Mortis {command} returned an unsupported result.")
        if report.get("run_id"):
            output("run-id", report["run_id"])
        return finish_pr_command(api, pr, request, command, report)
    threads = {}
    resolution_note = ""
    prior_args = []
    if api and settings.get("auto_resolve"):
        if "--prior-findings" in mortis("review", "--help").stdout:
            threads = api.finding_threads()
            available = {}
            prior = {}
            for finding in threads.values():
                sha = finding["source_sha"]
                if sha not in available:
                    try:
                        resolve(repo, sha)
                    except subprocess.CalledProcessError:
                        available[sha] = False
                    else:
                        available[sha] = True
                if available[sha]:
                    prior.setdefault(finding["id"], finding)
            if prior:
                prior_path = directory / "prior-findings.json"
                prior_path.write_text(json.dumps(list(prior.values())), encoding="utf-8")
                prior_args = ["--prior-findings", prior_path]
            if not all(available.values()):
                resolution_note = "\n\nSome Mortis threads have an unavailable original commit and remain open."
        else:
            resolution_note = "\n\nThe installed Mortis Engine does not support PR finding verification."
    report_json = reports / "report.json"
    report_markdown = reports / "report.md"
    result = mortis(
        *args, *prior_args, "--repo", repo, "--connection", "ci", "--output", report_json, "--output", report_markdown
    )
    for name, path in (("report-json", report_json), ("report-markdown", report_markdown)):
        if path.is_file():
            output(name, path)
    if not report_json.is_file():
        return result.returncode or 1, "failed", "Mortis produced no report. " + result.stderr.strip()
    report = json.loads(report_json.read_text())
    output("run-id", report["run_id"])
    status = "partial" if result.returncode == 2 else "failed" if result.returncode else report["status"]
    url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    heading = summary(report, status, url) + resolution_note
    if api:
        try:
            if not publish(api, report, heading, repo=repo, workflow_python=bin_dir / "python", threads=threads):
                heading += "\n\nThe PR changed during the run. Results apply to the recorded commit."
        except (ValueError, OSError, http.client.HTTPException) as error:
            return result.returncode or 1, "failed", f"{heading}\n\nPR publication failed. {error}"
    return result.returncode, status, heading


def main():
    try:
        if os.environ["RUNNER_OS"] != "Linux":
            raise ValueError("Mortis Action requires a Linux runner.")
        command = os.environ["MORTIS_COMMAND"]
        event_name = os.environ["GITHUB_EVENT_NAME"]
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        runner_temp = os.environ["RUNNER_TEMP"]
        with tempfile.TemporaryDirectory(prefix="mortis-work-", dir=runner_temp) as scratch:
            directory = Path(scratch)
            manual = event_name in COMMENT_EVENTS
            request = None
            if event_name in REMOTE_REVIEW_EVENTS:
                if command != "review":
                    raise ValueError("This event supports only Mortis PR reviews.")
                pr, reason = remote_pull_request(event_name, event)
                repo = directory / "review.git"
                args, revision = fetch_pull_request(repo, pr) if pr else (None, reason)
                if args and manual:
                    name, question = comment_command(event_name, event)
                    if name != "review":
                        args = [name, *args[1:]]
                        request = {"question": question, "comment": event["comment"],
                                   "inline": event_name == "pull_request_review_comment"}
            else:
                pr = event.get("pull_request") if event_name == "pull_request" else None
                repo = os.environ["GITHUB_WORKSPACE"]
                args, revision = select_run(command, event_name, event, repo)
            if args is None:
                code, status, message = 0, "skipped", revision
            else:
                # Runner-local outputs must outlive the temporary Engine state.
                reports = Path(tempfile.mkdtemp(prefix="mortis-reports-", dir=runner_temp))
                code, status, message = run_engine(
                    args, repo, revision, pr, reports, directory, manual=manual, request=request
                )
    except subprocess.CalledProcessError as error:
        code, status, message = (
            1,
            "failed",
            f"Setup or Git failed (exit {error.returncode}). Check checkout, refs and setup logs.",
        )
    except (KeyError, OSError, ValueError, http.client.HTTPException, tarfile.TarError) as error:
        code, status, message = 1, "failed", str(error)
    if key := os.environ.get("MORTIS_API_KEY"):
        message = message.replace(key, "[redacted]")
    if not message.startswith("## Mortis "):
        message = f"## Mortis {status}\n\n{safe_text(message, 2000)}"
    append("GITHUB_STEP_SUMMARY", message)
    print(f"Mortis action {status}. See the job summary for details.")
    output("status", status)
    output("exit-code", code)


if __name__ == "__main__":
    main()
