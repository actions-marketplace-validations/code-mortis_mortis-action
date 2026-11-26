"""GitHub API access and persisted metadata for Mortis findings."""

import base64
import hashlib
import http.client
import json
import os
import re
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

BOT = "github-actions[bot]"
COMMENT_BODY_LIMIT = 55_000
FINDING_ID = re.compile(r"finding-[0-9a-f]{32}")
FINDING_METADATA = "<!-- mortis-action:prior-finding:v1:"
EVIDENCE_MARKER = re.compile(r"<!-- mortis-action:evidence:v1:([0-9a-f]{64}) -->")
ANCHOR_ERROR = re.compile(rb"\b(?:diff(?:_hunk)?|path|position|line|side|start_line|start_side)\b", re.IGNORECASE)


class GitHubRequestError(ValueError):
    def __init__(self, method, status, *, retry_after=None):
        super().__init__(f"GitHub rejected the Mortis {method} request (HTTP {status}).")
        self.status = status
        self.retry_after = retry_after


class GitHubForbidden(ValueError):
    """GitHub explicitly denied an operation for this token."""


def rate_limit_delay(response, message):
    if response.status not in {403, 429}:
        return None
    delay = response.getheader("Retry-After") or ""
    if delay.isascii() and delay.isdigit():
        return int(delay)
    reset = response.getheader("X-RateLimit-Reset") or ""
    if response.getheader("X-RateLimit-Remaining") == "0" and reset.isascii() and reset.isdigit():
        return max(0, int(reset) - int(time.time()))
    if response.status == 429 or "rate limit" in message.lower():
        return 60
    return None


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
            if response.status == 204:
                return None
            if response.status == 404 and allow_missing:
                return None
            # GitHub also uses 422 for spam and global review validation. Only split anchor failures.
            if response.status == 422 and allow_invalid_anchor and ANCHOR_ERROR.search(body):
                return None
            if not 200 <= response.status < 300:
                if response.status in {403, 429}:
                    try:
                        message = json.loads(body).get("message", "")
                    except (ValueError, AttributeError):
                        message = ""
                    message = message if isinstance(message, str) else ""
                    if message.startswith("Resource not accessible by "):
                        raise GitHubForbidden("GitHub denied this operation for the current token.")
                    raise GitHubRequestError(method, response.status, retry_after=rate_limit_delay(response, message))
                raise GitHubRequestError(method, response.status)
            return json.loads(body)
        finally:
            connection.close()

    def graphql(self, query, variables):
        endpoint = urlsplit(os.environ["GITHUB_GRAPHQL_URL"])
        response = self._request(endpoint.netloc, "POST", endpoint.path, {"query": query, "variables": variables})
        errors = response.get("errors", [])
        if errors and all(error.get("type") == "FORBIDDEN" for error in errors):
            raise GitHubForbidden("GitHub denied this operation for the current token.")
        if response.get("errors") or not response.get("data"):
            raise ValueError("GitHub could not complete the Mortis GraphQL request. Check workflow permissions.")
        return response["data"]

    def trusted_summary_body(self, comment):
        """Return verified text, an empty string for untrusted content, or None if the read failed."""
        if not comment.get("node_id"):
            return ""
        try:
            data = self.graphql("""
                query($id: ID!) {
                  node(id: $id) {
                    ... on IssueComment {
                      body lastEditedAt author { __typename login } editor { __typename login }
                    }
                  }
                }
            """, {"id": comment["node_id"]})
        except (ValueError, OSError, http.client.HTTPException):
            return None
        node = data.get("node") or {}
        if not {"editor", "author", "body", "lastEditedAt"} <= node.keys() or not mortis_bot(node["author"]):
            return ""
        if (node["lastEditedAt"] or node["editor"]) and not mortis_bot(node["editor"]):
            return ""
        return node["body"] if isinstance(node["body"], str) else ""

    def download_artifact(self, artifact_id, limit):
        url = f"{self.endpoint.geturl().rstrip('/')}{self.repo}/actions/artifacts/{artifact_id}/zip"
        request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "mortis-action"})
        request.add_unredirected_header("Authorization", f"Bearer {os.environ['MORTIS_GITHUB_TOKEN']}")
        with urlopen(request, timeout=30) as response:
            archive = response.read(limit + 1)
        if len(archive) > limit:
            raise ValueError("The GitHub baseline archive exceeds the download limit.")
        return archive

    def finding_threads(self):
        query = """
            query($owner: String!, $name: String!, $number: Int!, $after: String) {
              repository(owner: $owner, name: $name) {
                pullRequest(number: $number) {
                  reviewThreads(first: 100, after: $after) {
                    nodes {
                      id
                      isResolved
                      isOutdated
                      path
                      line
                      startLine
                      diffSide
                      startDiffSide
                      comments(first: 1) {
                        nodes { body lastEditedAt author { login __typename } editor { login __typename } }
                      }
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
                    line = thread.get("line")
                    first = thread.get("startLine") or line
                    if (thread.get("isOutdated") is False and thread.get("diffSide") == "RIGHT"
                            and thread.get("startDiffSide") in {None, "RIGHT"}
                            and type(first) is int and type(line) is int and 1 <= first <= line):
                        finding["github_anchor"] = (thread["path"], first, line)
                    threads[thread["id"]] = finding
            if not page["pageInfo"]["hasNextPage"]:
                return threads
            variables = {**variables, "after": page["pageInfo"]["endCursor"]}

    def resolve_thread(self, thread_id):
        # A maintainer may have replied while the engine was verifying the fix.
        try:
            data = self.graphql("""
                query($id: ID!) {
                  node(id: $id) {
                    ... on PullRequestReviewThread { isResolved comments(first: 1) { totalCount } }
                  }
                }
            """, {"id": thread_id})
        except (ValueError, OSError, http.client.HTTPException):
            return False
        thread = data.get("node") or {}
        if thread.get("isResolved") is True:
            return True
        count = (thread.get("comments") or {}).get("totalCount")
        if thread.get("isResolved") is not False or type(count) is not int or count != 1:
            return False
        data = self.graphql("""
            mutation($id: ID!) {
              resolveReviewThread(input: {threadId: $id}) { thread { isResolved } }
            }
        """, {"id": thread_id})
        if not data["resolveReviewThread"]["thread"]["isResolved"]:
            raise ValueError("GitHub did not mark the Mortis thread as resolved.")
        return True

    def pages(self, path):
        page = 1
        separator = "&" if "?" in path else "?"
        while True:
            rows = self.request("GET", f"{path}{separator}per_page=100&page={page}")
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


def evidence_digest(content):
    return hashlib.sha256(" ".join(content.split()).encode()).hexdigest()


def finding_metadata(finding, head):
    identity = finding.get("id") or ""
    if not FINDING_ID.fullmatch(identity):
        return ""
    evidence = f"<!-- mortis-action:evidence:v1:{evidence_digest(finding['content'])} -->\n"
    value = {key: finding[key] for key in ("id", "path", "start_line", "end_line", "severity")}
    value.update(source_sha=head, content=" ".join(finding["content"].split())[:400])
    encoded = base64.b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()
    return f"{FINDING_METADATA}{encoded} -->\n{evidence}"


def mortis_bot(author):
    return bool(author and author.get("__typename") == "Bot" and author.get("login") in {BOT, "github-actions"})


def tracked_finding(comment):
    if (not mortis_bot(comment.get("author"))
            or ((comment.get("lastEditedAt") or comment.get("editor")) and not mortis_bot(comment.get("editor")))):
        return None
    lines = comment["body"].split("\n", 3)
    if len(lines) < 3 or not lines[0].startswith("<!-- mortis-action:finding:"):
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
            if match := EVIDENCE_MARKER.fullmatch(lines[2]):
                finding["evidence_digest"] = match[1]
            return finding
    except (KeyError, TypeError, ValueError):
        return None
    return None
