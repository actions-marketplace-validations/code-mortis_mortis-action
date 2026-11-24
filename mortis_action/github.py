"""GitHub API access and persisted metadata for Mortis findings."""

import base64
import http.client
import json
import os
import re
from urllib.parse import quote, urlsplit

BOT = "github-actions[bot]"
COMMENT_BODY_LIMIT = 55_000
FINDING_ID = re.compile(r"finding-[0-9a-f]{32}")
FINDING_METADATA = "<!-- mortis-action:prior-finding:v1:"


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
