"""Run the pinned Mortis CLI and publish its confirmed review findings."""

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
REMOTE_REVIEW_EVENTS = {"pull_request_target", "issue_comment"}
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


def remote_pull_request(event_name, event):
    repository = os.environ["GITHUB_REPOSITORY"]
    manual = event_name == "issue_comment"
    if manual:
        issue = event.get("issue", {})
        comment = event.get("comment", {})
        author = comment.get("user", {})
        if (
            event.get("action") != "created"
            or not issue.get("pull_request")
            or comment.get("body") != "/mortis review"
            or author.get("type") != "User"
        ):
            return None, "No Mortis review command"
        api = GitHubAPI(repository, issue["number"])
        if not api.can_review(author["login"]):
            return None, "Mortis review commands require repository write access"
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
    return f"\n\n```suggestion\n{replacement}\n```"


def safe_text(value, limit):
    text = " ".join(str(value).split())[:limit]
    return re.sub(r"[^\w ,:;!?'/\-]|_", lambda char: f"&#{ord(char[0])};", text)


def finding_text(finding):
    location = f"{finding['path']}:{finding['start_line']}"
    return (
        f"**{safe_text(finding['severity'], 20)}** · {safe_text(location, 300)}"
        f" — {safe_text(finding['content'], 400)}"
    )


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
        self.repo = f"/repos/{repository}"
        self.pull = f"/pulls/{int(number)}"
        self.issue = f"/issues/{int(number)}/comments"

    def request(self, method, path, data=None, *, allow_invalid_anchor=False, allow_missing=False):
        connection = http.client.HTTPSConnection(self.endpoint.netloc, timeout=30)
        try:
            connection.request(
                method,
                self.endpoint.path.rstrip("/") + self.repo + path,
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

    def pages(self, path):
        page = 1
        while True:
            rows = self.request("GET", f"{path}?per_page=100&page={page}")
            yield from rows
            if len(rows) < 100:
                return
            page += 1

    def is_current(self, report):
        pr = self.request("GET", self.pull)
        return (
            pr["state"] == "open"
            and not pr["draft"]
            and pr["base"]["sha"] == report["base_sha"]
            and pr["head"]["sha"] == report["head_sha"]
        )

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


def publish(api, report, heading):
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

    if not findings:
        return True
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
            "body": f"{marker}\n{finding_text(finding)}",
            "commit_id": report["head_sha"],
            "path": path,
            "line": line,
            "side": "RIGHT",
        }
        suggestion = suggested_change(finding, report["head_sha"], lines)
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


def run_engine(args, repo, revision, pr, reports, directory, *, manual=False):
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
            "mortis-engine==0.1.3",
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
    command = args[0]
    settings = json.loads(config.stdout)[command]["settings"]
    if command == "review" and pr:
        if not manual and not settings["automatic"]:
            return 0, "skipped", "Automatic review disabled in mortis.toml"
        if pr["user"]["type"] == "Bot" and not settings["include_bot_prs"]:
            return 0, "skipped", "Bot reviews disabled in mortis.toml"

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
    report_json = reports / "report.json"
    report_markdown = reports / "report.md"
    result = mortis(
        *args, "--repo", repo, "--connection", "ci", "--output", report_json, "--output", report_markdown
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
    heading = summary(report, status, url)
    if pr and command == "review":
        try:
            if not publish(GitHubAPI(os.environ["GITHUB_REPOSITORY"], pr["number"]), report, heading):
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
            if event_name in REMOTE_REVIEW_EVENTS:
                if command != "review":
                    raise ValueError("This event supports only Mortis PR reviews.")
                pr, reason = remote_pull_request(event_name, event)
                repo = directory / "review.git"
                args, revision = fetch_pull_request(repo, pr) if pr else (None, reason)
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
                    args, repo, revision, pr, reports, directory, manual=event_name == "issue_comment"
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
