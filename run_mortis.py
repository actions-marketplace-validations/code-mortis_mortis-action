"""Run the pinned Mortis CLI and publish its confirmed review findings."""

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
from urllib.parse import urlsplit

SUMMARY_MARKER = "<!-- mortis-action:review -->"
BOT = "github-actions[bot]"
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


def resolve(repo, ref):
    if not ref or ref.startswith("-"):
        raise ValueError("Supply a valid commit reference.")
    return subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()


def select_run(command, event_name, event, repo):
    if command not in {"review", "scan"}:
        raise ValueError("Set command to review or scan.")
    if event_name == "pull_request_target":
        raise ValueError("Use pull_request for Mortis reviews with provider credentials.")
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
    base, head = resolve(repo, base), resolve(repo, head)
    shallow = subprocess.check_output(["git", "-C", repo, "rev-parse", "--is-shallow-repository"], text=True)
    ancestor = subprocess.run(["git", "-C", repo, "merge-base", base, head], capture_output=True)
    if shallow.strip() == "true" or ancestor.returncode != 0:
        raise ValueError(
            "A review needs complete Git history and a common ancestor. Use checkout with fetch-depth: 0."
        )
    return ["review", "--base", base, "--head", head], base


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


def added_lines(patch):
    line = None
    for row in patch.splitlines():
        if row.startswith("@@"):
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", row)
            line = int(match[1]) if match else None
        elif line is not None:
            if row.startswith("+"):
                yield line
            if row.startswith(("+", " ")):
                line += 1


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

    def request(self, method, path, data=None, *, allow_invalid_anchor=False):
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


def publish(api, report, heading):
    if not api.is_current(report):
        return False
    findings = report["findings"]
    body = f"{SUMMARY_MARKER}\n{heading}"
    narrative = ((report.get("summary") or {}).get("result") or {}).get("narrative")
    if narrative:
        body += "\n\n" + safe_text(narrative, 1200)
    for finding in findings:
        item = "\n\n- " + finding_text(finding)
        if len((body + item).encode()) > 55_000:
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
    additions = {
        file["filename"]: sorted(added_lines(file.get("patch") or ""))
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
        line = next(
            (
                line
                for line in additions.get(path, ())
                if finding["start_line"] <= line <= finding["end_line"]
            ),
            None,
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
        api.request(
            "POST",
            comments,
            {
                "body": f"{marker}\n{finding_text(finding)}",
                "commit_id": report["head_sha"],
                "path": path,
                "line": line,
                "side": "RIGHT",
            },
            allow_invalid_anchor=True,
        )
        markers.add(marker)
    return True


def run_engine(args, repo, revision, pr, reports, directory):
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
            "mortis-engine==0.1.1",
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
        if not settings["automatic"]:
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
    connection = mortis(
        "connect",
        "ci",
        "--provider",
        os.environ["MORTIS_PROVIDER"],
        "--model",
        model,
        "--api-key-env",
        "MORTIS_API_KEY",
        "--non-interactive",
    )
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
        repo = os.environ["GITHUB_WORKSPACE"]
        args, revision = select_run(command, event_name, event, repo)
        if args is None:
            code, status, message = 0, "skipped", revision
        else:
            with tempfile.TemporaryDirectory(prefix="mortis-work-", dir=os.environ["RUNNER_TEMP"]) as scratch:
                # Keep reports readable by later steps while removing provider configuration and local history.
                directory = Path(tempfile.mkdtemp(prefix="mortis-", dir=os.environ["RUNNER_TEMP"]))
                code, status, message = run_engine(
                    args,
                    repo,
                    revision,
                    event.get("pull_request") if event_name == "pull_request" else None,
                    directory,
                    Path(scratch),
                )
    except subprocess.CalledProcessError as error:
        code, status, message = (
            1,
            "failed",
            f"Setup or Git failed (exit {error.returncode}). Check checkout, refs and setup logs.",
        )
    except (KeyError, OSError, ValueError, tarfile.TarError) as error:
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
