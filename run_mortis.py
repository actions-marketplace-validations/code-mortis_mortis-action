"""Run the pinned Mortis CLI and publish its results on GitHub."""

import http.client
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

# Isolated mode omits the script directory. Import modules from the trusted action checkout.
if sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from mortis_action import (
    baseline,
    commands,
    events,
    github,
    linked_issues,
    markdown,
    repository,
    review,
    trivy,
)
from mortis_action.markdown import redact_credentials


def append(path, message):
    with Path(os.environ[path]).open("a", encoding="utf-8") as stream:
        stream.write(message + "\n")


def output(name, value):
    if "\n" in str(value) or "\r" in str(value):
        raise ValueError(f"Invalid multiline value for output {name}.")
    append("GITHUB_OUTPUT", f"{name}={value}")


def annotation(level, message):
    message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", redact_credentials(message))[:2000]
    message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level}::{message}")


def run_engine(args, repo, revision, pr, reports, directory, *, manual=False, request=None, auto_describe=False):
    command = args[0]
    api = github.GitHubAPI(os.environ["GITHUB_REPOSITORY"], pr["number"]) if pr and command != "scan" else None
    reason = None
    if command == "ask":
        marker = commands.ask_marker(request)
        comments = f"{api.pull}/comments" if request["inline"] else api.issue
        if any((row.get("user") or {}).get("login") == github.BOT and row["body"].startswith(marker)
               for row in api.pages(comments)):
            return 0, "skipped", "Mortis has already answered this comment."
        question_args, reason = commands.ask_arguments(api, request, directory)
        if question_args:
            args = [*args, *question_args]
    environment = {
        name: value
        for name, value in os.environ.items()
        if name not in {"MORTIS_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "MORTIS_API_KEY", "MORTIS_STATE_KEY"}
    }
    environment.update(
        XDG_CONFIG_HOME=str(directory / "config"),
        XDG_STATE_HOME=str(directory / "state"),
        XDG_CACHE_HOME=str(directory / "cache"),
    )
    subprocess.run([sys.executable, "-I", "-m", "venv", directory / "venv"], check=True, env=environment)
    bin_dir = directory / "venv/bin"
    packages = ["mortis-engine==0.1.7"]
    state_secret = os.environ.get("MORTIS_STATE_KEY", "")
    if pr and command == "review":
        packages.append("PyYAML==6.0.3")
        if state_secret:
            packages.append("cryptography==50.0.2")
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
            [bin_dir / "mortis", *arguments], check=False, cwd=directory, env=environment, text=True, capture_output=True
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
        return commands.finish_pr_command(api, pr, request, command, report)
    if request and mortis(command, "--help").returncode:
        raise ValueError(f"The pinned Mortis Engine does not support {command}. Install a compatible release.")

    model = settings["model"] or os.environ["MORTIS_MODEL"].strip()
    if not model:
        raise ValueError("Set a model in mortis.toml or supply the model action input.")
    key = os.environ.get("MORTIS_API_KEY")
    if not key or not key.strip():
        raise ValueError("Set MORTIS_API_KEY from your provider secret.")
    if command == "scan":
        trivy.install_trivy(directory, environment)
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
        return commands.finish_pr_command(api, pr, request, command, report)
    threads = None
    resolution_note = ""
    prior_args = []
    checkpoint = None
    restored = False
    state_note = ""
    if api and (settings.get("incremental") or settings.get("skip_unchanged")):
        try:
            checkpoint = baseline.ReviewBaseline(api, bin_dir / "python", repo, environment, state_secret)
        except ValueError:
            state_note = "\n\nSet MORTIS_STATE_KEY to a base64-encoded 32-byte secret to save incremental review history."
        if checkpoint is not None:
            try:
                restored = checkpoint.restore(pr["base"]["sha"], pr["head"]["sha"])
            except (ValueError, OSError, http.client.HTTPException):
                state_note = "\n\nReview history could not be restored. Check Actions read permissions and the state key."
    if api and settings.get("auto_resolve"):
        if "--prior-findings" in mortis("review", "--help").stdout:
            try:
                threads = api.finding_threads()
            except (ValueError, OSError, http.client.HTTPException):
                resolution_note = "\n\nMortis could not load the GitHub threads for automatic resolution."
            available = {}
            prior = {}
            for finding in (threads or {}).values():
                sha = finding["source_sha"]
                if sha not in available:
                    try:
                        repository.resolve(repo, sha)
                    except subprocess.CalledProcessError:
                        available[sha] = False
                    else:
                        available[sha] = True
                if available[sha]:
                    engine_fields = ("id", "source_sha", "path", "start_line", "end_line", "severity", "content")
                    prior.setdefault(finding["id"], {k: finding[k] for k in engine_fields if k in finding})
            if prior:
                prior_path = directory / "prior-findings.json"
                prior_path.write_text(json.dumps(list(prior.values())), encoding="utf-8")
                prior_args = ["--prior-findings", prior_path]
            if not all(available.values()):
                resolution_note = "\n\nSome Mortis threads have an unavailable original commit and remain open."
        elif restored:
            try:
                threads = api.finding_threads()
            except (ValueError, OSError, http.client.HTTPException):
                resolution_note = "\n\nMortis could not load the GitHub threads for automatic resolution."
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
    heading = markdown.summary(report, status, url, full_review=manual and "--no-incremental" in args)
    heading += resolution_note + state_note
    if api:
        issue_section = None
        if (os.environ.get("MORTIS_CHECK_LINKED_ISSUES", "").lower() == "true" and status != "failed"
                and linked_issues.references(api, pr.get("body"))):
            def ask(question):
                path = directory / "issue-question.txt"
                path.write_text(question, encoding="utf-8")
                answer = mortis("ask", "--base", report["base_sha"], "--head", report["head_sha"],
                                "--repo", repo, "--connection", "ci", "--question-file", path, "--format", "json")
                if answer.returncode:
                    raise ValueError("Mortis could not assess this requirement.")
                return json.loads(answer.stdout)

            def issue_section(previous_body):
                config = {"settings": settings, "connection": connection_args, "engine": packages[0]}
                return linked_issues.section(api, pr, report, previous_body, config, ask)

        try:
            published = review.publish(api, report, heading, repo=repo, workflow_python=bin_dir / "python",
                                       threads=threads, auto_resolve=settings.get("auto_resolve", False),
                                       issue_section=issue_section)
            if not published:
                heading += "\n\nThe PR changed during the run. Results apply to the recorded commit."
            else:
                for name, count in published.counts.items():
                    output(name, count)
                heading += "\n\n" + published.summary
                for warning in published.warnings:
                    annotation("warning", warning)
                if auto_describe and status == "completed" and (note := commands.auto_describe(api, pr, report)):
                    heading += "\n\n" + note
                    annotation("warning", note)
        except (ValueError, OSError, http.client.HTTPException) as error:
            return result.returncode or 1, "failed", f"{heading}\n\nPR publication failed. {error}"
        if published and checkpoint is not None:
            try:
                if api.is_current(report):
                    path = checkpoint.save(report["run_id"], reports)
                    output("baseline-name", checkpoint.name)
                    output("baseline-path", path)
            except (ValueError, OSError, http.client.HTTPException, subprocess.CalledProcessError):
                heading += "\n\nMortis could not save the review history for the next run."
    if status in {"failed", "partial"}:
        diagnostics = [
            *report.get("problems", []),
            *(f"{row['path']}: {row['message']}" for row in report.get("errors", [])),
            *(f"{row['stage']}: {row['error']}" for row in report.get("stage_errors", [])),
            *(row["reason"] for row in report["coverage"].get("waived", [])),
        ]
        if diagnostics:
            heading += "\n\n" + markdown.safe_text(redact_credentials(" ".join(dict.fromkeys(diagnostics))), 1400)
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
            manual = event_name in events.COMMENT_EVENTS
            request = None
            if event_name in events.REMOTE_REVIEW_EVENTS:
                if command != "review":
                    raise ValueError("This event supports only Mortis PR reviews.")
                pr, reason = events.remote_pull_request(event_name, event)
                repo = directory / "review.git"
                args, revision = repository.fetch_pull_request(repo, pr) if pr else (None, reason)
                if args and manual:
                    name, question = events.comment_command(event_name, event)
                    if name == "review" and question == "full":
                        args = [*args, "--no-incremental", "--no-skip-unchanged"]
                    elif name != "review":
                        args = [name, *args[1:]]
                        request = {"question": question, "comment": event["comment"],
                                   "inline": event_name == "pull_request_review_comment"}
            else:
                pr = event.get("pull_request") if event_name == "pull_request" else None
                repo = os.environ["GITHUB_WORKSPACE"]
                args, revision = events.select_run(command, event_name, event, repo)
            if args is None:
                code, status, message = 0, "skipped", revision
            else:
                # Runner-local outputs must outlive the temporary Engine state.
                reports = Path(tempfile.mkdtemp(prefix="mortis-reports-", dir=runner_temp))
                code, status, message = run_engine(
                    args, repo, revision, pr, reports, directory, manual=manual, request=request,
                    auto_describe=(os.environ.get("MORTIS_AUTO_DESCRIBE", "").lower() == "true"
                                   and event_name in {"pull_request", "pull_request_target"}
                                   and event.get("action") in {"opened", "ready_for_review"}),
                )
    except subprocess.CalledProcessError as error:
        code, status, message = (
            1,
            "failed",
            f"Setup or Git failed (exit {error.returncode}). Check checkout, refs and setup logs.",
        )
    except (KeyError, OSError, ValueError, http.client.HTTPException, tarfile.TarError) as error:
        code, status, message = 1, "failed", str(error)
    message = redact_credentials(message)
    if status in {"failed", "partial"}:
        annotation("error" if status == "failed" else "warning", message)
    else:
        print(f"Mortis action {status}. See the job summary for details.")
    if not message.startswith("## Mortis "):
        message = f"## Mortis {status}\n\n{markdown.safe_text(message, 2000)}"
    append("GITHUB_STEP_SUMMARY", message)
    output("status", status)
    output("exit-code", code)


if __name__ == "__main__":
    main()
