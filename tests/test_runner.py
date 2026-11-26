"""Exercise the action lifecycle, Engine invocation and workflow outputs."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import run_mortis as runner
from mortis_action import baseline, events, github, repository, review
from mortis_action import trivy as scanner
from tests.helpers import ActionTestCase, comment_event, pr_event, review_report


class RunnerTests(ActionTestCase):
    def test_skips_ineligible_prs_without_resolving_revisions(self):
        for details in ({"draft": True}, {"fork": True}, {"login": "dependabot[bot]"}):
            with self.subTest(details=details):
                args, _ = events.select_run("review", "pull_request", pr_event(**details), "")
                self.assertIsNone(args)

    def test_comment_entrypoint_fetches_only_after_authorization(self):
        event = self.directory / "event.json"
        event.write_text(json.dumps(comment_event()))
        base, head = "a" * 40, "b" * 40
        pr = pr_event(base, head, fork=True)["pull_request"]
        args = ["review", "--base", base, "--head", head]
        environment = {
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(self.directory),
            "GITHUB_EVENT_NAME": "issue_comment",
            "GITHUB_EVENT_PATH": str(event),
            "MORTIS_COMMAND": "review",
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(github.GitHubAPI, "request", return_value={"permission": "read"}) as request,
            patch.object(repository, "fetch_pull_request", return_value=(args, base)) as fetch,
            patch.object(runner, "run_engine", return_value=(0, "completed", "## Mortis review")) as engine,
            patch("builtins.print"),
        ):
            runner.main()
            self.assertIn("status=skipped", self.outputs.read_text())
            fetch.assert_not_called()
            engine.assert_not_called()

            request.side_effect = [{"permission": "write"}, pr]
            runner.main()
            self.assertIn("status=completed", self.outputs.read_text())
            repo, fetched_pr = fetch.call_args.args
            self.assertEqual(fetched_pr, pr)
            self.assertEqual(engine.call_args.args[:4], (args, repo, base, pr))
            self.assertTrue(engine.call_args.kwargs["manual"])

    def test_ask_routes_from_the_conversation_and_reuses_the_engine_connection(self):
        base, head = "a" * 40, "b" * 40
        pr = pr_event(base, head, fork=True)["pull_request"]
        event = comment_event("/mortis ask Why did this change?")
        event["comment"]["id"] = 23
        event_path = self.directory / "event.json"
        event_path.write_text(json.dumps(event))
        engine_calls, comments = [], []
        settings = {"review": {"settings": {"model": "configured-model", "include_bot_prs": False}}}
        answer = {
            "schema_version": "mortis.ask/v1", "status": "completed", "base_sha": base, "head_sha": head,
            "result": {"answer": "The behavior changed.",
                       "citations": [{"path": "a (b).py", "sha": head, "start_line": 4, "end_line": 5}]},
        }

        def process(argv, **kwargs):
            if Path(argv[0]).name == "mortis":
                engine_calls.append(argv)
                if argv[1] == "config":
                    return subprocess.CompletedProcess(argv, 0, json.dumps(settings), "")
                if argv[1] == "ask" and "--format" in argv:
                    self.assertEqual(Path(argv[argv.index("--question-file") + 1]).read_text(), "Why did this change?")
                    return subprocess.CompletedProcess(argv, 0, json.dumps(answer), "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        def request(method, path, data=None, **kwargs):
            if path.endswith("/permission"):
                return {"permission": "write"}
            if method == "GET":
                return pr
            self.assertEqual((method, path), ("POST", "/issues/42/comments"))
            comments.append({"user": {"login": github.BOT}, **data})

        with (
            patch.dict(os.environ, {"RUNNER_OS": "Linux", "RUNNER_TEMP": str(self.directory),
                                    "MORTIS_COMMAND": "review", "GITHUB_EVENT_NAME": "issue_comment",
                                    "GITHUB_EVENT_PATH": str(event_path)}),
            patch.object(github.GitHubAPI, "request", side_effect=request),
            patch.object(github.GitHubAPI, "pages", side_effect=lambda path: [{"user": None, "body": ""}, *comments]),
            patch.object(repository, "fetch_pull_request", return_value=(["review", "--base", base, "--head", head], base)),
            patch.object(subprocess, "run", side_effect=process),
            patch("builtins.print"),
        ):
            runner.main()
            runner.main()
        self.assertIn("status=completed", self.outputs.read_text())
        self.assertIn("status=skipped", self.outputs.read_text())
        self.assertEqual(len(comments), 1)
        self.assertIn("#issuecomment-23", comments[0]["body"])
        self.assertIn(f"{head}/a%20%28b%29.py#L4-L5", comments[0]["body"])
        connect = next(call for call in engine_calls if call[1] == "connect")
        self.assertEqual(connect[connect.index("--model") + 1], "configured-model")
        self.assertEqual(sum("--format" in call for call in engine_calls), 1)

    def run_mock(self, command, settings, pr=None, *, invalid=False, manual=False, threads=None):
        calls = []
        report = (
            review_report()
            if command == "review"
            else {
                "schema_version": "mortis.security/v1",
                "status": "partial",
                "run_id": "scan-1",
                "commit": "a" * 40,
                "coverage": {"completed_files": 1, "selected_files": 3},
                "findings": [],
                "stages": {"trivy": {"status": "partial"}},
                "problems": ["Dependency inventory timed out. Token test.token",
                             "Fix verification remains uncertain for a private finding title."],
            }
        )

        def process(argv, **kwargs):
            calls.append(argv)
            self.assertNotIn("MORTIS_GITHUB_TOKEN", kwargs["env"])
            self.assertNotIn("MORTIS_STATE_KEY", kwargs["env"])
            if Path(argv[0]).name != "mortis":
                return subprocess.CompletedProcess(argv, 0)
            if argv[1] == "config":
                self.assertNotIn("MORTIS_API_KEY", kwargs["env"])
                return subprocess.CompletedProcess(
                    argv,
                    int(invalid),
                    json.dumps({command: {"settings": settings}}),
                    "Invalid TOML" if invalid else "",
                )
            self.assertEqual(kwargs["env"]["MORTIS_API_KEY"], "test-provider-key")
            if argv[1] == "connect":
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[1:] == ["review", "--help"]:
                return subprocess.CompletedProcess(argv, 0, "--prior-findings" if threads else "", "")
            if threads:
                prior_file = Path(argv[argv.index("--prior-findings") + 1])
                prior = json.loads(prior_file.read_text())
                self.assertEqual([item["id"] for item in prior], [item["id"] for item in threads.values()])
                for item in prior:
                    self.assertNotIn("github_anchor", item)
                    self.assertNotIn("evidence_digest", item)
            Path(argv[-3]).write_text(json.dumps(report))
            Path(argv[-1]).write_text("# Report")
            return subprocess.CompletedProcess(argv, 2, "", "")

        with (
            patch.object(subprocess, "run", side_effect=process),
            patch.object(scanner, "install_trivy") as trivy,
            patch.object(review, "publish", return_value=review.Delivery()),
            patch.object(github.GitHubAPI, "finding_threads", return_value=threads) as list_threads,
            patch.object(repository, "resolve", return_value="a" * 40),
        ):
            result = runner.run_engine([command], ".", "base", pr, self.reports, self.directory, manual=manual)
            if threads:
                list_threads.assert_called_once()
        return result, calls, trivy

    def test_review_supplies_previous_findings_to_the_engine(self):
        previous = {"id": "finding-" + "1" * 32, "source_sha": "a" * 40,
                    "github_anchor": ("app.py", 1, 1), "evidence_digest": "f" * 64}
        pr = pr_event("a" * 40, "b" * 40)["pull_request"]
        settings = {"automatic": True, "include_bot_prs": False, "auto_resolve": True, "model": ""}
        result, calls, _ = self.run_mock("review", settings, pr, threads={"thread": previous})
        self.assertEqual(result[:2], (2, "partial"))
        self.assertIn("--prior-findings", calls[-1])
        result, calls, _ = self.run_mock("review", settings, pr)
        self.assertEqual(result[:2], (2, "partial"))
        self.assertNotIn("--prior-findings", calls[-1])
        self.assertIn("does not support PR finding verification", result[2])

    def test_pr_review_restores_and_stages_encrypted_history_on_partial_results(self):
        pr = pr_event("a" * 40, "b" * 40)["pull_request"]
        settings = {"automatic": True, "include_bot_prs": False, "incremental": True, "model": ""}
        checkpoint = Mock()
        checkpoint.name = "mortis-pr-42"
        checkpoint.save.return_value = self.reports / "baseline.enc"
        with (
            patch.dict(os.environ, {"MORTIS_STATE_KEY": "test-state-key"}),
            patch.object(baseline, "ReviewBaseline", return_value=checkpoint),
            patch.object(github.GitHubAPI, "is_current", return_value=True),
        ):
            result, calls, _ = self.run_mock("review", settings, pr)

        self.assertEqual(result[:2], (2, "partial"))
        self.assertTrue(any("cryptography==50.0.2" in call for call in calls))
        checkpoint.restore.assert_called_once_with("a" * 40, "b" * 40)
        checkpoint.save.assert_called_once_with("review-1", self.reports)
        self.assertIn("baseline-name=mortis-pr-42", self.outputs.read_text())
        self.assertIn(f"baseline-path={checkpoint.save.return_value}", self.outputs.read_text())

    def test_incremental_without_a_key_still_reviews_the_pr(self):
        pr = pr_event("a" * 40, "b" * 40)["pull_request"]
        settings = {"automatic": True, "include_bot_prs": False, "incremental": True, "model": ""}
        with patch.dict(os.environ, {"MORTIS_STATE_KEY": ""}):
            result, calls, _ = self.run_mock("review", settings, pr)

        self.assertEqual(result[:2], (2, "partial"))
        self.assertIn("Set MORTIS_STATE_KEY", result[2])
        self.assertFalse(any("cryptography==50.0.2" in call for call in calls))
        self.assertNotIn("baseline-path=", self.outputs.read_text())

    def test_automatic_and_bot_policy_skip_before_connect(self):
        for settings in ({"automatic": False}, {"automatic": True, "include_bot_prs": False}):
            result, calls, trivy = self.run_mock(
                "review", settings, pr_event(author_type="Bot")["pull_request"]
            )
            self.assertEqual(result[:2], (0, "skipped"))
            self.assertFalse(any("connect" in call for call in calls))
            trivy.assert_not_called()

    def test_invalid_config_fails_before_connect(self):
        with self.assertRaisesRegex(ValueError, "Invalid TOML"):
            self.run_mock("review", {}, invalid=True)

    def test_manual_reviews_work_with_automatic_reviews_disabled(self):
        result, _, _ = self.run_mock(
            "review", {"automatic": False, "model": ""}, pr_event("a" * 40, "b" * 40, fork=True)["pull_request"], manual=True
        )
        self.assertEqual(result[:2], (2, "partial"))

    def test_manual_dependabot_review_can_run_with_bot_reviews_disabled(self):
        settings = {"automatic": False, "include_bot_prs": False, "model": ""}
        for login, expected in (("dependabot[bot]", (2, "partial")), ("another[bot]", (0, "skipped"))):
            with self.subTest(login=login):
                pr = pr_event("a" * 40, "b" * 40, login=login, author_type="Bot")["pull_request"]
                result, calls, _ = self.run_mock("review", settings, pr, manual=True)
                self.assertEqual(result[:2], expected)
                self.assertEqual(any("connect" in call for call in calls), login == "dependabot[bot]")

    def test_partial_scan_preserves_outputs_and_uses_configured_model(self):
        with patch.dict(os.environ, {"MORTIS_GITHUB_TOKEN": "test.token"}):
            result, calls, trivy = self.run_mock("scan", {"model": "committed-model"})
        self.assertEqual(result[:2], (2, "partial"))
        self.assertIn("1/3 files covered", result[2])
        self.assertIn("Incomplete scan stages: trivy", result[2])
        self.assertNotIn("private finding title", result[2])
        self.assertNotIn("test&#46;token", result[2])
        trivy.assert_called_once()
        connect = next(call for call in calls if "connect" in call)
        self.assertEqual(connect[connect.index("--model") + 1], "committed-model")
        self.assertIn("run-id=scan-1", self.outputs.read_text())
        self.assertIn(f"report-json={self.reports / 'report.json'}", self.outputs.read_text())
        self.assertIn(f"report-markdown={self.reports / 'report.md'}", self.outputs.read_text())
        self.assertNotIn("finding-index=", self.outputs.read_text())

    def test_opt_in_scan_index_is_staged_even_for_a_partial_result(self):
        with patch.dict(os.environ, {"MORTIS_RETAIN_SCAN_FINDINGS": "true"}):
            result, _, _ = self.run_mock("scan", {"model": "scan-model"})
        self.assertEqual(result[:2], (2, "partial"))
        emitted = dict(line.split("=", 1) for line in self.outputs.read_text().splitlines())
        index = Path(emitted["finding-index"])
        self.assertIn("Scan findings (0)", index.read_text())
        self.assertNotIn("Dependency inventory timed out", index.read_text())

    def test_review_uses_fallback_model_without_installing_trivy(self):
        result, calls, trivy = self.run_mock("review", {"model": ""})
        self.assertEqual(result[:2], (2, "partial"))
        connect = next(call for call in calls if "connect" in call)
        self.assertEqual(connect[connect.index("--model") + 1], "fallback")
        self.assertNotIn("--protocol", connect)
        self.assertNotIn("--base-url", connect)
        trivy.assert_not_called()

    def test_review_passes_connection_overrides_to_engine(self):
        endpoint = "https://opencode.ai/inference/go/openai/v1"
        with patch.dict(os.environ, {
            "MORTIS_PROVIDER": "opencode-go",
            "MORTIS_PROTOCOL": "openai-responses",
            "MORTIS_BASE_URL": endpoint,
        }):
            result, calls, _ = self.run_mock("review", {"model": ""})
        self.assertEqual(result[:2], (2, "partial"))
        connect = next(call for call in calls if "connect" in call)
        self.assertEqual(connect[connect.index("--provider") + 1], "opencode-go")
        self.assertEqual(connect[connect.index("--protocol") + 1], "openai-responses")
        self.assertEqual(connect[connect.index("--base-url") + 1], endpoint)
        self.assertEqual(connect[connect.index("--model") + 1], "fallback")

    def test_entrypoint_records_partial_result_before_shell_propagates_exit_code(self):
        event = self.directory / "event.json"
        event.write_text("{}")
        environment = {
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(self.directory),
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_WORKSPACE": str(self.directory),
            "MORTIS_COMMAND": "scan",
        }
        def engine(args, repo, revision, pr, reports, directory, *, manual, request, auto_describe):
            for name, filename in (("report-json", "report.json"), ("report-markdown", "report.md")):
                path = reports / filename
                path.write_text("Partial report")
                runner.output(name, path)
            (directory / "state").mkdir()
            return 2, "partial", "## Mortis security scan"

        with (
            patch.dict(os.environ, environment),
            patch.object(events, "select_run", return_value=(["scan", "--ref", "base"], "base")),
            patch.object(runner, "run_engine", side_effect=engine) as run,
            patch("builtins.print") as log,
        ):
            runner.main()
        log.assert_called_once_with("::warning::## Mortis security scan")
        self.assertIn("status=partial\nexit-code=2\n", self.outputs.read_text())
        self.assertIn("Mortis security scan", Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text())
        outputs = dict(line.split("=", 1) for line in self.outputs.read_text().splitlines())
        for name in ("report-json", "report-markdown"):
            self.assertEqual(Path(outputs[name]).read_text(), "Partial report")
        self.assertFalse(run.call_args.args[-1].exists())

    def test_entrypoint_logs_the_failure_without_secrets_or_extra_workflow_commands(self):
        base = "a" * 40
        event = self.directory / "event.json"
        event.write_text("{}")
        environment = {
            "RUNNER_OS": "Linux",
            "RUNNER_TEMP": str(self.directory),
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_WORKSPACE": str(self.directory),
            "MORTIS_COMMAND": "scan",
        }
        failure = ValueError("Provider rejected test-provider-key at 50%\r\n::notice::test-github-token")
        with (
            patch.dict(os.environ, environment),
            patch.object(events, "select_run", return_value=(["scan", "--ref", base], base)),
            patch.object(runner, "run_engine", side_effect=failure),
            patch("builtins.print") as log,
        ):
            runner.main()
        log.assert_called_once_with(
            "::error::Provider rejected [redacted] at 50%25%0D%0A::notice::[redacted]"
        )
        self.assertIn("status=failed\nexit-code=1\n", self.outputs.read_text())

    def test_isolated_entrypoint_runs_from_the_runner_temp_directory(self):
        event = self.directory / "event.json"
        event.write_text(json.dumps(comment_event("Looks good")))
        entrypoint = Path(runner.__file__).resolve()
        result = subprocess.run(
            [sys.executable, "-I", "-B", entrypoint],
            cwd=self.directory,
            env={**os.environ, "RUNNER_OS": "Linux", "RUNNER_TEMP": str(self.directory),
                 "MORTIS_COMMAND": "review", "GITHUB_EVENT_NAME": "issue_comment",
                 "GITHUB_EVENT_PATH": str(event)},
            capture_output=True, text=True, check=True,
        )
        self.assertIn("Mortis action skipped", result.stdout)
        self.assertIn("status=skipped\nexit-code=0\n", self.outputs.read_text())
