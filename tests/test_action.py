import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import run_mortis as action


def pr_event(base="base", head="head", *, draft=False, fork=False, login="contributor", author_type="User"):
    return {
        "action": "opened",
        "sender": {"login": login},
        "pull_request": {
            "number": 42,
            "state": "open",
            "draft": draft,
            "user": {"login": login, "type": author_type},
            "base": {"sha": base, "repo": {"full_name": "owner/repo"}},
            "head": {"sha": head, "repo": {"full_name": "user/fork" if fork else "owner/repo"}},
        },
    }


def comment_event(body="/mortis review"):
    return {
        "action": "created",
        "sender": {"login": "maintainer"},
        "issue": {"number": 42, "pull_request": {"url": "https://api.github.com/repos/owner/repo/pulls/42"}},
        "comment": {"body": body, "user": {"login": "maintainer", "type": "User"}},
    }


def review_report():
    return {
        "schema_version": "mortis.review/v1",
        "status": "partial",
        "run_id": "review-1",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "coverage": {"completed": ["app.py"], "selected": ["app.py", "other.py"]},
        "findings": [
            {
                "severity": "high",
                "path": "app.py",
                "start_line": 4,
                "end_line": 5,
                "content": "Inline defect",
            },
            {
                "severity": "low",
                "path": "other.py",
                "start_line": 7,
                "end_line": 7,
                "content": "Summary-only defect",
            },
        ],
    }


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.repo = self.enterContext(tempfile.TemporaryDirectory())
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Mortis Test")
        self.git("config", "user.email", "mortis@example.org")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", self.repo, *args], text=True).strip()

    def commit(self, files):
        for name, value in files.items():
            Path(self.repo, name).write_text(value)
        self.git("add", ".")
        self.git("commit", "-qm", "Fixture")
        return self.git("rev-parse", "HEAD")

    def engine(self, *args, repo=None):
        return subprocess.run(
            [
                sys.executable,
                "-c",
                "from mortis_engine.cli import main; raise SystemExit(main())",
                *args,
                "--repo",
                repo or self.repo,
            ],
            text=True,
            capture_output=True,
        )

    def test_trusted_target_policy_and_merge_base(self):
        ancestor = self.commit({"keep.py": "x = 1\n", "skip.py": "y = 1\n"})
        self.git("checkout", "-qb", "candidate")
        head = self.commit(
            {
                "keep.py": "x = 2\n",
                "skip.py": "y = 2\n",
                "mortis.toml": '[review]\nexclusions = "keep.py"\n',
            }
        )
        self.git("checkout", "-q", "main")
        base = self.commit(
            {
                "mortis.toml": '[review]\nexclusions = "skip.py"\nmodel = "review-model"\n[scan]\nmodel = "scan-model"\n',
            }
        )
        self.git("checkout", "-q", "candidate")
        Path(self.repo, "mortis.toml").write_text("[broken")
        args, revision = action.select_run("review", "pull_request", pr_event(base, head), self.repo)
        self.assertEqual(revision, base)
        result = self.engine(*args, "--preview", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["merge_base"], ancestor)
        self.assertEqual({row["path"] for row in report["selected_files"]}, {"keep.py", "mortis.toml"})
        self.assertEqual(self.config(base)["review"]["settings"]["model"], "review-model")
        self.assertEqual(self.config(ancestor)["review"]["settings"]["language"], "English")
        with patch.dict(os.environ, {"MORTIS_REF": "main"}):
            scan_args, revision = action.select_run("scan", "schedule", {}, self.repo)
        self.assertEqual(scan_args, ["scan", "--ref", base])
        self.assertEqual(self.config(revision)["scan"]["settings"]["model"], "scan-model")
        with patch.dict(os.environ, {"MORTIS_BASE": "main", "MORTIS_HEAD": "candidate"}):
            self.assertEqual(action.select_run("review", "workflow_dispatch", {}, self.repo), (args, base))
        invalid = self.commit({"mortis.toml": "[invalid"})
        self.assertNotEqual(self.engine("config", "show", "--base", invalid).returncode, 0)

    def config(self, sha):
        result = self.engine("config", "show", "--base", sha)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_bare_fetch_pins_refs_and_uses_target_policy(self):
        base = self.commit({"keep.py": "x = 1\n", "mortis.toml": '[review]\nexclusions = "skip.py"\n'})
        head = self.commit({"keep.py": "x = 2\n", "skip.py": "x = 3\n", "mortis.toml": '[review]\nexclusions = "keep.py"\n'})
        self.git("update-ref", "refs/pull/42/head", head)
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "owner").mkdir()
        subprocess.run(["git", "clone", "--quiet", "--mirror", self.repo, root / "owner/repo.git"], check=True)
        pr = pr_event(base, head, fork=True)["pull_request"]
        repo = root / "fetch.git"
        with patch.dict(os.environ, {
            "GITHUB_SERVER_URL": root.as_uri(), "GITHUB_REPOSITORY": "owner/repo", "MORTIS_GITHUB_TOKEN": "test-token",
        }):
            args, revision = action.fetch_pull_request(repo, pr)
            stale = {**pr, "head": {**pr["head"], "sha": base}}
            stale_args, _ = action.fetch_pull_request(root / "stale.git", stale)

        self.assertIsNone(stale_args)
        self.assertEqual(revision, base)
        self.assertFalse((repo / "mortis.toml").exists())
        self.assertNotIn("extraheader", (repo / "config").read_text().lower())
        result = self.engine(*args, "--preview", "--format", "json", repo=repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["head_sha"], head)
        self.assertEqual({row["path"] for row in report["selected_files"]}, {"keep.py", "mortis.toml"})


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.reports = self.directory / "reports"
        self.reports.mkdir()
        self.outputs = self.directory / "outputs"
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "GITHUB_OUTPUT": str(self.outputs),
                    "GITHUB_STEP_SUMMARY": str(self.directory / "summary"),
                    "MORTIS_API_KEY": "test-provider-key",
                    "MORTIS_PROVIDER": "openai",
                    "MORTIS_MODEL": "fallback",
                    "MORTIS_GITHUB_TOKEN": "test-github-token",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_RUN_ID": "123",
                },
            )
        )

    def test_skips_ineligible_prs_without_resolving_revisions(self):
        for details in ({"draft": True}, {"fork": True}, {"login": "dependabot[bot]"}):
            with self.subTest(details=details):
                args, _ = action.select_run("review", "pull_request", pr_event(**details), "")
                self.assertIsNone(args)

    def test_comment_admission_checks_command_and_author_before_fetching_pr(self):
        pr = pr_event(fork=True)["pull_request"]
        with patch.object(action.GitHubAPI, "request") as request:
            for body in ("Looks good", "/Mortis review", "/mortis review now"):
                self.assertIsNone(action.remote_pull_request("issue_comment", comment_event(body))[0])
            request.assert_not_called()

            for permission in (None, {"permission": "read"}):
                request.reset_mock()
                request.return_value = permission
                self.assertIsNone(action.remote_pull_request("issue_comment", comment_event())[0])
                request.assert_called_once_with("GET", "/collaborators/maintainer/permission", allow_missing=True)

            request.side_effect = [{"permission": "write"}, pr]
            self.assertEqual(action.remote_pull_request("issue_comment", comment_event()), (pr, None))

    def test_automatic_fork_review_is_opt_in_and_uses_event_shas(self):
        event = pr_event(fork=True)
        pr = event["pull_request"]
        with patch.object(action.GitHubAPI, "request", return_value=pr) as request:
            with patch.dict(os.environ, {"MORTIS_REVIEW_FORKS": "false"}):
                self.assertIsNone(action.remote_pull_request("pull_request_target", event)[0])
            with patch.dict(os.environ, {"MORTIS_REVIEW_FORKS": "true"}):
                self.assertEqual(action.remote_pull_request("pull_request_target", event), (pr, None))
                request.return_value = {**pr, "head": {**pr["head"], "sha": "new-head"}}
                self.assertIsNone(action.remote_pull_request("pull_request_target", event)[0])

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
            patch.object(action.GitHubAPI, "request", return_value={"permission": "read"}) as request,
            patch.object(action, "fetch_pull_request", return_value=(args, base)) as fetch,
            patch.object(action, "run_engine", return_value=(0, "completed", "## Mortis review")) as engine,
            patch("builtins.print"),
        ):
            action.main()
            self.assertIn("status=skipped", self.outputs.read_text())
            fetch.assert_not_called()
            engine.assert_not_called()

            request.side_effect = [{"permission": "write"}, pr]
            action.main()
            self.assertIn("status=completed", self.outputs.read_text())
            repo, fetched_pr = fetch.call_args.args
            self.assertEqual(fetched_pr, pr)
            self.assertEqual(engine.call_args.args[:4], (args, repo, base, pr))
            self.assertTrue(engine.call_args.kwargs["manual"])

    def run_mock(self, command, settings, pr=None, *, invalid=False, manual=False):
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
            }
        )

        def process(argv, **kwargs):
            calls.append(argv)
            self.assertNotIn("MORTIS_GITHUB_TOKEN", kwargs["env"])
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
            Path(argv[-3]).write_text(json.dumps(report))
            Path(argv[-1]).write_text("# Report")
            return subprocess.CompletedProcess(argv, 2, "", "")

        with (
            patch.object(action.subprocess, "run", side_effect=process),
            patch.object(action, "install_trivy") as trivy,
            patch.object(action, "publish", return_value=True),
        ):
            result = action.run_engine([command], ".", "base", pr, self.reports, self.directory, manual=manual)
        return result, calls, trivy

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
            "review", {"automatic": False, "model": ""}, pr_event(fork=True)["pull_request"], manual=True
        )
        self.assertEqual(result[:2], (2, "partial"))

    def test_partial_scan_preserves_outputs_and_uses_configured_model(self):
        result, calls, trivy = self.run_mock("scan", {"model": "committed-model"})
        self.assertEqual(result[:2], (2, "partial"))
        self.assertIn("1/3 files covered", result[2])
        trivy.assert_called_once()
        connect = next(call for call in calls if "connect" in call)
        self.assertEqual(connect[connect.index("--model") + 1], "committed-model")
        self.assertIn("run-id=scan-1", self.outputs.read_text())
        self.assertIn(f"report-json={self.reports / 'report.json'}", self.outputs.read_text())
        self.assertIn(f"report-markdown={self.reports / 'report.md'}", self.outputs.read_text())

    def test_review_uses_fallback_model_without_installing_trivy(self):
        result, calls, trivy = self.run_mock("review", {"model": ""})
        self.assertEqual(result[:2], (2, "partial"))
        connect = next(call for call in calls if "connect" in call)
        self.assertEqual(connect[connect.index("--model") + 1], "fallback")
        trivy.assert_not_called()

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
        def engine(args, repo, revision, pr, reports, directory, *, manual):
            for name, filename in (("report-json", "report.json"), ("report-markdown", "report.md")):
                path = reports / filename
                path.write_text("Partial report")
                action.output(name, path)
            (directory / "state").mkdir()
            return 2, "partial", "## Mortis security scan"

        with (
            patch.dict(os.environ, environment),
            patch.object(action, "select_run", return_value=(["scan", "--ref", "base"], "base")),
            patch.object(action, "run_engine", side_effect=engine) as run,
            patch("builtins.print"),
        ):
            action.main()
        self.assertIn("status=partial\nexit-code=2\n", self.outputs.read_text())
        self.assertIn("Mortis security scan", Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text())
        outputs = dict(line.split("=", 1) for line in self.outputs.read_text().splitlines())
        for name in ("report-json", "report-markdown"):
            self.assertEqual(Path(outputs[name]).read_text(), "Partial report")
        self.assertFalse(run.call_args.args[-1].exists())


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.report = review_report()
        self.api = Mock(pull="/pulls/42", issue="/issues/42/comments")
        self.api.is_current.return_value = True
        self.comments = []
        self.inline = []
        self.filename = "app.py"
        self.diff_patch = "@@ -3,3 +3,3 @@\n context\n-previous\n+new\n context"
        self.reject_suggestions = False

        def pages(path):
            if path == self.api.issue:
                return iter(self.comments)
            if path.endswith("/files"):
                return iter([{"filename": self.filename, "patch": self.diff_patch}])
            return iter(self.inline)

        def request(method, path, payload, **kwargs):
            if path.endswith("/pulls/42/comments"):
                if self.reject_suggestions and "```suggestion\n" in payload["body"]:
                    return None
                self.inline.append({"id": 3, "user": {"login": action.BOT}, **payload})
                return self.inline[-1]
            elif method == "POST":
                self.comments.append({"id": 2, "user": {"login": action.BOT}, **payload})
            else:
                self.comments[-1].update(payload)

        self.api.pages.side_effect = pages
        self.api.request.side_effect = request

    def set_suggestion(self, **overrides):
        data = {
            "source_sha": self.report["head_sha"],
            "existing_code": "new\ncontext",
            "suggestion_code": "    updated\ncontext\n",
            "assessment": {"suggestion_supported": True},
        }
        self.report["findings"][0].update(data | overrides)

    def test_updates_only_bot_summary_and_deduplicates_inline(self):
        impostor = {"id": 1, "user": {"login": "human"}, "body": action.SUMMARY_MARKER}
        self.comments.append(impostor.copy())
        self.assertTrue(action.publish(self.api, self.report, "First summary"))
        self.assertTrue(action.publish(self.api, self.report, "Second summary"))
        self.assertEqual(len(self.comments), 2)
        self.assertEqual(self.comments[0], impostor)
        self.assertIn("Second summary", self.comments[1]["body"])
        self.assertIn("Summary-only defect", self.comments[1]["body"])
        self.assertEqual(len(self.inline), 1)
        self.assertEqual(self.inline[0]["line"], 4)
        self.assertEqual(self.inline[0]["commit_id"], self.report["head_sha"])

    def test_stale_review_skips_writes(self):
        self.api.is_current.side_effect = [True, False]
        self.assertFalse(action.publish(self.api, self.report, "Stale summary"))
        self.api.request.assert_not_called()

    def test_suggestion_replaces_the_exact_multiline_range(self):
        self.set_suggestion()
        self.assertTrue(action.publish(self.api, self.report, "Review summary"))
        self.assertTrue(action.publish(self.api, self.report, "Review summary"))
        self.assertEqual(len(self.inline), 1)
        comment = self.inline[0]
        self.assertIn("```suggestion\n    updated\ncontext\n```", comment["body"])
        self.assertEqual((comment["start_line"], comment["line"]), (4, 5))
        self.assertEqual((comment["start_side"], comment["side"]), ("RIGHT", "RIGHT"))
        self.assertEqual(comment["commit_id"], self.report["head_sha"])

    def test_single_line_suggestion_omits_range_start(self):
        self.set_suggestion(end_line=4, existing_code="new", suggestion_code="updated")
        self.assertTrue(action.publish(self.api, self.report, "Review summary"))
        comment = self.inline[0]
        self.assertIn("```suggestion\nupdated\n```", comment["body"])
        self.assertEqual(comment["line"], 4)
        self.assertNotIn("start_line", comment)
        self.assertNotIn("start_side", comment)

    def test_ineligible_suggestions_keep_the_plain_finding(self):
        for overrides in (
            {"existing_code": "ne\ncontext"},
            {"end_line": 6, "existing_code": "new\ncontext\nmissing"},
            {"assessment": {"suggestion_supported": False}},
            {"suggestion_code": "updated\n```\n@everyone"},
            {"suggestion_code": "x" * action.COMMENT_BODY_LIMIT},
        ):
            with self.subTest(fields=tuple(overrides)):
                self.inline.clear()
                self.set_suggestion(end_line=5)
                self.report["findings"][0].update(overrides)
                self.assertTrue(action.publish(self.api, self.report, "Review summary"))
                self.assertEqual(self.inline[0]["line"], 4)
                self.assertNotIn("```suggestion", self.inline[0]["body"])

    def test_suggestion_cannot_span_two_diff_hunks(self):
        self.diff_patch = "@@ -4 +4 @@\n-previous\n+new\n@@ -5 +5 @@\n-old context\n+context"
        self.set_suggestion()
        self.assertTrue(action.publish(self.api, self.report, "Review summary"))
        self.assertNotIn("```suggestion", self.inline[0]["body"])

    def test_rejected_suggestion_falls_back_to_plain_finding(self):
        self.set_suggestion()
        self.reject_suggestions = True
        self.assertTrue(action.publish(self.api, self.report, "Review summary"))
        suggested, fallback = self.api.request.call_args_list[-2:]
        self.assertIn("```suggestion", suggested.args[2]["body"])
        self.assertEqual(fallback.args[2]["line"], 4)
        self.assertNotIn("```suggestion", fallback.args[2]["body"])
        self.assertEqual(len(self.inline), 1)

    def test_summary_includes_overview_and_escapes_model_text(self):
        self.report["summary"] = {"result": {
            "narrative": "Adds a retry",
            "groups": [{"title": "Timeouts", "description": "Handles @everyone <b> safely", "paths": ["app.py"]}],
        }}
        self.assertTrue(action.publish(self.api, self.report, "Review summary"))
        body = self.comments[0]["body"]
        self.assertIn("Adds a retry", body)
        self.assertIn("**Timeouts**", body)
        self.assertIn("(app&#46;py)", body)
        self.assertIn("### Findings", body)
        self.assertNotIn("@everyone", body)
        self.assertNotIn("<b>", body)

    def test_unavailable_patch_or_anchor_stays_in_summary(self):
        self.filename = "renamed.py"
        self.assertTrue(action.publish(self.api, self.report, "Coverage summary"))
        self.assertIn("Inline defect", self.comments[0]["body"])
        self.assertEqual(self.inline, [])
