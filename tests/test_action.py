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
        "sender": {"login": login},
        "pull_request": {
            "number": 42,
            "draft": draft,
            "user": {"login": login, "type": author_type},
            "base": {"sha": base, "repo": {"full_name": "owner/repo"}},
            "head": {"sha": head, "repo": {"full_name": "user/fork" if fork else "owner/repo"}},
        },
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

    def engine(self, *args):
        return subprocess.run(
            [
                sys.executable,
                "-c",
                "from mortis_engine.cli import main; raise SystemExit(main())",
                *args,
                "--repo",
                self.repo,
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
                    "GITHUB_RUN_ID": "123",
                },
            )
        )

    def test_skips_ineligible_prs_without_resolving_revisions(self):
        for details in ({"draft": True}, {"fork": True}, {"login": "dependabot[bot]"}):
            with self.subTest(details=details):
                args, _ = action.select_run("review", "pull_request", pr_event(**details), "")
                self.assertIsNone(args)
        with self.assertRaisesRegex(ValueError, "Use pull_request"):
            action.select_run("review", "pull_request_target", pr_event(), "")

    def run_mock(self, command, settings, pr=None, *, invalid=False):
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
        ):
            result = action.run_engine([command], ".", "base", pr, self.reports, self.directory)
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
        with (
            patch.dict(os.environ, environment),
            patch.object(action, "select_run", return_value=(["scan", "--ref", "base"], "base")),
            patch.object(action, "run_engine", return_value=(2, "partial", "## Mortis security scan")) as run,
            patch("builtins.print"),
        ):
            action.main()
        self.assertIn("status=partial\nexit-code=2\n", self.outputs.read_text())
        self.assertIn("Mortis security scan", Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text())
        self.assertTrue(run.call_args.args[-2].is_dir())
        self.assertFalse(run.call_args.args[-1].exists())


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.report = review_report()
        self.api = Mock(pull="/pulls/42", issue="/issues/42/comments")
        self.api.is_current.return_value = True
        self.comments = []
        self.inline = []
        self.filename = "app.py"

        def pages(path):
            if path == self.api.issue:
                return iter(self.comments)
            if path.endswith("/files"):
                patch = "@@ -3,3 +3,3 @@\n context\n-previous\n+new\n context"
                return iter([{"filename": self.filename, "patch": patch}])
            return iter(self.inline)

        def request(method, path, payload, **kwargs):
            if path.endswith("/pulls/42/comments"):
                self.inline.append({"id": 3, "user": {"login": action.BOT}, **payload})
            elif method == "POST":
                self.comments.append({"id": 2, "user": {"login": action.BOT}, **payload})
            else:
                self.comments[-1].update(payload)

        self.api.pages.side_effect = pages
        self.api.request.side_effect = request

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

    def test_unavailable_patch_or_anchor_stays_in_summary(self):
        self.filename = "renamed.py"
        self.assertTrue(action.publish(self.api, self.report, "Coverage summary"))
        self.assertIn("Inline defect", self.comments[0]["body"])
        self.assertEqual(self.inline, [])
