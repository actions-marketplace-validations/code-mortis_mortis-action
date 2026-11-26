"""Verify head-bound feedback and the composite's final exit status."""

import json
import os
from unittest.mock import Mock, patch

import run_mortis
from mortis_action import checks, github
from tests.helpers import ActionTestCase, pr_event


class CheckTests(ActionTestCase):
    def setUp(self):
        super().setUp()
        self.base, self.head = "a" * 40, "b" * 40
        self.revisions = {"base_sha": self.base, "head_sha": self.head}
        self.report = {
            **self.revisions, "schema_version": "mortis.review/v1", "status": "completed", "workflow_status": "completed",
            "coverage": {"selected": ["app.py"], "completed": ["app.py"]},
            "findings": [{"id": "1", "severity": "low"}],
            "history": [{"id": "1", "status": "open", "snapshot": {"severity": "high"}},
                        {"id": "2", "status": "open", "snapshot": {"severity": "high"}},
                        {"id": "3", "status": "resolved", "snapshot": {"severity": "critical"}}],
        }
        self.path = self.reports / "report.json"
        self.api = Mock(number=42, issue="/issues/42/comments")
        self.api.is_current.return_value = True
        self.api.pages.return_value = []
        self.enterContext(patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "review"}))

    def finish(self, **options):
        self.path.write_text(json.dumps(self.report))
        args = {"check_id": "4", "threshold": "high", "status": self.report["status"], "report_path": self.path,
                "superseded": False, "upload_failed": False, "cancelled": False, "warn": Mock(), **options}
        return checks.finish(self.api, self.revisions, **args)

    def test_check_starts_on_pr_head_and_recovers_a_lost_response(self):
        self.api.request.side_effect = [
            TimeoutError(),
            {"check_runs": [{"id": 7, "app": {"slug": "github-actions"}, "external_id": "123:2:review:42"}]},
        ]
        with patch.dict(os.environ, {"MORTIS_FAIL_ON_SEVERITY": "high"}), patch.object(github, "GitHubAPI", return_value=self.api):
            run_mortis.begin_review_feedback(pr_event(self.base, self.head)["pull_request"])
        request = self.api.request.call_args_list[0]
        self.assertEqual(request.args[:2], ("POST", "/check-runs"))
        self.assertEqual((request.args[2]["head_sha"], request.args[2]["status"]), (self.head, "in_progress"))
        self.assertIn("check-id=7", self.outputs.read_text())

    def test_open_counts_and_unchanged_policy_use_carried_history(self):
        self.assertEqual(checks.report_counts(self.report), {"critical": 0, "high": 1, "medium": 0, "low": 1})
        self.report.update(status="skipped", findings=[], comparison={"strategy": "skipped_unchanged"})
        self.report["coverage"].update(reused=["app.py"], completed=[])
        policy, code, summary = self.finish()
        self.assertEqual((policy, code), ("blocked", 1))
        self.assertIn("2 high", summary)
        self.assertIn("1/1 selected", summary)
        self.assertEqual(self.api.request.call_args.args[2]["conclusion"], "failure")
        self.assertEqual(self.finish(threshold="critical")[:2], ("passed", 0))
        self.assertEqual(self.finish(threshold="none")[:2], ("advisory", 0))

    def test_skips_wrong_revisions_partial_and_unreadable_checks_cannot_pass_policy(self):
        self.assertEqual(self.finish(status="skipped", report_path="")[:2], ("unevaluated", 1))
        self.assertEqual(self.finish(status="partial")[:2], ("unevaluated", 1))
        self.assertEqual(self.finish(upload_failed=True)[:2], ("unevaluated", 1))
        self.assertEqual(self.finish(check_id=None)[:2], ("unevaluated", 1))
        self.report["head_sha"] = self.base
        self.assertEqual(self.finish()[:2], ("unevaluated", 1))
        self.api.request.side_effect = github.GitHubForbidden("denied")
        self.assertEqual(self.finish()[:2], ("unevaluated", 1))

    def test_superseded_check_only_finishes_on_its_original_id(self):
        self.api.is_current.return_value = False
        self.assertEqual(self.finish()[:2], ("unevaluated", 0))
        method, path, body = self.api.request.call_args.args
        self.assertEqual((method, path, body["conclusion"]), ("PATCH", "/check-runs/4", "cancelled"))
        self.api.pages.assert_not_called()

    def test_malformed_report_finishes_the_check_and_failed_patch_posts_a_notice(self):
        self.report["findings"] = ["bad row"]
        self.assertEqual(self.finish()[:2], ("unevaluated", 1))
        self.assertEqual(self.api.request.call_args.args[2]["conclusion"], "failure")
        self.api.request.reset_mock()
        self.api.request.side_effect = [github.GitHubRequestError("PATCH", 422), {"id": 7}]
        self.assertEqual(self.finish()[:2], ("unevaluated", 1))
        self.assertEqual([call.args[:2] for call in self.api.request.call_args_list],
                         [("PATCH", "/check-runs/4"), ("POST", self.api.issue)])

    def test_full_empty_scope_can_pass_and_limits_cannot(self):
        self.report.update(status="skipped", history=[], findings=[], coverage={"selected": [], "completed": []})
        self.assertEqual(self.finish()[:2], ("passed", 0))
        self.report["warnings"] = [{"type": "review_limit_reached"}]
        self.assertEqual(self.finish()[:2], ("unevaluated", 1))

    def test_retry_updates_one_bot_notice_and_success_removes_it(self):
        self.api.pages.return_value = [{"id": 1, "user": {"login": "contributor"}, "body": checks.NOTICE + "\nhi"}]
        self.finish(status="failed", report_path="", threshold="none", check_id=None)
        method, path, notice = self.api.request.call_args.args
        self.assertEqual((method, path), ("POST", self.api.issue))
        self.assertIn(self.head[:12], notice["body"])
        self.api.pages.return_value.append({"id": 2, "user": {"login": github.BOT}, **notice})
        self.api.request.reset_mock()
        self.finish(status="failed", report_path="", threshold="none", check_id=None)
        self.api.request.assert_not_called()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "next"}):
            self.finish(status="failed", report_path="", threshold="none", check_id=None)
        self.assertEqual(self.api.request.call_args.args[:2], ("PATCH", "/issues/comments/2"))
        self.finish(threshold="none", check_id=None)
        self.api.request.assert_called_with("DELETE", "/issues/comments/2", allow_missing=True)

    def test_composite_finalizer_preserves_partial_exit_and_marks_failed_upload(self):
        self.path.write_text(json.dumps(self.report))
        env = {"MORTIS_EXIT_CODE": "2", "MORTIS_FAIL_ON_SEVERITY": "critical", "MORTIS_PR_NUMBER": "42",
               "MORTIS_PR_BASE": self.base, "MORTIS_PR_HEAD": self.head, "MORTIS_CHECK_ID": "4",
               "MORTIS_RUN_STATUS": "partial", "MORTIS_REPORT_JSON": str(self.path), "MORTIS_UPLOAD_FAILED": "true"}
        with patch.dict(os.environ, env), patch.object(github, "GitHubAPI", return_value=self.api), patch("builtins.print"):
            self.assertEqual(run_mortis.finish_action(), 2)
        self.assertIn("policy-result=unevaluated", self.outputs.read_text())
        self.assertEqual(self.api.request.call_args.args[2]["conclusion"], "failure")
