"""Grounded linked-issue assessments and cross-run reuse."""

import copy
import os
import unittest
from unittest.mock import Mock, patch

from mortis_action import linked_issues
from mortis_action.commands import DESCRIPTION_END, DESCRIPTION_START
from tests.helpers import pr_event


class LinkedIssueTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"GITHUB_SERVER_URL": "https://github.example",
                                                  "MORTIS_API_KEY": "secret-5678"}))
        self.api = Mock(owner="owner")
        self.api.name = "repo"
        self.pr = {**pr_event("a" * 40, "b" * 40)["pull_request"], "body": "Closes #1"}
        self.report = {"base_sha": "a" * 40, "head_sha": "b" * 40, "merge_base": "c" * 40}
        self.api.current.return_value = self.pr
        self.issue = {"number": 1, "title": "Notifications", "body": "Message requirements"}
        self.api.request.return_value = self.issue
        self.result = {"schema_version": "mortis.ask/v1", "status": "completed",
                       "base_sha": self.report["base_sha"], "head_sha": self.report["head_sha"],
                       "result": {"answer": "The diff handles this.", "citations": [
                           {"sha": self.report["merge_base"], "path": "src/some file.py",
                            "start_line": 3, "end_line": 4}]}}
        self.ask = Mock(return_value=self.result)

    def section(self, previous="", **settings):
        return linked_issues.section(self.api, self.pr, self.report, previous, settings, self.ask)

    def test_closing_refs_are_explicit_ordered_same_repo_and_author_written(self):
        self.pr["body"] = (
            "Closes #12, #3 and Owner/Repo#4. FIXED https://github.example/owner/repo/issues/5.\n"
            "Resolves any/repo#6. References #7. Closes #12. `Closes #10`.\n"
            "> Fixes #8\n```text\nCloses #9\n```\n<!-- Closes #11 -->\n"
            f"{DESCRIPTION_START}\nFixes #20\n{DESCRIPTION_END}\n"
            "Closes https://alt.example/owner/repo/issues/21\nClose #5abc. Resolve #6"
        )
        self.assertEqual(linked_issues.references(self.api, self.pr["body"]), [12, 3, 4, 5, 6])
        self.pr["body"] = "Refs #1"
        self.assertEqual(self.section(), "")
        self.api.request.assert_not_called()
        self.ask.assert_not_called()

    def test_limits_in_document_order_and_reports_omissions(self):
        self.pr["body"] = "Fixes #2, #1 and #3. Closes #4"
        issues = {
            2: {"number": 2, "title": "First", "body": (
                "- Design note\n- [ ] task one\n## Acceptance criteria\n"
                "- bullet two\n    continued\n1. bullet three\n### Details\n* bullet four\n"
                "## Notes\n- Not a requirement")},
            1: self.issue,
            3: {"number": 3, "title": "Last", "body": "- [x] six\n- [ ] seven"},
        }
        self.api.request.side_effect = lambda method, path, **kw: issues[int(path.split("/")[-1])]
        text = self.section()
        questions = [c.args[0] for c in self.ask.call_args_list]
        self.assertEqual(len(questions), 6)
        for question, expected in zip(questions, ["task one", "bullet two continued", "bullet three",
                                                   "bullet four", "Message requirements", "six"], strict=True):
            self.assertIn(expected, question)
        self.assertIn("Issue-level assessment", text)
        self.assertIn("1 additional linked issue(s) omitted", text)
        self.assertIn("1 additional requirement(s) omitted", text)
        self.assertEqual([c.args[1] for c in self.api.request.call_args_list],
                         ["/issues/2", "/issues/1", "/issues/3"])

    def test_prose_fallback_uses_visible_issue_text(self):
        self.issue["body"] = "Reject expired sessions.\n<!--" + "hidden note " * 900 + "-->"
        self.section()
        question = self.ask.call_args.args[0]
        self.assertIn("Reject expired sessions.", question)
        self.assertNotIn("hidden note", question)

    def test_reuses_matching_results_but_retries_unavailable(self):
        self.issue["body"] = "- [ ] First criterion\n- [x] Second"
        self.ask.side_effect = [self.result, OSError("unavailable")]
        first = self.section(model="a")
        self.assertIn("Unavailable", first)
        self.ask.reset_mock(side_effect=True)
        text = self.section(first, model="a")
        self.assertEqual(self.ask.call_count, 1)
        self.assertIn("Second", self.ask.call_args.args[0])
        self.assertNotIn("Unavailable", text)
        self.ask.reset_mock()
        self.assertEqual(self.section(text, model="a"), text)
        self.ask.assert_not_called()
        self.section(text, model="b")
        self.assertEqual(self.ask.call_count, 2)
        self.ask.reset_mock()
        self.issue["title"] = "Edited title"
        self.section(text, model="a")
        self.assertEqual(self.ask.call_count, 2)

    def test_accepts_only_pinned_answers_and_validated_citations(self):
        self.assertIn("/blob/" + "c" * 40 + "/src/some%20file.py#L3-L4", self.section())
        for edit in ({"head_sha": "d" * 40}, {"schema_version": "wrong"},
                     {"result": {"answer": "Present", "citations": [
                         {**self.result["result"]["citations"][0], "path": "../x"}]}},
                     {"result": {"answer": "Present", "citations": [
                         {**self.result["result"]["citations"][0], "sha": "f" * 40}]}}):
            with self.subTest(edit=edit):
                self.ask.return_value = {**self.result, **edit}
                self.assertIn("Unavailable", self.section())
        self.ask.return_value = {**self.result, "status": "insufficient_context"}
        self.assertIn("Unverified", self.section())
        self.ask.return_value = {**self.result, "result": {"answer": "Present", "citations": []}}
        self.assertIn("Unverified", self.section())

    def test_stale_revisions_and_changed_closing_refs_drop_results(self):
        self.pr["head"]["sha"] = "f" * 40
        self.assertEqual(self.section(), "")
        self.ask.assert_not_called()
        self.pr["head"]["sha"] = self.report["head_sha"]
        self.api.current.return_value = {**self.pr, "body": "Closes #2"}
        self.assertEqual(self.section(), "")
        self.api.current.return_value = None
        self.assertEqual(self.section(), "")

    def test_missing_issues_prs_and_failed_reads_stay_unavailable(self):
        for issue in (None, {**self.issue, "pull_request": {}}, {**self.issue, "number": 15}):
            self.api.request.return_value = issue
            self.assertIn("Unavailable", self.section())
        self.api.request.side_effect = ValueError("403")
        self.assertIn("Unavailable", self.section())
        self.ask.assert_not_called()

    def test_long_requirements_are_never_silently_truncated(self):
        self.issue["body"] = "- [ ] " + "x" * 9000 + " and reject duplicate requests"
        self.assertIn("exceeds the Engine question limit", self.section())
        self.ask.assert_not_called()

    def test_cached_answer_is_redacted_if_credentials_changed(self):
        self.result["result"]["answer"] = "A~rotated#credential"
        first = self.section()
        with patch.dict(os.environ, {"MORTIS_API_KEY": "A~rotated#credential"}):
            self.ask.reset_mock()
            updated = self.section(first)
        self.ask.assert_called_once()
        self.assertNotIn("rotated", updated)

    def test_escapes_text_redacts_secrets_and_bounds_markdown_and_cache(self):
        self.pr["body"] = "Closes #1, #2 and #3"
        issue = {**self.issue, "title": "secret-5678 @team", "body": (
            "- [ ] secret-5678 @team <html> " + "⛵" * 4000 + "\n- [ ] another " + "界" * 4000)}
        self.api.request.side_effect = lambda method, path, **kw: {**issue, "number": int(path.split("/")[-1])}
        report = copy.deepcopy(self.result)
        report["result"]["answer"] = "secret-5678 <script>@all " + "界" * 3000
        self.ask.return_value = report
        text = self.section()
        self.assertLessEqual(len(text.encode()), 12_000)
        self.assertEqual(len(linked_issues.CACHE.findall(text)), 6)
        self.assertNotIn("secret-5678", text + "".join(c.args[0] for c in self.ask.call_args_list))
        self.assertNotIn("<script>", text)
        self.assertNotIn("@team", text)
        self.ask.reset_mock()
        self.section(text.replace("another", "tampered"))
        self.assertEqual(self.ask.call_count, 3)
