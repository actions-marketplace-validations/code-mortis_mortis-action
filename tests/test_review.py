"""Check review summaries, inline findings, suggestions and thread resolution."""

import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from mortis_action import github, review
from tests.helpers import review_report


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
                self.inline.append({"id": 3, "user": {"login": github.BOT}, **payload})
                return self.inline[-1]
            elif method == "POST":
                self.comments.append({"id": 2, "user": {"login": github.BOT}, **payload})
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
        impostor = {"id": 1, "user": {"login": "human"}, "body": review.SUMMARY_MARKER}
        self.comments.append(impostor.copy())
        self.assertTrue(review.publish(self.api, self.report, "First summary"))
        self.assertTrue(review.publish(self.api, self.report, "Second summary"))
        self.assertEqual(len(self.comments), 2)
        self.assertEqual(self.comments[0], impostor)
        self.assertIn("Second summary", self.comments[1]["body"])
        self.assertIn("Summary-only defect", self.comments[1]["body"])
        self.assertEqual(len(self.inline), 1)
        self.assertEqual(self.inline[0]["line"], 4)
        self.assertEqual(self.inline[0]["commit_id"], self.report["head_sha"])

    def test_stale_review_skips_writes(self):
        self.api.is_current.side_effect = [True, False]
        self.assertFalse(review.publish(self.api, self.report, "Stale summary"))
        self.api.request.assert_not_called()

    def test_open_threads_are_loaded_from_bot_comments_across_pages(self):
        finding = {**self.report["findings"][0], "id": "finding-" + "1" * 32}
        body = "<!-- mortis-action:finding:existing -->\n" + github.finding_metadata(finding, "a" * 40) + "Finding"
        bot = {"login": "github-actions", "__typename": "Bot"}

        def thread(thread_id, *, resolved=False, author=bot, comment=body):
            return {"id": thread_id, "isResolved": resolved,
                    "comments": {"nodes": [{"body": comment, "author": author}]}}

        def page(nodes, cursor=None):
            return {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": nodes, "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
            }}}}

        with patch.dict(os.environ, {"GITHUB_API_URL": "https://api.github.com"}):
            api = github.GitHubAPI("owner/repo", 42)
        with patch.object(api, "graphql", side_effect=[
            page([thread("human", author={**bot, "__typename": "User"}), thread("closed", resolved=True)], "cursor"),
            page([thread("open"), thread("legacy", comment="<!-- mortis-action:finding:legacy -->\nFinding")]),
        ]) as graphql:
            self.assertEqual(api.finding_threads(), {"open": {**finding, "source_sha": "a" * 40}})
            self.assertEqual(graphql.call_args.args[1]["after"], "cursor")

    def test_resolves_only_the_verified_thread_and_keeps_existing_open_findings_inline(self):
        origin = "c" * 40
        fixed = "finding-" + "1" * 32
        open_id = "finding-" + "2" * 32
        threads = {"fixed-thread": {"id": fixed, "source_sha": origin},
                   "open-thread": {"id": open_id, "source_sha": origin}}
        verification = {"status": "completed", "verdict": "fixed", "original_sha": origin,
                        "head_sha": self.report["head_sha"]}
        self.report["findings"][0]["id"] = open_id
        self.report["history"] = [
            {"id": fixed, "status": "resolved", "verification": verification},
            {"id": open_id, "status": "open", "verification": {**verification, "verdict": "still_present"}},
        ]

        self.assertTrue(review.publish(self.api, self.report, "Partial", threads=threads))
        self.api.resolve_thread.assert_not_called()
        self.report.update(status="completed", workflow_status="completed")
        self.api.is_current.side_effect = [True, True, False]
        self.assertFalse(review.publish(self.api, self.report, "Stale", threads=threads))
        self.api.resolve_thread.assert_not_called()
        self.api.is_current.side_effect = None
        self.assertTrue(review.publish(self.api, self.report, "Completed", threads=threads))
        self.api.resolve_thread.assert_called_once_with("fixed-thread")
        self.assertEqual(self.inline, [])
        self.api.resolve_thread.reset_mock()
        self.report.update(status="skipped", workflow_status="partial", findings=[],
                           coverage={"selected": [], "waived": []})
        self.assertTrue(review.publish(self.api, self.report, "Incomplete verification", threads=threads))
        self.api.resolve_thread.assert_not_called()
        self.report["workflow_status"] = "completed"
        self.assertTrue(review.publish(self.api, self.report, "Verified without a diff", threads=threads))
        self.api.resolve_thread.assert_called_once_with("fixed-thread")

    def test_suggestion_replaces_the_exact_multiline_range(self):
        self.set_suggestion()
        self.assertTrue(review.publish(self.api, self.report, "Review summary"))
        self.assertTrue(review.publish(self.api, self.report, "Review summary"))
        self.assertEqual(len(self.inline), 1)
        comment = self.inline[0]
        self.assertIn("```suggestion\n    updated\ncontext\n```", comment["body"])
        self.assertEqual((comment["start_line"], comment["line"]), (4, 5))
        self.assertEqual((comment["start_side"], comment["side"]), ("RIGHT", "RIGHT"))
        self.assertEqual(comment["commit_id"], self.report["head_sha"])

    def test_single_line_suggestion_omits_range_start(self):
        self.set_suggestion(end_line=4, existing_code="new", suggestion_code="updated")
        self.assertTrue(review.publish(self.api, self.report, "Review summary"))
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
            {"suggestion_code": "x" * github.COMMENT_BODY_LIMIT},
        ):
            with self.subTest(fields=tuple(overrides)):
                self.inline.clear()
                self.set_suggestion(end_line=5)
                self.report["findings"][0].update(overrides)
                self.assertTrue(review.publish(self.api, self.report, "Review summary"))
                self.assertEqual(self.inline[0]["line"], 4)
                self.assertNotIn("```suggestion", self.inline[0]["body"])

    def test_suggestion_cannot_span_two_diff_hunks(self):
        self.diff_patch = "@@ -4 +4 @@\n-previous\n+new\n@@ -5 +5 @@\n-old context\n+context"
        self.set_suggestion()
        self.assertTrue(review.publish(self.api, self.report, "Review summary"))
        self.assertNotIn("```suggestion", self.inline[0]["body"])

    def test_only_valid_workflow_suggestions_are_published(self):
        self.filename = ".github/workflows/review.yml"
        self.diff_patch = "@@ -1,5 +1,7 @@\n on: push\n \n jobs:\n+  review:\n+    runs-on: ubuntu-latest\n     steps:\n       - run: echo review"
        source = b"on: push\n\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo review\n"
        self.assertEqual(self.report["findings"][0]["start_line"], 4)
        for replacement, offer in (
            ("jobs:\n  review:\n    runs-on: ubuntu-latest", False),
            ("  review:\n    runs-on: [ubuntu-latest", False),
            ("  review:\n    runs-on: ubuntu-latest\n    runs-on: ubuntu-24.04", False),
            ("  review:\n    runs-on: ubuntu-24.04", True),
        ):
            with self.subTest(replacement=replacement):
                self.inline.clear()
                self.set_suggestion(
                    path=self.filename,
                    existing_code="  review:\n    runs-on: ubuntu-latest",
                    suggestion_code=replacement,
                )
                with patch.object(subprocess, "check_output", return_value=source) as read:
                    self.assertTrue(review.publish(
                        self.api, self.report, "Review summary", repo="test-repo", workflow_python=sys.executable,
                    ))
                read.assert_called_once()
                self.assertIn(f"{self.report['head_sha']}:{self.filename}", read.call_args.args[0])
                self.assertEqual(len(self.inline), 1)
                self.assertEqual("```suggestion" in self.inline[0]["body"], offer)

    def test_rejected_suggestion_falls_back_to_plain_finding(self):
        self.set_suggestion()
        self.reject_suggestions = True
        self.assertTrue(review.publish(self.api, self.report, "Review summary"))
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
        self.assertTrue(review.publish(self.api, self.report, "Review summary"))
        body = self.comments[0]["body"]
        self.assertIn("Adds a retry", body)
        self.assertIn("**Timeouts**", body)
        self.assertIn("(app&#46;py)", body)
        self.assertIn("### Findings", body)
        self.assertNotIn("@everyone", body)
        self.assertNotIn("<b>", body)

    def test_unavailable_patch_or_anchor_stays_in_summary(self):
        self.filename = "renamed.py"
        self.assertTrue(review.publish(self.api, self.report, "Coverage summary"))
        self.assertIn("Inline defect", self.comments[0]["body"])
        self.assertEqual(self.inline, [])
