"""Check review summaries, inline findings, suggestions and thread resolution."""

import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from mortis_action import github, markdown, review
from tests.helpers import review_report


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.report = review_report()
        self.api = Mock(pull="/pulls/42", issue="/issues/42/comments")
        self.api.is_current.return_value = True
        self.api.finding_threads.return_value = {}
        self.api.trusted_summary_body.side_effect = lambda row: row["body"]
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
                return self.comments[-1]
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

        def thread(thread_id, *, resolved=False, author=bot, editor=None, comment=body, **location):
            return {"id": thread_id, "isResolved": resolved, **location,
                    "comments": {"nodes": [{"body": comment, "author": author, "editor": editor}]}}

        def page(nodes, cursor=None):
            return {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": nodes, "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
            }}}}

        with patch.dict(os.environ, {"GITHUB_API_URL": "https://api.github.com"}):
            api = github.GitHubAPI("owner/repo", 42)
        location = {"diffSide": "RIGHT", "path": "moved.py", "startLine": 6, "line": 8, "isOutdated": False}
        human = {**bot, "__typename": "User"}
        with patch.object(api, "graphql", side_effect=[
            page([thread("human", author=human), thread("edited", editor=human), thread("closed", resolved=True)], "cursor"),
            page([thread("open", **location), thread("old", **(location | {"isOutdated": True})),
                  thread("legacy", comment="<!-- mortis-action:finding:legacy -->\nFinding")]),
        ]) as graphql:
            previous = {**finding, "source_sha": "a" * 40, "evidence_digest": github.evidence_digest(finding["content"])}
            self.assertEqual(api.finding_threads(), {
                "open": {**previous, "github_anchor": ("moved.py", 6, 8)}, "old": previous,
            })
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

        self.assertTrue(review.publish(self.api, self.report, "Partial", threads=threads, auto_resolve=True))
        self.api.resolve_thread.assert_not_called()
        self.report.update(status="completed", workflow_status="completed")
        self.api.is_current.side_effect = [True, True, False]
        self.assertFalse(review.publish(self.api, self.report, "Stale", threads=threads, auto_resolve=True))
        self.api.resolve_thread.assert_not_called()
        self.api.is_current.side_effect = None
        self.assertTrue(review.publish(self.api, self.report, "Completed", threads=threads, auto_resolve=True))
        self.api.resolve_thread.assert_called_once_with("fixed-thread")
        self.assertEqual(self.inline, [])
        self.api.resolve_thread.reset_mock()
        self.report.update(status="skipped", workflow_status="partial", findings=[],
                           coverage={"selected": [], "waived": []})
        self.assertTrue(review.publish(self.api, self.report, "Incomplete verification", threads=threads, auto_resolve=True))
        self.api.resolve_thread.assert_not_called()
        self.report["workflow_status"] = "completed"
        self.assertTrue(review.publish(self.api, self.report, "Verified without a diff", threads=threads, auto_resolve=True))
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
        suggested, fallback = [call for call in self.api.request.call_args_list if call.args[1] == "/pulls/42/comments"]
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

    def test_incremental_summary_lists_files_and_keeps_earlier_open_findings(self):
        self.report.update(status="completed", comparison={"strategy": "incremental"}, coverage={
            "completed": [{"path": "app.py"}], "reused": [{"path": "@user<old>.py"}],
            "selected": [{"path": "app.py"}, {"path": "@user<old>.py"}],
        })
        current = {**self.report["findings"][0], "id": "finding-" + "1" * 32}
        prior = {**self.report["findings"][1], "id": "finding-" + "2" * 32}
        self.report["findings"] = [current]
        self.report["history"] = [
            {"id": current["id"], "status": "open", "snapshot": current},
            {"id": prior["id"], "status": "open", "snapshot": prior},
            {"id": "finding-" + "3" * 32, "status": "resolved",
             "snapshot": {**prior, "content": "Resolved defect"}},
        ]
        heading = markdown.summary(self.report, "completed", "https://github.com/owner/repo/actions/runs/123")
        self.assertIn("2/2 files covered", heading)
        self.assertIn("Files reviewed (1)", heading)
        self.assertIn("Files reused (1)", heading)
        self.assertIn("&#64;user&#60;old&#62;&#46;py", heading)
        self.assertTrue(review.publish(self.api, self.report, heading))
        body = self.comments[0]["body"]
        self.assertEqual(body.count("Inline defect"), 1)
        self.assertIn("### Earlier open findings", body)
        self.assertIn("Summary-only defect", body)
        self.assertNotIn("Resolved defect", body)
        self.assertEqual(len(self.inline), 1)

    def test_inline_delivery_counts_rejected_and_summary_only(self):
        self.set_suggestion()
        normal = self.api.request.side_effect

        def reject(method, path, payload, **kwargs):
            if path == "/pulls/42/comments":
                return None
            return normal(method, path, payload, **kwargs)

        self.api.request.side_effect = reject
        delivery = review.publish(self.api, self.report, "Review")
        self.assertEqual(delivery.counts, {"inline-posted": 0, "inline-existing": 0, "summary-only": 1, "inline-failed": 1})
        self.assertTrue(delivery.warnings)
        self.assertIn(delivery.summary, self.comments[0]["body"])
        self.assertIn("### Findings with failed inline delivery", self.comments[0]["body"])
        self.assertIn("Inline defect", self.comments[0]["body"])
        self.assertEqual(self.inline, [])

    def test_inline_head_read_timeout_keeps_finding_in_summary(self):
        self.api.is_current.side_effect = [True, TimeoutError(), True]
        delivery = review.publish(self.api, self.report, "Review")
        self.assertEqual(delivery.counts["inline-failed"], 1)
        self.assertEqual(self.inline, [])
        self.assertIn("### Findings with failed inline delivery", self.comments[0]["body"])
        self.assertIn("Inline defect", self.comments[0]["body"])

    def test_thread_read_failure_keeps_confirmed_markers_and_withholds_other_posts(self):
        review.publish(self.api, self.report, "First")
        self.api.finding_threads.side_effect = TimeoutError()
        self.report["findings"].append({**self.report["findings"][0], "content": "Another inline defect"})
        delivery = review.publish(self.api, self.report, "Second")
        self.assertEqual(delivery.counts, {"inline-posted": 0, "inline-existing": 1, "summary-only": 1, "inline-failed": 1})
        self.assertEqual(len(self.inline), 1)
        self.assertIn("Another inline defect", self.comments[0]["body"])

    def test_ambiguous_inline_success_reconciled_without_duplicate_plain_comment(self):
        self.set_suggestion()
        normal = self.api.request.side_effect

        def lost_ack(method, path, payload, **kwargs):
            result = normal(method, path, payload, **kwargs)
            if path == "/pulls/42/comments":
                raise ConnectionResetError()
            return result

        self.api.request.side_effect = lost_ack
        delivery = review.publish(self.api, self.report, "Review")
        self.assertEqual(delivery.counts["inline-posted"], 1)
        self.assertEqual(len(self.inline), 1)
        self.assertIn("```suggestion", self.inline[0]["body"])

    def test_retry_after_absent_marker_rechecks_head(self):
        normal = self.api.request.side_effect
        writes = []

        def lost_write(method, path, payload, **kwargs):
            if path == "/pulls/42/comments":
                writes.append(payload)
                if len(writes) == 1:
                    raise github.GitHubRequestError("POST", 502)
            return normal(method, path, payload, **kwargs)

        self.api.request.side_effect = lost_write
        self.api.is_current.side_effect = [True, True, False]
        self.assertIsNone(review.publish(self.api, self.report, "Review"))
        self.assertEqual(len(writes), 1)
        self.assertEqual(self.inline, [])

    def test_cross_head_publication_matches_open_identity_or_current_anchor_and_evidence(self):
        finding = self.report["findings"][0]
        finding["id"] = "finding-" + "1" * 32
        first = review.publish(self.api, self.report, "First")
        self.assertEqual(first.counts["inline-posted"], 1)
        old = {**finding, "github_anchor": ("app.py", 6, 6)}
        self.report["head_sha"] = "d" * 40
        finding.update(start_line=6, end_line=6)
        self.diff_patch = "@@ -5,1 +5,2 @@\n context\n+new"
        self.api.finding_threads.return_value = {"open": old}
        self.assertEqual(review.publish(self.api, self.report, "Matched ID").counts["inline-existing"], 1)
        finding["id"] = "finding-" + "2" * 32
        self.assertEqual(review.publish(self.api, self.report, "Mapped location").counts["inline-existing"], 1)
        finding["content"] = "Another issue"
        self.assertEqual(review.publish(self.api, self.report, "Distinct defect").counts["inline-posted"], 1)
        self.report["head_sha"] = "e" * 40
        self.api.finding_threads.return_value = {}  # The old threads are resolved.
        self.assertEqual(review.publish(self.api, self.report, "Reintroduced").counts["inline-posted"], 1)

    def test_unreadable_reconciliation_never_reposts(self):
        pages = self.api.pages.side_effect
        reads = 0

        def read(path):
            nonlocal reads
            if path == "/pulls/42/comments":
                reads += 1
                if reads > 1:
                    raise TimeoutError()
            return pages(path)

        self.api.pages.side_effect = read
        normal = self.api.request.side_effect

        def lost_ack(method, path, payload, **kwargs):
            if path == "/pulls/42/comments":
                raise ConnectionResetError()
            return normal(method, path, payload, **kwargs)

        self.api.request.side_effect = lost_ack
        delivery = review.publish(self.api, self.report, "Uncertain")
        self.assertEqual(delivery.counts["inline-failed"], 1)
        self.assertEqual(1, sum(call.args[1] == "/pulls/42/comments" for call in self.api.request.call_args_list))

    def test_unchanged_overview_survives_multiple_heads_and_legacy_summary(self):
        first = self.report["head_sha"]
        legacy = (f"{review.SUMMARY_MARKER}\n## Mortis review\n\n**Completed** · Commit {first[:12]} · 2/2 files covered"
                  " · [Workflow run](https://example.org/job)\n\n<details>Old coverage</details>"
                  "\n\nChanged the retry policy.\n\n### Changes\n\n- **Retries** — Bounds retries."
                  "\n\n### Findings\n\n- Old defect from the last review.")
        self.comments.append({"id": 2, "user": {"login": github.BOT}, "body": legacy})
        for head in ("d" * 40, "e" * 40):
            self.report.update(head_sha=head, comparison={"strategy": "skipped_unchanged", "baseline_head_sha": first},
                               findings=[], summary={"status": "skipped"}, history=[])
            callback = Mock(return_value="\n\n### Linked issues\n\nChecked.")
            delivery = review.publish(self.api, self.report, f"Review of {head[:12]} with reused coverage", issue_section=callback)
            callback.assert_called_once()
            self.assertTrue(all(count == 0 for count in delivery.counts.values()))
            body = self.comments[0]["body"]
            self.assertIn("Changed the retry policy.", body)
            self.assertIn("**Retries** — Bounds retries.", body)
            self.assertIn(head[:12], body)
            self.assertNotIn("Old coverage", body)
            self.assertNotIn("Old defect", body)
            self.assertEqual(body.count("### Linked issues"), 1)
            first = head

    def test_unchanged_overview_survives_transient_provenance_read_failures(self):
        self.report.update(findings=[], summary={"result": {"narrative": "Keep the previous overview."}})
        review.publish(self.api, self.report, "Original review")
        comment = self.comments[0]
        comment["node_id"] = "I1"
        original = comment["body"]
        self.report.update(comparison={"strategy": "skipped_unchanged"}, summary={"status": "skipped"})
        with patch.dict(os.environ, {"GITHUB_API_URL": "https://api.github.com"}):
            api = github.GitHubAPI("owner/repo", 42)
        self.api.trusted_summary_body.side_effect = api.trusted_summary_body
        node = {"author": {"login": "github-actions", "__typename": "Bot"}, "editor": None,
                "lastEditedAt": None, "body": original}
        self.api.request.reset_mock()
        with patch.object(api, "graphql", side_effect=[TimeoutError(), TimeoutError(), TimeoutError(), {"node": node}]):
            with self.assertRaisesRegex(ValueError, "previous review overview"):
                review.publish(self.api, self.report, "Skipped review")
            self.api.request.assert_not_called()
            self.assertEqual(comment["body"], original)
            review.publish(self.api, self.report, "Recovered review")
        self.assertIn("Recovered review", comment["body"])
        self.assertIn("Keep the previous overview", comment["body"])

        self.report.update(comparison={}, summary={"result": {"narrative": "Fresh overview"}})
        section = Mock(return_value="")
        with patch.object(api, "graphql", side_effect=TimeoutError()):
            review.publish(self.api, self.report, "New review", issue_section=section)
        section.assert_called_once_with("")
        self.assertIn("Fresh overview", comment["body"])

    def test_previous_summary_requires_bot_editor_provenance(self):
        with patch.dict(os.environ, {"GITHUB_API_URL": "https://api.github.com"}):
            api = github.GitHubAPI("owner/repo", 42)
        bot = {"__typename": "Bot", "login": "github-actions"}
        node = {"body": "Summary from the same response", "author": bot, "editor": None, "lastEditedAt": None}
        for changes, expected in [
            ({}, node["body"]), ({"editor": bot, "lastEditedAt": "yesterday"}, node["body"]),
            ({"editor": {"__typename": "User", "login": "writer"}, "lastEditedAt": "today"}, ""),
            ({"editor": None, "lastEditedAt": "today"}, ""),
        ]:
            with self.subTest(changes=changes), patch.object(api, "graphql", return_value={"node": node | changes}):
                self.assertEqual(api.trusted_summary_body({"node_id": "I1", "body": "stale"}), expected)
        self.report["findings"] = []
        self.comments.append({"id": 2, "body": review.SUMMARY_MARKER + "\nOld edited text", "user": {"login": github.BOT}})
        self.api.trusted_summary_body.side_effect = None
        self.api.trusted_summary_body.return_value = ""
        self.report.update(comparison={"strategy": "skipped_unchanged"})
        section = Mock(return_value="")
        review.publish(self.api, self.report, "Head", issue_section=section)
        section.assert_called_once_with("")
        self.assertNotIn("Old edited text", self.comments[0]["body"])

    def test_resolution_permission_warning_leaves_review_published(self):
        fixed, original = "finding-" + "2" * 32, "c" * 40
        self.report.update(status="completed", workflow_status="completed", history=[{
            "status": "resolved", "id": fixed, "verification": {
                "status": "completed", "verdict": "fixed", "original_sha": original, "head_sha": self.report["head_sha"],
            },
        }])
        threads = {"thread": {"id": fixed, "source_sha": original}}
        self.api.resolve_thread.side_effect = github.GitHubForbidden("denied")
        delivery = review.publish(self.api, self.report, "Head", threads=threads, auto_resolve=True)
        self.assertEqual(delivery.counts["inline-posted"], 1)
        self.assertIn("denied permission to resolve", self.comments[0]["body"])
        self.assertIn("denied permission to resolve", delivery.summary)
        self.api.resolve_thread.side_effect = ValueError("malformed result")
        with self.assertRaisesRegex(ValueError, "malformed result"):
            review.publish(self.api, self.report, "Head", threads=threads, auto_resolve=True)
        self.api.resolve_thread.side_effect = github.GitHubForbidden("denied")
        normal = self.api.request.side_effect

        def fail_warning(method, path, payload, **kwargs):
            if method == "PATCH" and "denied permission to resolve" in payload["body"]:
                raise github.GitHubRequestError(method, 503)
            return normal(method, path, payload, **kwargs)

        self.api.request.side_effect = fail_warning
        delivery = review.publish(self.api, self.report, "Updated head", threads=threads, auto_resolve=True)
        self.assertEqual(len(delivery.warnings), 2)
        self.assertIn("Updated head", self.comments[0]["body"])

    def test_missing_required_summary_fails_publication(self):
        self.api.request.side_effect = github.GitHubRequestError("POST", 403)
        with self.assertRaises(github.GitHubRequestError):
            review.publish(self.api, self.report, "Summary")

    def test_truncated_failed_findings_fail_publication(self):
        self.report["findings"] = [{**self.report["findings"][0], "content": f"Evidence {i} " + "é" * 400}
                                   for i in range(130)]
        normal = self.api.request.side_effect

        def reject(method, path, payload, **kwargs):
            return None if path == "/pulls/42/comments" else normal(method, path, payload, **kwargs)

        self.api.request.side_effect = reject
        with self.assertRaisesRegex(ValueError, "could not fit"):
            review.publish(self.api, self.report, "Summary")
        self.assertIn("failed inline findings could not fit", self.comments[0]["body"])
        self.assertLessEqual(len(self.comments[0]["body"].encode()), github.COMMENT_BODY_LIMIT)

    def test_optional_read_failure_keeps_required_summary_and_avoids_duplicate(self):
        pages = self.api.pages.side_effect
        self.inline.append({"body": "<!-- mortis-action:finding:previous -->", "user": {"login": github.BOT}})
        for failed_read in ("files", "comments", "threads"):
            with self.subTest(failed_read=failed_read):
                def read(path, failed_read=failed_read):
                    if path == f"/pulls/42/{failed_read}":
                        raise TimeoutError()
                    return pages(path)

                self.api.pages.side_effect = read
                self.api.finding_threads.side_effect = TimeoutError() if failed_read == "threads" else None
                result = review.publish(self.api, self.report, "Review")
                self.assertEqual(result.counts["inline-failed"], 2 if failed_read == "files" else 1)
                self.assertEqual(result.counts["summary-only"], 0 if failed_read == "files" else 1)
                self.assertIn("Inline defect", self.comments[0]["body"])
                self.assertEqual(len(self.inline), 1)

    def test_writes_review_before_assessment_and_preserves_previous_cache_during_refresh(self):
        old = "\n\n### Linked issues\n\nPrevious assessment."
        new = "\n\n### Linked issues\n\nCurrent assessment."
        result = review.publish(self.api, self.report, "Review", issue_section=lambda _: old)
        self.assertEqual(result.counts["inline-posted"], 1)
        self.assertIn(old, self.comments[0]["body"])
        self.report["head_sha"] = "d" * 40

        def assess(previous):
            self.assertIn(old, previous)
            self.assertIn(review.ISSUES_START, self.comments[0]["body"])
            self.assertIn("pending refresh", self.comments[0]["body"])
            self.assertIn("Inline defect", self.comments[0]["body"])
            self.assertIn("New head", self.comments[0]["body"])
            return new

        review.publish(self.api, self.report, "New head", issue_section=assess)
        self.assertIn(new, self.comments[0]["body"])
        self.assertNotIn(old, self.comments[0]["body"])
        self.assertNotIn("pending refresh", self.comments[0]["body"])
        self.assertEqual(len(self.comments), 1)

    def test_pending_assessment_omits_rotated_credential_when_refresh_fails(self):
        credential = "fixture#rotated"
        for row in (markdown.safe_text(credential, 100), "[Source](https://example.com/fixture%23rotated.py)"):
            with self.subTest(row=row):
                old = "\n\n### Linked issues\n\n- " + row
                review.publish(self.api, self.report, "First", issue_section=Mock(return_value=old))
                self.assertIn(old, self.comments[0]["body"])
                refresh = Mock(side_effect=TimeoutError())
                with patch.dict(os.environ, {"MORTIS_API_KEY": credential}):
                    result = review.publish(self.api, self.report, "Second", issue_section=refresh)

                refresh.assert_called_once()
                self.assertTrue(result.warnings)
                self.assertIn("Second", self.comments[0]["body"])
                self.assertNotIn(review.ISSUES_START, self.comments[0]["body"])
                self.assertNotIn("rotated", self.comments[0]["body"])

    def test_same_head_legacy_marker_does_not_suppress_different_evidence(self):
        finding = self.report["findings"][0]
        finding["title"] = "Bad return value"
        legacy = review.finding_marker([self.report["head_sha"], self.filename, 4, finding["title"]])
        self.inline.append({"body": f"{legacy}\n{review.finding_text(finding)}", "user": {"login": github.BOT}})
        reused = review.publish(self.api, self.report, "Same finding")
        self.assertEqual(reused.counts["inline-existing"], 1)
        finding["content"] = "This one breaks a different caller."
        posted = review.publish(self.api, self.report, "Different evidence")
        self.assertEqual(posted.counts["inline-posted"], 1)

    def test_failed_advisory_patch_keeps_core_review_success(self):
        normal = self.api.request.side_effect

        def reject_patch(method, path, payload, **kwargs):
            if method == "PATCH":
                raise github.GitHubRequestError(method, 503)
            return normal(method, path, payload, **kwargs)

        self.api.request.side_effect = reject_patch
        result = review.publish(self.api, self.report, "Review", issue_section=lambda _: "\n\n### Linked issues\n\nChecked.")
        self.assertEqual(result.counts["inline-posted"], 1)
        self.assertTrue(result.warnings)
        self.assertIn("Inline defect", self.comments[0]["body"])
        self.assertNotIn("### Linked issues", self.comments[0]["body"])

    def test_long_evidence_matches_only_the_complete_digest_at_a_current_anchor(self):
        finding = self.report["findings"][0]
        finding.update(id="finding-" + "1" * 32, content="a" * 400 + " final evidence")
        review.publish(self.api, self.report, "First")
        stored = github.tracked_finding({"author": {"login": "github-actions", "__typename": "Bot"},
                                         "body": self.inline[0]["body"]})
        self.assertEqual(len(stored["content"]), 400)
        self.assertIn("evidence_digest", stored)
        stored["github_anchor"] = ("app.py", 4, 4)
        self.api.finding_threads.return_value = {"open": stored}
        self.report["head_sha"] = "e" * 40
        finding["id"] = "finding-" + "2" * 32
        self.assertEqual(review.publish(self.api, self.report, "Same evidence").counts["inline-existing"], 1)
        finding["content"] = "a" * 400 + " different evidence"
        self.assertEqual(review.publish(self.api, self.report, "Different ending").counts["inline-posted"], 1)
        self.report["head_sha"] = "f" * 40
        del stored["evidence_digest"]  # Old comments only have a prefix.
        self.assertEqual(review.publish(self.api, self.report, "Legacy prefix").counts["inline-posted"], 1)
