"""Check PR comment authorization, anchors and ask and describe publication."""

import os
from pathlib import Path
from unittest.mock import patch

from mortis_action import commands, events, github
from tests.helpers import ActionTestCase, comment_event, pr_event


class PullRequestTests(ActionTestCase):
    def test_comment_admission_checks_command_and_author_before_fetching_pr(self):
        pr = pr_event(fork=True)["pull_request"]
        with patch.object(github.GitHubAPI, "request") as request:
            for body in ("Looks good", "/Mortis review", "/mortis review now"):
                self.assertIsNone(events.remote_pull_request("issue_comment", comment_event(body))[0])
            request.assert_not_called()

            for permission in (None, {"permission": "read"}):
                request.reset_mock()
                request.return_value = permission
                self.assertIsNone(events.remote_pull_request("issue_comment", comment_event())[0])
                request.assert_called_once_with("GET", "/collaborators/maintainer/permission", allow_missing=True)

            request.side_effect = [{"permission": "write"}, pr]
            self.assertEqual(events.remote_pull_request("issue_comment", comment_event()), (pr, None))

    def test_automatic_fork_review_is_opt_in_and_uses_event_shas(self):
        event = pr_event(fork=True)
        pr = event["pull_request"]
        with patch.object(github.GitHubAPI, "request", return_value=pr) as request:
            with patch.dict(os.environ, {"MORTIS_REVIEW_FORKS": "false"}):
                self.assertIsNone(events.remote_pull_request("pull_request_target", event)[0])
            with patch.dict(os.environ, {"MORTIS_REVIEW_FORKS": "true"}):
                self.assertEqual(events.remote_pull_request("pull_request_target", event), (pr, None))
                request.return_value = {**pr, "head": {**pr["head"], "sha": "new-head"}}
                self.assertIsNone(events.remote_pull_request("pull_request_target", event)[0])

    def test_inline_and_linked_ask_use_the_same_current_diff_anchor(self):
        api = github.GitHubAPI("owner/repo", 42)
        anchor = {"pull_request_url": "https://api.github.com/repos/owner/repo/pulls/42",
                  "path": "src/main.py", "line": 7, "start_line": 5, "side": "LEFT", "start_side": "LEFT"}
        inline = {"comment": {"id": 4, "in_reply_to_id": 3}, "question": "Why remove this?", "inline": True}
        linked = {"comment": {"id": 5}, "inline": False,
                  "question": "Why remove this?\nhttps://github.com/owner/repo/pull/42/files#discussion_r3"}
        with patch.object(api, "request", return_value=anchor) as request:
            for command in (inline, linked):
                args, reason = commands.ask_arguments(api, command, self.directory)
                self.assertIsNone(reason)
                self.assertEqual(args[2:], ["--path=src/main.py", "--line", "5:7", "--side", "left"])
                self.assertEqual(Path(args[1]).read_text(), "Why remove this?")
            self.assertEqual(request.call_args.args, ("GET", "/pulls/comments/3"))
            request.return_value = {**anchor, "line": None}
            self.assertIsNone(commands.ask_arguments(api, inline, self.directory)[0])
            request.reset_mock()
            wrong_pr = {**linked, "question": linked["question"].replace("/42/", "/41/")}
            self.assertIsNone(commands.ask_arguments(api, wrong_pr, self.directory)[0])
            request.assert_not_called()

            commands.publish_answer(api, inline, {"status": "insufficient_context", "message": "Outdated anchor."})
            self.assertEqual(request.call_args.args[:2], ("POST", "/pulls/42/comments/3/replies"))
            self.assertIn("#discussion_r4", request.call_args.args[2]["body"])

    def test_ask_caps_rendered_comment_bytes_and_preserves_complete_citations(self):
        api = github.GitHubAPI("owner/repo", 42)
        path = "🚀" * 60 + ".py"
        sha = "b" * 40
        citations = [{"path": path, "sha": sha, "start_line": line, "end_line": line} for line in range(1, 13)]
        report = {"status": "completed", "limited_context": True,
                  "result": {"answer": "界" + "😀" * 5999, "citations": citations}}
        command = {"comment": {"id": 23}, "inline": False}
        with patch.object(api, "request") as request:
            commands.publish_answer(api, command, report)
        body = request.call_args.args[2]["body"]
        self.assertLessEqual(len(body.encode()), github.COMMENT_BODY_LIMIT)
        self.assertIn("#issuecomment-23", body)
        self.assertIn("界", body)
        self.assertNotRegex(body.split("\n\n**Sources**")[0], r"&#\d*$")
        for line in range(1, 13):
            self.assertIn(f"/blob/{sha}/" + "%F0%9F%9A%80" * 60 + f".py#L{line})", body)
        self.assertIn("configured context limit", body)
        self.assertIn("omitted to fit GitHub's comment limit", body)

    def test_inline_forks_are_skipped_before_api_access(self):
        event = {**pr_event(fork=True), "action": "created", "comment": comment_event("/mortis ask Why?")["comment"]}
        with patch.object(github.GitHubAPI, "request") as request:
            pr, reason = events.remote_pull_request("pull_request_review_comment", event)
        self.assertIsNone(pr)
        self.assertIn("from the conversation", reason)
        request.assert_not_called()

    def test_describe_preserves_author_content_and_checks_for_concurrent_edits(self):
        api = github.GitHubAPI("owner/repo", 42)
        base, head = "a" * 40, "b" * 40
        pr = {**pr_event(base, head)["pull_request"], "title": "Old title", "body": "Author notes\n\n- [ ] Run tests"}
        report = {"status": "completed", "base_sha": base, "head_sha": head,
                  "result": {"title": "Increase the default", "narrative": "Changes the default.", "groups": []}}
        self.assertEqual(events.comment_command("issue_comment", comment_event("/mortis describe")), ("describe", None))
        with patch.object(api, "request") as request, patch.object(api, "current", return_value=pr) as current:
            self.assertEqual(commands.finish_pr_command(api, pr, {}, "describe", report)[1], "completed")
            method, path, values = request.call_args.args
            self.assertEqual((method, path, values["title"]), ("PATCH", "/pulls/42", "Increase the default"))
            self.assertTrue(values["body"].startswith(pr["body"] + "\n\n"))
            updated = commands.description_body(values["body"] + "\nAuthor footer", report)
            self.assertEqual(updated.count(commands.DESCRIPTION_START), 1)
            self.assertTrue(updated.endswith("\nAuthor footer"))
            request.reset_mock()
            current.return_value = {**pr, "body": "New author notes"}
            self.assertEqual(commands.finish_pr_command(api, pr, {}, "describe", report)[1], "skipped")
            request.assert_not_called()
            current.return_value = None
            self.assertEqual(commands.finish_pr_command(api, pr, {}, "describe", report)[1], "skipped")
            request.assert_not_called()
