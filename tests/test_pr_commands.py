"""Check PR comment authorization, anchors and ask and describe publication."""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

import run_mortis
from mortis_action import commands, events, github, markdown, repository
from tests.helpers import ActionTestCase, comment_event, pr_event, review_report


class PullRequestTests(ActionTestCase):
    def test_bundled_workflow_uses_trusted_triggers_for_pr_commands(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/mortis-review.yml"
        triggers = yaml.load(path.read_text(), Loader=yaml.BaseLoader)["on"]
        self.assertEqual(triggers["issue_comment"]["types"], ["created"])
        self.assertNotIn("pull_request_review_comment", triggers)

    def test_retargets_review_new_base_and_other_edits_skip_before_api_calls(self):
        event = {**pr_event(), "action": "edited", "changes": {"body": {"from": "old body"}}}
        with patch.object(github.GitHubAPI, "request", return_value=event["pull_request"]) as request:
            self.assertIsNone(events.remote_pull_request("pull_request_target", event)[0])
            self.assertIsNone(events.select_run("review", "pull_request", event, "")[0])
            request.assert_not_called()
            event["changes"] = {"base": {"ref": {"from": "release"}}}
            self.assertEqual(events.remote_pull_request("pull_request_target", event), (event["pull_request"], None))
            request.assert_called_once_with("GET", "/pulls/42")

    def test_scope_preview_is_a_single_authorized_conversation_reply_without_provider_calls(self):
        base, head = "a" * 40, "b" * 40
        pr = pr_event(base, head, fork=True)["pull_request"]
        event = comment_event("  /mortis preview\n")
        event["comment"]["id"] = 58
        self.assertIsNone(events.comment_command("pull_request_review_comment", event))
        self.assertIsNone(events.comment_command("issue_comment", comment_event("/mortis preview extra")))
        self.assertEqual(events.comment_command("issue_comment", comment_event(" /mortis review --full\n")),
                         ("review", "full"))
        event_path = self.directory / "preview-event.json"
        event_path.write_text(json.dumps(event))
        report = {"schema_version": "mortis.review-preview/v1", "base_sha": base, "head_sha": head,
                  "totals": {"selected_files": 1, "excluded_files": 1, "planned_batches": 1},
                  "selected_files": [{"path": "app.py"}], "excluded_files": [{"path": "metal.bin", "reason": "binary"}],
                  "bounds": {"max_files": 10}, "limit_reason": "File limit reached", "errors": []}
        comments = []
        calls = []

        def process(argv, **kwargs):
            self.assertNotIn("MORTIS_API_KEY", kwargs["env"])
            self.assertNotIn("MORTIS_STATE_KEY", kwargs["env"])
            if Path(argv[0]).name == "mortis":
                calls.append(argv[1:])
                if argv[1] == "config":
                    return subprocess.CompletedProcess(argv, 0, json.dumps({"review": {"settings": {}}}), "")
                self.assertEqual(argv[1:6], ["review", "--base", base, "--head", head])
                self.assertEqual(argv[-3:], ["--preview", "--format", "json"])
                return subprocess.CompletedProcess(argv, 2, json.dumps(report), "")
            return subprocess.CompletedProcess(argv, 0)

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
                                    "GITHUB_EVENT_PATH": str(event_path), "MORTIS_MODEL": "", "MORTIS_API_KEY": ""}),
            patch.object(github.GitHubAPI, "request", side_effect=request),
            patch.object(github.GitHubAPI, "pages", side_effect=lambda path: comments),
            patch.object(repository, "fetch_pull_request", return_value=(["review", "--base", base, "--head", head], base)),
            patch.object(subprocess, "run", side_effect=process),
            patch("builtins.print"),
        ):
            run_mortis.main()
            run_mortis.main()
        self.assertEqual([argv[0] for argv in calls], ["config", "review"])
        self.assertIn("status=partial", self.outputs.read_text())
        self.assertIn("status=skipped", self.outputs.read_text())
        self.assertNotIn("baseline-", self.outputs.read_text())
        self.assertEqual(len(comments), 1)
        for part in ("Full comparison scope", "1 planned batch", "app", "metal", "binary", "file limit is 10",
                     "File limit reached"):
            self.assertIn(part, comments[0]["body"])
        with patch.object(github.GitHubAPI, "is_current", return_value=False), patch.object(github.GitHubAPI, "request") as write:
            api = github.GitHubAPI("owner/repo", 42)
            self.assertEqual(commands.publish_preview(api, pr, event, report, 0)[1], "skipped")
            with self.assertRaises(ValueError):
                commands.publish_preview(api, pr, event, {**report, "head_sha": base}, 0)
            write.assert_not_called()

    def test_full_review_is_an_exact_authorized_conversation_command(self):
        name = "issue_comment"
        event = comment_event("/mortis review --full")
        self.assertEqual(events.comment_command(name, event), ("review", "full"))
        self.assertIsNone(events.comment_command("pull_request_review_comment", event))
        for body in ("/mortis review --full extra", "/mortis review --full\nmessage", "/mortis review --other"):
            self.assertIsNone(events.comment_command(name, comment_event(body)))
        with patch.object(github.GitHubAPI, "request", return_value={"permission": "read"}) as request:
            self.assertIsNone(events.remote_pull_request(name, event)[0])
            request.assert_called_once_with("GET", "/collaborators/maintainer/permission", allow_missing=True)

    def test_review_mode_is_visible_for_incremental_and_forced_full_reviews(self):
        report = review_report()
        full = markdown.summary(report, "completed", "run-url", full_review=True)
        self.assertIn("Full review requested manually", full)
        report.update(comparison={"strategy": "full", "reason": "no_baseline"},
                      coverage={"selected": [], "completed": []})
        normal = markdown.summary(report, "completed", "run-url")
        self.assertIn("**full** (no baseline)", normal)
        scan = {"schema_version": "mortis.scan/v1", "findings": [], "commit": "abcd",
                "coverage": {"completed_files": 0, "selected_files": 0}}
        self.assertEqual(markdown.summary(scan, "completed", "url", full_review=True),
                         markdown.summary(scan, "completed", "url"))

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

    def test_dependabot_reviews_require_a_write_authorized_manual_review_command(self):
        event = pr_event(login="dependabot[bot]", author_type="Bot")
        pr = event["pull_request"]
        with patch.object(github.GitHubAPI, "request") as request:
            for body in ("/mortis review", "/mortis review --full", "/mortis ask Why?", "/mortis preview", "/mortis describe"):
                with self.subTest(body=body):
                    request.side_effect = [{"permission": "write"}, pr]
                    selected, _ = events.remote_pull_request("issue_comment", comment_event(body))
                    self.assertEqual(selected, pr if body.startswith("/mortis review") else None)
            request.side_effect = [{"permission": "read"}]
            self.assertIsNone(events.remote_pull_request("issue_comment", comment_event())[0])
            request.side_effect = [pr]
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

    def test_inline_and_fork_questions_include_only_recent_prior_comments_from_the_selected_thread(self):
        api = github.GitHubAPI("owner/repo", 42)
        url = "https://api.github.com/repos/owner/repo/pulls/42"
        root = {"id": 1, "pull_request_url": url, "path": "app.py", "line": 3, "side": "RIGHT",
                "body": "<!-- machine metadata -->Why is this check needed?"}
        reply = {**root, "id": 8, "in_reply_to_id": 1, "body": "It protects concurrent writes."}
        rows = [root, reply, {**reply, "id": 9, "body": "test-provider-key"},
                {**reply, "id": 10, "body": "duplicate question", "created_at": "2026-02-02T00:00:00Z"},
                {**reply, "id": 11, "body": "future reply", "created_at": "2026-02-03T00:00:00Z"},
                {**reply, "id": 7, "in_reply_to_id": 6, "body": "different thread"},
                {**reply, "id": 4, "pull_request_url": "wrong", "body": "different PR"}]
        current = {"id": 10, "in_reply_to_id": 1, "created_at": "2026-02-01T00:00:00Z"}
        for inline in (True, False):
            link = "" if inline else "\nhttps://github.com/owner/repo/pull/42/files#discussion_r8"
            command = {"inline": inline, "comment": current, "question": "Why is that safer?" + link}
            with patch.object(api, "request", side_effect=[root if inline else reply, sorted(rows, key=lambda r: -r["id"])]):
                args, reason = commands.ask_arguments(api, command, self.directory)
            self.assertIsNone(reason)
            text = Path(args[1]).read_text()
            for included in ("Why is this check needed?", "It protects concurrent writes.", "[redacted]"):
                self.assertIn(included, text)
            for omitted in ("machine metadata", "duplicate question", "future reply", "different thread", "different PR",
                            "test-provider-key"):
                self.assertNotIn(omitted, text)
            self.assertTrue(text.endswith("Current question:\nWhy is that safer?"))

        for question in ("W" * 7999, "X" * 8000):
            self.assertEqual(commands.question_with_history(api, {"inline": True, "comment": current}, root, question),
                             question)
        with patch.object(api, "request", side_effect=TimeoutError):
            text = commands.question_with_history(api, {"inline": True, "comment": current}, root, "Why?")
            self.assertIn('"Why is this check needed?"', text)
            self.assertNotIn("machine metadata", text)
            self.assertTrue(text.endswith("Current question:\nWhy?"))

    def test_history_pages_past_unrelated_discussions_and_stops_at_the_root(self):
        api = github.GitHubAPI("owner/repo", 42)
        root = {"id": 50, "pull_request_url": "https://api.github.com/repos/owner/repo/pulls/42", "body": "First message"}
        reply = {**root, "id": 55, "in_reply_to_id": 50, "body": "Prior answer"}
        unrelated = [{**root, "id": n, "body": "Unrelated"} for n in range(200, 100, -1)]
        # Both full pages would trigger a third fetch if the root did not stop the search.
        second = [reply, root, *[{**root, "id": 40, "body": "Older"}] * 98]
        request = {"inline": True, "comment": {"id": 58}}
        with patch.object(api, "request", side_effect=[unrelated, second]) as get:
            text = commands.question_with_history(api, request, root, "Why?")
        self.assertEqual([call.args[1] for call in get.call_args_list],
                         [f"/pulls/42/comments?sort=created&direction=desc&per_page=100&page={p}" for p in (1, 2)])
        self.assertIn('"First message"\n"Prior answer"', text)
        self.assertNotIn("Unrelated", text)
        self.assertNotIn("Older", text)
        self.assertTrue(text.endswith("Why?"))
        with patch.object(api, "request", side_effect=[[*unrelated[:-1], reply], TimeoutError()]):
            text = commands.question_with_history(api, request, root, "Why?")
        self.assertIn('"First message"\n"Prior answer"', text)
        self.assertNotIn("Unrelated", text)
        self.assertTrue(text.endswith("Current question:\nWhy?"))

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

    def test_auto_describe_reuses_completed_summary_and_only_updates_body(self):
        pr = {**pr_event()["pull_request"], "title": "Author title", "body": "Author notes"}
        summary = {"status": "completed", "limited_context": True,
                   "result": {"narrative": "Use the new format.", "groups": []}}
        report = {"status": "completed", "base_sha": "base", "head_sha": "head", "summary": summary}
        api = Mock(pull="/pulls/42")
        api.current.return_value = pr
        self.assertEqual(commands.auto_describe(api, pr, report), "")
        body = commands.description_body(pr["body"], summary)
        self.assertTrue(body.startswith("Author notes\n\n"))
        self.assertIn("Use the new format", body)
        self.assertIn("configured context limit", body)
        api.request.assert_called_once_with("PATCH", api.pull, {"body": body})

        api.request.reset_mock()
        self.assertEqual(commands.auto_describe(api, {**pr, "body": body}, report), "")
        for changes in ({"status": "partial"}, {"summary": None}, {"summary": {"status": "skipped"}},
                        {"summary": {"status": "completed", "result": {}}}):
            self.assertEqual(commands.auto_describe(api, pr, {**report, **changes}), "")
        self.assertTrue(commands.auto_describe(api, pr, {**report, "head_sha": "unrelated"}))
        for current in (None, {**pr, "body": "Fresh author edit"}):
            api.current.return_value = current
            self.assertTrue(commands.auto_describe(api, pr, report))
        for original in (commands.DESCRIPTION_START, "a" * 65_536):
            self.assertTrue(commands.auto_describe(api, {**pr, "body": original}, report))
        api.request.assert_not_called()

        api.current.return_value = pr
        api.request.side_effect = ValueError("denied")
        self.assertTrue(commands.auto_describe(api, pr, report))
