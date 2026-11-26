"""Exercise the composite Action's PR lifecycle with offline GitHub and Engine responses."""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import run_mortis
from mortis_action import github, repository
from tests.helpers import ActionTestCase, comment_event, pr_event


class ReviewWorkflowTests(ActionTestCase):
    def setUp(self):
        super().setUp()
        self.base, self.head = "a" * 40, "b" * 40
        self.pr = pr_event(self.base, self.head)["pull_request"]
        self.pr.update(title="Author's title", body="Closes #9")
        self.issue = {"number": 9, "title": "Requirements", "body": "- [ ] Reject duplicates"}
        self.summaries = []
        self.inline = []
        self.body_edits = []
        self.questions = []
        self.reviews = []
        self.skip_unchanged = False
        self.event_file = self.directory / "event.json"
        self.enterContext(patch.dict(os.environ, {
            "RUNNER_OS": "Linux", "RUNNER_TEMP": str(self.directory), "MORTIS_COMMAND": "review",
            "GITHUB_EVENT_PATH": str(self.event_file), "GITHUB_EVENT_NAME": "pull_request_target",
        }))
        self.enterContext(patch.object(repository, "fetch_pull_request", side_effect=lambda repo, pr:
            (["review", "--base", pr["base"]["sha"], "--head", pr["head"]["sha"]], pr["base"]["sha"])))
        self.enterContext(patch.object(github.GitHubAPI, "request", side_effect=self.github_request))
        self.enterContext(patch.object(github.GitHubAPI, "graphql", side_effect=self.graphql))
        self.enterContext(patch.object(subprocess, "run", side_effect=self.engine))
        self.enterContext(patch("builtins.print"))

    def github_request(self, method, path, data=None, **kwargs):
        if method == "GET":
            if path == "/pulls/42":
                return dict(self.pr)
            if path == "/issues/9":
                return self.issue
            if path == "/collaborators/maintainer/permission":
                return {"permission": "write"}
            if path.startswith("/issues/42/comments?"):
                return self.summaries
            if path.startswith("/pulls/42/files?"):
                return [{"filename": "app.py", "patch": "@@ -1 +1,2 @@\n context\n+new"}]
            if path.startswith("/pulls/42/comments?"):
                return self.inline
        if method == "POST" and path == "/pulls/42/comments":
            self.inline.append({"id": 3, "user": {"login": github.BOT}, **data})
            return self.inline[-1]
        if method == "POST" and path == "/issues/42/comments":
            self.summaries.append({"id": 1, "node_id": "summary", "user": {"login": github.BOT}, **data})
            return self.summaries[-1]
        if method == "PATCH" and path == "/issues/comments/1":
            self.summaries[0].update(data)
            return self.summaries[0]
        if method == "PATCH" and path == "/pulls/42":
            self.body_edits.append(data)
            self.pr.update(data)
            return self.pr
        self.fail(f"Unexpected GitHub request {method} {path}")

    def graphql(self, query, variables):
        actor = {"__typename": "Bot", "login": "github-actions"}
        if variables == {"id": "summary"}:
            return {"node": {"author": actor, "editor": actor, "body": self.summaries[0]["body"],
                             "lastEditedAt": "2026-01-01T01:00:00Z"}}
        if "reviewThreads(" in query:
            threads = [{"id": "thread", "isResolved": False, "isOutdated": False, "path": row["path"],
                        "diffSide": "RIGHT", "line": row["line"],
                        "comments": {"nodes": [{"body": row["body"], "author": actor}]}} for row in self.inline]
            return {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": threads, "pageInfo": {"hasNextPage": False}}}}}
        self.fail(f"Unexpected GraphQL request {variables}")

    def engine(self, argv, **kwargs):
        result = {}
        if Path(argv[0]).name == "mortis":
            if argv[1] == "config":
                result = {"review": {"settings": {"model": "fixture", "automatic": True}}}
            elif argv[1] == "review":
                self.reviews.append(argv)
                skipped = self.skip_unchanged and "--no-skip-unchanged" not in argv
                report = {
                    "schema_version": "mortis.review/v1", "run_id": f"review-{len(self.reviews)}",
                    "base_sha": self.base, "head_sha": self.head, "status": "skipped" if skipped else "completed",
                    "workflow_status": "completed", "findings": [], "coverage": {"completed": [], "selected": []},
                    "summary": {"status": "completed", "result": {"narrative": "Detect duplicate records", "groups": []}},
                }
                if skipped:
                    report.update(comparison={"strategy": "skipped_unchanged", "reason": "identical_content"},
                                  summary={"status": "skipped"})
                else:
                    report["findings"] = [{"id": "finding-" + self.head[:32], "severity": "high", "path": "app.py",
                                           "start_line": 2, "end_line": 2, "content": "Duplicate write"}]
                Path(argv[-3]).write_text(json.dumps(report))
                Path(argv[-1]).write_text("# Report")
            elif argv[1] == "ask":
                self.assertEqual(argv[argv.index("--head") + 1], self.head)
                self.questions.append(Path(argv[argv.index("--question-file") + 1]).read_text())
                result = {"schema_version": "mortis.ask/v1", "base_sha": self.base, "head_sha": self.head,
                          "status": "completed", "result": {"answer": "Handled in the validator.", "citations": [
                              {"path": "app.py", "sha": self.head, "start_line": 2, "end_line": 3}]}}
            else:
                self.assertEqual(argv[1], "connect")
        return subprocess.CompletedProcess(argv, 0, json.dumps(result), "")

    def trigger(self, action, *, full=False):
        if full:
            event = comment_event("/mortis review --full")
        else:
            event = {"action": action, "sender": {"login": "contributor"}, "pull_request": self.pr}
        self.event_file.write_text(json.dumps(event))
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "issue_comment" if full else "pull_request_target"}):
            run_mortis.main()
        self.assertTrue(self.outputs.read_text().endswith("exit-code=0\n"))
        self.assertEqual(len(self.summaries), 1)
        return self.summaries[0]["body"]

    def test_opt_in_features_through_open_push_full_review_and_issue_edit(self):
        with patch.dict(os.environ, {"MORTIS_AUTO_DESCRIBE": "true", "MORTIS_CHECK_LINKED_ISSUES": "true"}):
            body = self.trigger("opened")
            self.assertIn("Handled in the validator", body)
            self.assertIn("Reject duplicates", self.questions[0])
            self.assertIn("inline-posted=1", self.outputs.read_text())
            self.assertEqual(self.body_edits, [{"body": self.pr["body"]}])
            self.assertTrue(self.pr["body"].startswith("Closes #9"))
            self.head = self.pr["head"]["sha"] = "c" * 40
            self.trigger("synchronize")
            self.assertIn("inline-existing=1", self.outputs.read_text())
            self.assertEqual(len(self.inline), 1)
            self.assertEqual(len(self.questions), 2)
            body = self.trigger("created", full=True)
            self.assertIn("Full review requested manually", body)
            self.assertIn("--no-incremental", self.reviews[-1])
            self.assertIn("--no-skip-unchanged", self.reviews[-1])
            self.assertEqual(len(self.questions), 2)
            self.skip_unchanged = True
            self.issue["body"] = "- [ ] Reject duplicate email addresses"
            body = self.trigger("synchronize")
            self.assertIn("Detect duplicate records", body)
            self.assertIn("Reject duplicate email addresses", self.questions[-1])
            self.assertEqual((len(self.questions), len(self.body_edits)), (3, 1))

    def test_disabled_features_do_not_ask_or_edit_description(self):
        self.trigger("opened")
        self.assertEqual((self.questions, self.body_edits), ([], []))
