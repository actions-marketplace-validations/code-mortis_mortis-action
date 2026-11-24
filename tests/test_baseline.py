"""Exercise encrypted review history across fresh repositories and runner directories."""

import base64
import io
import json
import os
import subprocess
import sys
import zipfile
from unittest.mock import Mock, patch
from urllib.request import HTTPRedirectHandler

from mortis_engine import gateway
from mortis_engine.history import History, encode
from mortis_engine.review import review_commits
from mortis_engine.schemas import Response, Usage

from mortis_action import baseline, github
from tests.helpers import ActionTestCase, review_report


class BaselineTests(ActionTestCase):
    def setUp(self):
        super().setUp()
        self.key = base64.b64encode(b"a" * 32).decode()
        self.enterContext(patch.dict(os.environ, {
            "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/review.yml@refs/heads/main",
            "GITHUB_JOB": "review",
            "GITHUB_EVENT_NAME": "pull_request_target",
        }))
        self.repo = self.directory / "source"
        self.repo.mkdir()
        self.git("init", "-qb", "main")

    def git(self, *args):
        return subprocess.check_output([
            "git", "-C", self.repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com",
            "-c", "commit.gpgsign=false", *args,
        ], text=True).strip()

    def commit(self, files):
        for name, value in files.items():
            (self.repo / name).write_text(value)
        self.git("add", "--all")
        self.git("commit", "-qm", "Fixture")
        return self.git("rev-parse", "HEAD")

    def checkpoint(self, name, number=42, *, key=None):
        job = self.directory / name
        job.mkdir(mode=0o700)
        repo = job / "review.git"
        self.git("clone", "--quiet", "--bare", str(self.repo), str(repo))
        api = Mock(number=number, repo="/repos/owner/repo")
        environment = {"PATH": os.environ["PATH"], "XDG_STATE_HOME": str(job / "state")}
        return baseline.ReviewBaseline(api, sys.executable, repo, environment, key or self.key)

    def artifact(self, checkpoint, encrypted, *, run_id=123):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(baseline.FILENAME, encrypted)
        checkpoint.api.download_artifact.return_value = buffer.getvalue()
        checkpoint.api.request.return_value = {"artifacts": [{
            "name": checkpoint.name, "id": 25, "expired": False, "created_at": "2026-11-24T10:00:00Z",
            "workflow_run": {"id": run_id},
        }]}

    def test_restores_coverage_and_prior_findings_after_a_push(self):
        base = self.commit({
            "mortis.toml": "[review]\nincremental = true\nskip_unchanged = true\n",
            "app.py": "a = 0\n", "other.py": "b = 0\n",
        })
        first_head = self.commit({"app.py": "a = 1\n", "other.py": "b = 1\n"})
        first = self.checkpoint("first")

        async def send(connection, credentials, request, **kwargs):
            content = request.messages[0].content
            payload = json.loads(content.split("\n\n", 2)[1] if content.startswith("# ") else content)
            if "narrative" in request.output_schema["properties"]:
                output = {"narrative": "Fixture summary", "groups": []}
            else:
                output = {"task_key": payload["task_key"], "findings": [],
                          "completed_units": [unit["key"] for unit in payload["assigned_units"]]}
            return Response(output=output, usage=Usage(total_tokens=3))

        def run(checkpoint, head):
            with patch.dict(os.environ, {"XDG_STATE_HOME": checkpoint.env["XDG_STATE_HOME"]}):
                return review_commits(
                    checkpoint.repo, base=base, head=head,
                    connection={"provider": "custom", "protocol": "openai", "model": "fixture", "options": {}},
                    get_credentials=dict,
                )

        self.enterContext(patch.object(gateway, "send", side_effect=send))
        original = run(first, first_head)
        self.assertEqual(original["comparison"]["reason"], "no_baseline")
        finding = {**review_report()["findings"][0], "id": "finding-" + "1" * 32,
                   "status": "open", "source_sha": first_head}
        original["findings"].append(finding)
        with (
            patch.dict(os.environ, {"XDG_STATE_HOME": first.env["XDG_STATE_HOME"]}),
            History(first.repo) as history,
            history.db,
        ):
            history.db.execute("UPDATE runs SET report=? WHERE id=?", (encode(original), original["run_id"]))
        saved = first.save(original["run_id"], self.reports).read_bytes()
        self.assertNotIn(finding["content"].encode(), saved)

        second_head = self.commit({"other.py": "b = 2\n"})
        second = self.checkpoint("second")
        self.artifact(second, saved)
        self.assertTrue(second.restore(base, second_head))
        report = run(second, second_head)
        self.assertEqual(report["comparison"]["strategy"], "incremental")
        self.assertEqual(report["comparison"]["baseline_run_id"], original["run_id"])
        self.assertEqual([row["path"] for row in report["coverage"]["completed"]], ["other.py"])
        self.assertEqual([row["path"] for row in report["coverage"]["reused"]], ["app.py"])
        self.assertEqual([row["snapshot"] for row in report["history"] if row["status"] == "open"], [finding])

        with patch.dict(os.environ, {"GITHUB_RUN_ID": "124"}):
            updated = second.save(report["run_id"], self.reports).read_bytes()
        third = self.checkpoint("third")
        self.artifact(third, updated, run_id=124)
        self.assertTrue(third.restore(base, second_head))
        skipped = run(third, second_head)
        self.assertEqual(skipped["comparison"]["strategy"], "skipped_unchanged")
        self.assertEqual(skipped["usage"]["requests"], [])
        self.assertEqual([row["id"] for row in skipped["history"]], [finding["id"]])

        for number, key, run_id in ((43, self.key, 123), (42, self.key, 124), (42, base64.b64encode(b"b" * 32).decode(), 123)):
            with self.subTest(number=number, run_id=run_id, same_key=key == self.key):
                other = self.checkpoint(f"invalid-{number}-{run_id}-{key[0]}", number, key=key)
                self.artifact(other, saved, run_id=run_id)
                with self.assertRaisesRegex(ValueError, "No valid Mortis baseline"):
                    other.restore(base, second_head)
                with patch.dict(os.environ, {"XDG_STATE_HOME": other.env["XDG_STATE_HOME"]}), History(other.repo) as history:
                    self.assertEqual(history.list(), [])

    def test_download_never_redirects_the_github_token(self):
        api = github.GitHubAPI("owner/repo", 42)
        response = io.BytesIO(b"artifact content")
        with patch.object(github, "urlopen", return_value=response) as open_url:
            self.assertEqual(api.download_artifact(25, 32), b"artifact content")
        request = open_url.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-github-token")
        redirect = HTTPRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, "https://blob.example.com/archive",
        )
        self.assertIsNone(redirect.get_header("Authorization"))

    def test_expired_baseline_is_ignored(self):
        self.commit({"app.py": "a = 0\n"})
        checkpoint = self.checkpoint("expired")
        self.artifact(checkpoint, b"artifact")
        checkpoint.api.request.return_value["artifacts"][0]["expired"] = True
        self.assertFalse(checkpoint.restore("a" * 40, "b" * 40))
        checkpoint.api.download_artifact.assert_not_called()
