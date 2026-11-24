"""Exercise revision selection and bare fetches with local Git fixtures."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mortis_action import events, repository
from tests.helpers import pr_event


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
            check=False,
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
        args, revision = events.select_run("review", "pull_request", pr_event(base, head), self.repo)
        self.assertEqual(revision, base)
        result = self.engine(*args, "--preview", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["merge_base"], ancestor)
        self.assertEqual({row["path"] for row in report["selected_files"]}, {"keep.py", "mortis.toml"})
        self.assertEqual(self.config(base)["review"]["settings"]["model"], "review-model")
        self.assertEqual(self.config(ancestor)["review"]["settings"]["language"], "English")
        with patch.dict(os.environ, {"MORTIS_REF": "main"}):
            scan_args, revision = events.select_run("scan", "schedule", {}, self.repo)
        self.assertEqual(scan_args, ["scan", "--ref", base])
        self.assertEqual(self.config(revision)["scan"]["settings"]["model"], "scan-model")
        with patch.dict(os.environ, {"MORTIS_BASE": "main", "MORTIS_HEAD": "candidate"}):
            self.assertEqual(events.select_run("review", "workflow_dispatch", {}, self.repo), (args, base))
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
            args, revision = repository.fetch_pull_request(repo, pr)
            stale = {**pr, "head": {**pr["head"], "sha": base}}
            stale_args, _ = repository.fetch_pull_request(root / "stale.git", stale)

        self.assertIsNone(stale_args)
        self.assertEqual(revision, base)
        self.assertFalse((repo / "mortis.toml").exists())
        self.assertNotIn("extraheader", (repo / "config").read_text().lower())
        result = self.engine(*args, "--preview", "--format", "json", repo=repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["head_sha"], head)
        self.assertEqual({row["path"] for row in report["selected_files"]}, {"keep.py", "mortis.toml"})
