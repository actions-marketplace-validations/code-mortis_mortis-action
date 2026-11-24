"""Synthetic GitHub payloads, Mortis reports and runner environment."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def pr_event(base="base", head="head", *, draft=False, fork=False, login="contributor", author_type="User"):
    return {
        "action": "opened",
        "sender": {"login": login},
        "pull_request": {
            "number": 42,
            "state": "open",
            "draft": draft,
            "user": {"login": login, "type": author_type},
            "base": {"sha": base, "repo": {"full_name": "owner/repo"}},
            "head": {"sha": head, "repo": {"full_name": "user/fork" if fork else "owner/repo"}},
        },
    }


def comment_event(body="/mortis review"):
    return {
        "action": "created",
        "sender": {"login": "maintainer"},
        "issue": {"number": 42, "pull_request": {"url": "https://api.github.com/repos/owner/repo/pulls/42"}},
        "comment": {"body": body, "user": {"login": "maintainer", "type": "User"}},
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


class ActionTestCase(unittest.TestCase):
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
                    "MORTIS_PROTOCOL": "",
                    "MORTIS_BASE_URL": "",
                    "MORTIS_MODEL": "fallback",
                    "MORTIS_GITHUB_TOKEN": "test-github-token",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_RUN_ID": "123",
                },
            )
        )
