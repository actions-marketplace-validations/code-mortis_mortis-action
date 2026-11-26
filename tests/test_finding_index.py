"""Check the reachability, commit anchors and public fields of finding indexes."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mortis_action import markdown, review


class FindingIndexTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {
            "GITHUB_SERVER_URL": "https://github.example", "GITHUB_REPOSITORY": "org/repo",
            "MORTIS_API_KEY": "test#credential",
        }))
        self.head = "a" * 40
        self.original = "b" * 40
        self.finding = {"path": "src/a (b).py", "severity": "high", "start_line": 2, "end_line": 5,
                        "content": "Review this call", "title": "Wrong argument"}

    def test_summary_order_and_history_links(self):
        delivery = review.Delivery()
        delivery.findings["summary-only"] = [{**self.finding, "severity": "critical", "content": "Unanchored"}]
        delivery.findings["inline-failed"] = [{**self.finding, "content": "GitHub rejected this line"}]
        delivery.findings["inline-routed"] = [{**self.finding, "severity": "low", "content": "Routed to summary"}]
        delivery.findings["inline-existing"] = [self.finding]
        report = {"findings": [], "history": [{"id": "prior", "status": "open", "sha": self.original,
                  "snapshot": {**self.finding, "content": "Earlier defect"}}]}
        prior = markdown.earlier_open_findings(report)
        sticky, overflow, omitted = review.finding_sections(delivery, prior, self.head, 10000)
        self.assertEqual((overflow, omitted), ("", 0))
        for first, second in (("Unanchored", "GitHub rejected"), ("GitHub rejected", "Routed to summary"),
                              ("Routed to summary", "Earlier defect"), ("Earlier defect", "Wrong argument")):
            self.assertLess(sticky.index(first), sticky.index(second))
        self.assertNotIn("Review this call", sticky)
        self.assertIn(f"/blob/{self.original}/src/a%20%28b%29.py#L2-L5", sticky)
        self.assertIn(f"/blob/{self.head}/src/a%20%28b%29.py#L2-L5", sticky)

    def test_summary_only_overflow_preserves_every_finding_and_sanitizes_text(self):
        delivery = review.Delivery()
        for number in range(85):
            delivery.findings["summary-only"].append({**self.finding,
                "content": f"Finding {number:03} test#credential @team " + "é" * 380,
                "existing_code": "raw source", "suggestion_code": "private suggestion"})
        sticky, overflow, omitted = review.finding_sections(delivery, [], self.head, review.COMMENT_BODY_LIMIT)
        self.assertGreater(omitted, 0)
        self.assertLessEqual(len(sticky.encode()), review.COMMENT_BODY_LIMIT)
        self.assertEqual(overflow.count("Finding "), omitted)
        for number in range(85):
            self.assertEqual((sticky + overflow).count(f"Finding {number:03}"), 1)
        for private in ("test#credential", "@team", "raw source", "private suggestion"):
            self.assertNotIn(private, sticky + overflow)

    def test_step_summary_byte_limit_counts_newline_and_preserves_the_index(self):
        reports = Path(self.enterContext(tempfile.TemporaryDirectory()))
        heading = "## Mortis review"
        prefix = len((heading + "\n\n\n").encode())
        index = "ø" * ((markdown.JOB_SUMMARY_BYTES - prefix) // 2)
        body, path = markdown.fit_job_index(heading, index, reports)
        self.assertIsNone(path)
        self.assertLessEqual(len((body + "\n").encode()), markdown.JOB_SUMMARY_BYTES)
        larger = index + "ø"
        body, path = markdown.fit_job_index(heading, larger, reports)
        self.assertIn(path.name, body)
        self.assertLessEqual(len((body + "\n").encode()), markdown.JOB_SUMMARY_BYTES)
        self.assertEqual(path.read_text(), larger + "\n")

    def test_scan_counts_and_opt_in_index_only_expose_selected_fields(self):
        scan = {"schema_version": "mortis.security/v1", "commit": self.head,
                "coverage": {"completed_files": 1, "selected_files": 2}, "findings": [
                    {"severity": "low", "title": "Package update", "path": "deps.lock"},
                    {"severity": "critical", "title": "Inspect @team test#credential", "path": "app.py",
                     "source_sha": self.original, "explanation": "private explanation",
                     "evidence": [{"path": "app.py", "start_line": 3, "end_line": 4, "quote": "secret source"}]},
                    {"severity": "unclassified", "title": "Review manifest", "path": "test%23credential.yml"},
                ]}
        summary = markdown.summary(scan, "partial", "https://github.example/org/repo/actions/runs/1")
        self.assertIn("1/2 files covered", summary)
        self.assertIn("1 critical · 0 high · 0 medium · 1 low · 1 unknown", summary)
        self.assertNotIn("Inspect", summary)
        index = markdown.scan_index(scan)
        self.assertIn("**critical**", index)
        self.assertLess(index.index("Inspect"), index.index("Package update"))
        self.assertIn(f"/blob/{self.original}/app.py#L3-L4", index)
        self.assertIn(f"/blob/{self.head}/deps.lock)", index)
        self.assertIn("Location unavailable", index)
        for private in ("test#credential", "test%23credential", "private explanation", "secret source", "@team"):
            self.assertNotIn(private, index)
