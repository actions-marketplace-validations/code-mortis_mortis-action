import unittest

from scripts.release_notes import release_notes


class ReleaseNotesTests(unittest.TestCase):
    def test_extracts_only_the_matching_version_and_preserves_markdown(self):
        notes = (
            "Release description.\n\n### Fixes\n\n- Keep `inline code`.\n  - Nested bullet.\n\n"
            "```sh\n## Example\nmortis --help\n```"
        )
        changelog = (
            "# Changelog\n\n## Unreleased\n\nFuture changes.\n\n"
            "## 1.2.30 - 2026-02-01\n\nNewer release.\n\n"
            f"## 1.2.3 - 2026-01-01\n\n{notes}\n\n"
            "## 1.2.2 - 2025-12-01\n\nPrevious release."
        )
        self.assertEqual(release_notes("v1.2.3", changelog), notes)
        self.assertEqual(release_notes("v1.2.2", changelog), "Previous release.")

    def test_rejects_missing_empty_or_duplicate_entries(self):
        heading = "## 1.2.3 - 2026-01-01\n"
        for changelog in (
            "## 1.2.30 - 2026-01-01\nDifferent patch.\n",
            heading + "\n \t\n## 1.2.2 - 2025-12-01\nOlder release.\n",
            heading + "First.\n" + heading + "Second.\n",
        ):
            with self.subTest(changelog=changelog), self.assertRaisesRegex(ValueError, "CHANGELOG.md"):
                release_notes("v1.2.3", changelog)
