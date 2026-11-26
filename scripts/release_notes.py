"""Print one Action release description from the repository changelog."""

import argparse
import re
from pathlib import Path

VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"


def release_notes(tag, changelog):
    if not re.fullmatch(f"v{VERSION}", tag):
        raise ValueError(f"Expected a stable release tag such as v1.2.3, got {tag!r}.")

    version = re.escape(tag[1:])
    heading = re.compile(rf"{version} - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}")
    matches = []
    sections = re.split(rf"^##[ \t]+(?=Unreleased\b|{VERSION}\b)", changelog, flags=re.MULTILINE)
    for section in sections[1:]:
        title, _, body = section.partition("\n")
        if heading.fullmatch(title.rstrip()):
            matches.append(body.strip("\n"))

    if len(matches) != 1 or not matches[0].strip():
        raise ValueError(f"Expected one nonempty '## {tag[1:]} - YYYY-MM-DD' entry in CHANGELOG.md.")
    return matches[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    args = parser.parse_args()
    try:
        print(release_notes(args.tag, Path("CHANGELOG.md").read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
