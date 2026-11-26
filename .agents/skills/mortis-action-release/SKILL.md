---
name: mortis-action-release
description: Prepare or audit a Mortis Action release. Verify the composite action and its pinned Engine, reconcile repository and site guides, and write the versioned changelog entry used as the GitHub release description. Publication requires separate authorization.
---

# Mortis Action release preparation

Prepare a reviewable diff in this checkout and any affected guides in
`../mortis-site` or the site checkout specified by the maintainer. The Action
runs directly from its Git revision and has its own release tag. The Engine
version is a runtime dependency.

## Establish the release scope

- Read `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `action.yml`, and the current
  `.github/workflows/ci.yml` and `.github/workflows/release.yml`. Check the Git
  status in each affected checkout and preserve unrelated work. Use the
  [public-surface map](references/public-surface-map.md) to find affected callers,
  regressions and documentation.
- Use the requested stable tag `vMAJOR.MINOR.PATCH` or propose one from the
  verified changes. Compare the latest published release with the candidate
  commit, including any in-scope working changes. Verify local tags against
  GitHub when available and report an unverified baseline as such.

## Write the GitHub release description

Edit the root `CHANGELOG.md` before tagging. Under `## Unreleased`, add or
update one `## X.Y.Z - YYYY-MM-DD` heading for the proposed Action tag
`vX.Y.Z`. Move the changes shipping in this version into that section. Keep
older releases in newest-first order and preserve their entries.

Write the section body for Action users. Summarize what changed since the
preceding release and any upgrade steps. Include changes to inputs, outputs,
permissions, runner requirements, dependency pins and known limitations when
relevant. Use `###` for subsections. The workflow uses this Markdown verbatim
as the draft description, with the tag as the release title.

## Synchronize the Action and its documentation

- Review `action.yml`, `run_mortis.py`, `mortis_action/`, and affected `tests/`
  for changes to the public contract. Check that the README and consumer
  examples match the released commands, scope, outputs and exit behavior.
  Review the bundled workflow in `.github/workflows/mortis-review.yml`.
- Keep `requirements-test.txt` aligned with the relevant runtime pins in
  `run_mortis.py`. On a dependency bump, verify the targeted Engine version is
  available on PyPI and supports the runner's Python version. Check the Action's
  Engine calls and report parsing against that version, including trusted revision
  configuration, partial results and saved baselines when affected.
- Check scan compatibility explicitly for each release. Compare the Trivy
  version in `mortis_action/trivy.py` with the scanner requirement in the pinned
  Engine release. If the installer changes, verify its architecture and checksum
  entries against the corresponding assets. The mocked suite can pass while the
  versions disagree. Report version mismatches as scan blockers and reflect the
  limitation in release notes and guides.
- Preserve the trusted base configuration and treatment of PR head content as
  data. When changing workflows or incremental reviews, verify documented token
  permissions, fork behavior, encrypted baseline requirements and artifact
  handling against source and offline fixtures.
- Use full commit SHAs with version comments in recommended consumer workflows.
  Resolve the SHA from the actual release tag. Plan any self-use pin update in
  `.github/workflows/mortis-review.yml` as a follow-up after tagging.

## Synchronize the site

Read the site's `README.md` and `package.json`. Edit the affected Action guides,
docs index and homepage examples identified in the public-surface map.

Keep Setup, CI and the docs index on the same Action release when updating their
recommended version. Update the Action guides' Engine pin when the dependency
changes. Keep historical caveats tied to their releases and preserve bookmarked
headings. If headings or routes move, check `src/data/doc-bookmarks.ts`,
`src/data/doc-sections.ts` and `tests/site.test.ts`. If a site checkout or a final
release SHA is unavailable, prepare the independent changes and report the
pending site follow-up. Coordinate deployment after the referenced release and
listing are available.

## Validate and hand off

- Use Python 3.15 and install `requirements-test.txt` in an isolated virtual
  environment. Run focused regressions for behavior changes, then
  `python -B -m unittest discover -s tests`. Run `ruff check .` if available.
  Review changed workflow syntax and permissions. Record the offline suite,
  hosted CI and live runner/provider evidence separately.
- For affected site pages, run `bun install --frozen-lockfile`, `bun run check`,
  `bun run build`, then `bun test`. The tests read generated `dist/` pages.
  Verify rendered examples, release pins, compatibility notes and bookmarks.
- From the repository root, preview the release description with
  `python3 scripts/release_notes.py vX.Y.Z` using the proposed tag. Check
  the Markdown and include the changelog entry in the release diff.
- Provide the proposed tag, preceding release, link to the changelog section,
  changed repository and site surfaces, checks run and any pending work.

## Publication boundary

With explicit authorization, a new stable tag on a reviewed commit on `main`
triggers the Action release workflow. It checks the tag's commit and main
ancestry, runs CI and extracts the matching changelog entry from that commit.
It creates a GitHub release draft or refreshes the matching draft's description
on a rerun. Verify the tag and compare the draft body with the local preview.
The maintainer publishes the draft with **Publish this Action to the GitHub
Marketplace** selected. Verify the tag, public release and Marketplace listing
before switching public examples to that release.

Release preparation ends at the diff and handoff. Commits, tags, pushes,
Marketplace publication, site deployment and live evaluations require explicit
authorization. Preserve published tags and repair only the failed release stage.
