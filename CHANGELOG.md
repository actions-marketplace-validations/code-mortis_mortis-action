# Changelog

## Unreleased

- Upgrade to Mortis Engine 0.1.7. Incremental reviews recheck Python importers when a module-level function’s required parameters change or it gains or loses `*args` or `**kwargs`. The first review after upgrading establishes a new baseline.
- GitHub release drafts now use the tagged version’s changelog entry as their description.

## 0.2.1 - 2026-11-26

- Upgrade to Mortis Engine 0.1.6 and retain caller coverage in encrypted review history. Deleting or renaming an eligible file triggers a full comparison so the review includes surviving callers.
- Restore security scans on Linux x64 and ARM64 by installing the Engine’s required Trivy version, 0.76.2.

## 0.2.0 - 2026-11-24

- Add opt-in incremental pull request reviews. Set `incremental = true` and configure the `MORTIS_STATE_KEY` secret to reuse coverage and carry open findings forward in encrypted per-PR history.
- Security scans in this version fail because it installs Trivy 0.76.0 and the Engine requires 0.76.2.

## 0.1.0 - 2026-11-24

- Run Mortis Engine on GitHub Actions for pull request reviews and branch comparisons.
- Publish PR summaries and inline findings, answer `/mortis ask` questions, and update PR descriptions with `/mortis describe`.
- Introduce the `scan` command. Its Trivy version mismatch is fixed in 0.2.1.
