# Mortis Action release surface map

Use the candidate Action revision and the exact Engine version it installs
when checking these surfaces. Repository paths in this table are relative to
the Action checkout.

| Changed surface | Release review targets |
| --- | --- |
| Public inputs, outputs and runner | `action.yml`, `run_mortis.py`, `tests/test_runner.py`, README workflow examples and site setup/CI guides |
| Workflow triggers, token permissions and fork handling | `.github/workflows/mortis-review.yml`, `mortis_action/events.py`, `mortis_action/github.py`, `run_mortis.py`, runner and PR command tests, README and site setup/PR guides |
| Git scopes and trusted configuration | `mortis_action/repository.py`, `mortis_action/events.py`, `run_mortis.py`, `mortis.toml`, `tests/test_repository.py`, `tests/test_runner.py`, README and site PR/CI guides |
| `/mortis` commands and PR body updates | `mortis_action/events.py`, `mortis_action/commands.py`, `mortis_action/github.py`, `tests/test_pr_commands.py`, README and site PR guide |
| PR summaries, inline comments and suggestions | `mortis_action/review.py`, `mortis_action/github.py`, `mortis_action/markdown.py`, `mortis_action/validate_workflow.py`, `tests/test_review.py`, README and site PR guide |
| Incremental reviews and encrypted baseline artifacts | `action.yml`, `.github/workflows/mortis-review.yml`, `run_mortis.py`, `mortis_action/baseline.py`, `tests/test_baseline.py`, `tests/test_runner.py`, README and site setup/PR guides |
| Report paths, partial results and exit status | `action.yml`, `run_mortis.py`, `mortis_action/markdown.py`, `tests/test_runner.py`, README and site CI guide |
| Engine and Trivy compatibility | `run_mortis.py`, `requirements-test.txt`, `mortis_action/trivy.py` and `src/mortis_engine/security_scans/scanner.py` in the pinned Engine release, plus the README and site CI guide |
| Release, CI and Marketplace metadata | `action.yml`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`, README release instructions and the site Action index |

## Documentation site

The default checkout is `../mortis-site`. The site describes the recommended
published Action revision. Keep capability claims tied to that Action tag and
its own Engine pin.

| Surface | Site files |
| --- | --- |
| Marketplace listing, released Action version and installed Engine | `src/content/docs/docs/action/index.mdx` |
| Consumer workflow, provider references, secrets and permissions | `src/content/docs/docs/action/setup.md` |
| PR commands, comments and incremental review state | `src/content/docs/docs/action/pull-requests.md` |
| Branch comparisons, scan compatibility and reports | `src/content/docs/docs/action/ci.md` |
| Checked release references and homepage Action setup example | `src/content/docs/docs/index.mdx`, `src/components/review-desk/content.ts` |
| Product navigation, moved routes and headings | `src/data/doc-sections.ts`, `src/data/doc-bookmarks.ts`, `src/pages/docs/[oldGuide].astro` and `tests/site.test.ts` |
| Site validation | `package.json`, `bun.lock`, `tests/site.test.ts`; build before testing generated routes and headings |

When updating the recommended release, check the full Action SHAs in the setup
and CI examples, the provider link for the installed Engine, and the release and
Marketplace links. Preserve existing bookmarks and review assertions in the
site tests that pin a version or historical compatibility note.
