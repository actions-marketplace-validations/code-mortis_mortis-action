# Repository Guidelines

## Project Structure

- `action.yml` defines the composite GitHub Action and its inputs and outputs. `run_mortis.py` is the entry point that runs Mortis Engine and publishes results.
- `mortis_action/` contains event routing, Git revision handling, GitHub API calls, review publishing, report rendering, and Trivy setup.
- `tests/` contains the offline test suite. Shared fixtures and mocks live in `tests/helpers.py`.
- `.github/workflows/ci.yml` runs the test suite. `.github/workflows/mortis-review.yml` is the bundled review workflow. `mortis.toml` configures this repository’s Mortis runs.

## Local Development

Use Python 3.15 and Git. The composite action runs directly from its checkout.

```sh
python3.15 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
python -B -m unittest discover -s tests
```

The first three commands prepare the test environment. The last runs the same suite as CI without writing bytecode. Keep the dependency pins in `requirements-test.txt` aligned with the corresponding runtime pins in `run_mortis.py`.

## Coding Style

Use four spaces for Python and two for YAML. Follow existing `snake_case` names for Python modules, functions, and variables, and `PascalCase` for classes. The PR template asks for Ruff results. Run `ruff check .` if Ruff is available and record the outcome.

## Testing

Use `unittest` with `test_*.py` files and `test_*` methods. Add regression tests for behavior changes using synthetic fixtures, temporary Git repositories, and mocked GitHub and provider calls. Run one module with `python -B -m unittest tests.test_runner`. CI has no numeric coverage threshold.

## Commits and Pull Requests

Use Conventional Commits with short, imperative subjects, such as `fix(action): redact secrets from failure diagnostics`. Keep PRs focused and use the [PR template](.github/pull_request_template.md). Explain the problem and resulting behavior, link relevant issues, and report checks and any gaps.

## Security

Keep PR head content as data and load review policy from the trusted base revision. Sanitize logs and reports before sharing. Report vulnerabilities privately through the [security policy](SECURITY.md).
