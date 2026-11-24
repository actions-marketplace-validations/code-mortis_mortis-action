# Mortis Action

Run Mortis Engine on GitHub Actions for pull request reviews, branch comparisons, and security scans. The action installs Mortis Engine 0.1.3 on a Linux runner and uses your AI provider connection. Engine analysis sends eligible source and diffs to that provider.

## Review pull requests

1. Copy [the review workflow](.github/workflows/mortis-review.yml) to `.github/workflows/mortis-review.yml` on your default branch.
2. Add the `MORTIS_API_KEY` repository secret and set the action's `provider` to an [Engine provider preset](https://pypi.org/project/mortis-engine/0.1.3/#connect-with-environment-variables). Set the `MORTIS_MODEL` repository variable if `mortis.toml` does not set a review model.
3. Pin the action to a reviewed commit SHA. The workflow includes the SHA used by this repository.

Same-repository PRs are reviewed automatically. A user with repository write access can post `/mortis review` as a new PR comment to review the current head, including on forks. The `[review].automatic` setting controls automatic runs. Drafts and Dependabot PRs are skipped. Other bot-authored PRs require `include_bot_prs = true`.

- Set the `MORTIS_REVIEW_FORKS` repository variable to `true` to enable automatic fork reviews. Fork activity can then trigger provider calls.
- Set `MORTIS_UPLOAD_REPORTS` to `true` to retain JSON and Markdown as workflow artifacts for seven days. Reports can include source evidence.

The workflow uses `pull_request_target` and `issue_comment`. The action fetches PR commits into a temporary bare Git repository and reads them as data. It compares the exact head to the merge base and loads `mortis.toml` from the **target commit**. Mortis updates one summary comment with the change overview, coverage, and confirmed findings. It also posts findings inline when GitHub can anchor them to added lines.

When an Engine-supported replacement matches the complete line range in the current PR diff, the inline comment includes a GitHub suggestion. For workflow files, Mortis also checks that the resulting YAML parses and has unique mapping keys. Use **Commit suggestion** to apply the replacement to the PR branch.

With an Engine release that supports `review --prior-findings`, set `auto_resolve = true` under `[review]` in the target branch's `mortis.toml` to verify earlier inline findings on the next review. Mortis reuses its open threads and resolves one only after the Engine verifies the fix against the current PR head. Threads posted before finding IDs were recorded, or whose original commit is unavailable, stay open. The 0.1.3 package pinned here predates this integration.

Existing `pull_request` workflows can continue reviewing same-repository PRs with their full checkout.

## Compare branches

This workflow compares two refs available in the full checkout. Use a trusted base ref such as `origin/main`.

```yaml
name: Mortis branch review
on:
  workflow_dispatch:
    inputs:
      head:
        description: Head ref to review, such as origin/my-branch
        required: true
        type: string
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: code-mortis/mortis-action@main
        with:
          base: origin/main
          head: ${{ inputs.head }}
          provider: openai
          model: ${{ vars.MORTIS_MODEL }}
        env:
          MORTIS_API_KEY: ${{ secrets.MORTIS_API_KEY }}
```

## Scan a revision

Scan mode installs a checksum-verified Trivy 0.76.0 on Linux X64 and ARM64. Pass `ref` to select another local revision. The default is the commit that triggered the workflow.

```yaml
name: Mortis security scan
on:
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: code-mortis/mortis-action@main
        with:
          command: scan
          provider: openai
          model: ${{ vars.MORTIS_MODEL }}
        env:
          MORTIS_API_KEY: ${{ secrets.MORTIS_API_KEY }}
```

## Repository configuration and reports

Commit `mortis.toml` at your repository root. Reviews read it from the base commit. Scans read it from the scanned commit. For example:

```toml
[review]
automatic = true
include_bot_prs = false
language = "English"
exclusions = "vendor/**, generated/**"
effort = "medium"
max_files = 40

[scan]
exclusions = "vendor/**"
timeout_seconds = 600
```

The engine supplies defaults when the file is absent and rejects invalid configuration before contacting the provider. A model in the effective Engine settings takes precedence over the action’s `model` input. The provider preset and API key come from the workflow. Use the optional `protocol` and `base-url` inputs to override the preset’s connection settings. Each invocation uses fresh local Engine state.

The Actions summary shows status and coverage. The action exposes `status` (`completed`, `partial`, `failed`, or `skipped`), `run-id`, `report-json`, and `report-markdown`. Report outputs are runner-local paths for subsequent steps in the same job. Partial results keep their reports and return exit code 2. A later step can use `if: ${{ !cancelled() && steps.mortis.outputs.report-json != '' }}` to consume available reports, including after a failure. Reports may include source evidence. Successful analysis with findings exits 0.

## Development

Install `mortis-engine==0.1.3` and `PyYAML==6.0.3`, then run `python -B -m unittest discover -s tests`. Tests exercise local Git fixtures and mock the provider and GitHub boundaries.
