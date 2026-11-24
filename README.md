# Mortis Action

Run Mortis Engine on GitHub Actions for pull request reviews, branch comparisons, and security scans. The action installs Mortis Engine 0.1.5 on a Linux runner and uses your AI provider connection. Engine analysis sends eligible source and diffs to that provider.

## Review pull requests

1. Copy [the review workflow](.github/workflows/mortis-review.yml) to `.github/workflows/mortis-review.yml` on your default branch.
2. Add the `MORTIS_API_KEY` repository secret and set the action's `provider` to an [Engine provider preset](https://pypi.org/project/mortis-engine/0.1.5/#connect-with-environment-variables). Set the `MORTIS_MODEL` repository variable if `mortis.toml` does not set a review model.
3. Pin the action to a reviewed commit SHA. The workflow includes the SHA used by this repository.

Same-repository PRs are reviewed automatically. A user with repository write access can post `/mortis review` as a new PR comment to review the current head, including on forks. The `[review].automatic` setting controls automatic runs. Drafts and Dependabot PRs are skipped. Other bot-authored PRs require `include_bot_prs = true`.

### Ask or describe

With an action commit that installs Mortis Engine 0.1.5 or later, users with repository write access can post these commands on an open PR:

- `/mortis ask Why does this change the default?` answers from the current diff with links to the source lines. In a same-repository PR, post the command on a line in **Files changed** to receive a reply in that thread. For a fork PR, put the question in **Conversation** and paste the URL of a review comment on the selected lines on the last line.
- `/mortis describe` updates the title and the Mortis summary block in the description. The rest of the description is preserved.

To enable inline questions, add this event under `on`:

```yaml
  pull_request_review_comment:
    types: [created]
```

The existing `contents: read` and `pull-requests: write` permissions are sufficient. Both commands use the review model and provider already configured for the workflow.

- Set the `MORTIS_REVIEW_FORKS` repository variable to `true` to enable automatic fork reviews. Fork activity can then trigger provider calls.
- Set `MORTIS_UPLOAD_REPORTS` to `true` to retain JSON and Markdown as workflow artifacts for seven days. Reports can include source evidence.

The workflow uses `pull_request_target` and `issue_comment`. The action fetches PR commits into a temporary bare Git repository and reads them as data. It compares the exact head to the merge base and loads `mortis.toml` from the **target commit**. Mortis updates one summary comment with the change overview, coverage, and confirmed findings. It also posts findings inline when GitHub can anchor them to added lines.

When an Engine-supported replacement matches the complete line range in the current PR diff, the inline comment includes a GitHub suggestion. For workflow files, Mortis also checks that the resulting YAML parses and has unique mapping keys. Use **Commit suggestion** to apply the replacement to the PR branch.

Set `auto_resolve = true` under `[review]` in the target branch's `mortis.toml` to verify findings carried by incremental review history. Mortis resolves a matching GitHub thread only after the Engine verifies the fix against the current PR head. Resolving threads from GitHub comments alone requires an Engine release with `review --prior-findings`.

Existing `pull_request` workflows can continue reviewing same-repository PRs with their full checkout.

### Incremental pull request reviews

Set `incremental = true` under `[review]` in the target branch's `mortis.toml`. The first run reviews the full PR. Subsequent runs analyze files that changed since the last compatible, fully covered review and reuse coverage for the other files. Set `skip_unchanged = true` to skip review analysis when the head tree is identical. The job summary and PR comment list reviewed and reused files. The PR comment also keeps earlier open findings from the saved history.

Generate a key with `openssl rand -base64 32` and store it as the `MORTIS_STATE_KEY` repository secret. The bundled workflow passes the key to the action and grants `actions: read`. For a custom workflow, add those settings and serialize review jobs per PR using a concurrency group. Use an action revision that includes incremental review support.

Each PR's finalized review history is encrypted and stored as a workflow artifact for the repository's configured retention period. A missing or incompatible baseline triggers a full review. Keep the encryption key stable across runs to restore earlier findings.

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

The engine supplies defaults when the file is absent and rejects invalid configuration before contacting the provider. A model in the effective Engine settings takes precedence over the action’s `model` input. The provider preset and API key come from the workflow. Use the optional `protocol` and `base-url` inputs to override the preset’s connection settings.

The Actions summary shows status and coverage. The action exposes `status` (`completed`, `partial`, `failed`, or `skipped`), `run-id`, `report-json`, and `report-markdown`. Report outputs are runner-local paths for subsequent steps in the same job. Partial results keep their reports and return exit code 2. A later step can use `if: ${{ !cancelled() && steps.mortis.outputs.report-json != '' }}` to consume available reports, including after a failure. Reports may include source evidence. Successful analysis with findings exits 0.

## Development

Use Python 3.15 and follow the [contribution guide](CONTRIBUTING.md) to install test dependencies and run the offline suite.

### Releasing the action

Use the project-local [release preparation skill](.agents/skills/mortis-action-release/SKILL.md),
`$mortis-action-release` in Codex, to check Engine compatibility, update the
Action guides, and prepare release notes.

Push a new `vMAJOR.MINOR.PATCH` tag from `main`. The release workflow runs CI on that commit and creates a GitHub release draft with generated notes. Open the draft, select **Publish this Action to the GitHub Marketplace**, and publish the release.

## Security

Report vulnerabilities privately using the [security policy](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
