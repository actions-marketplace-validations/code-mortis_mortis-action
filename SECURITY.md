# Security policy

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/code-mortis/mortis-action/security/advisories/new).
If the form is unavailable, open an issue asking for a private reporting channel
and keep the vulnerability details out of the issue.

Include the Action tag or commit, the pinned Engine version, the workflow trigger
or command, the impact, and a minimal sanitized reproduction. Remove provider
credentials, GitHub tokens, private endpoints, and private repository content.

## Data and permissions

The bundled review workflow fetches pinned PR commits into a temporary bare Git
repository and loads review settings from the trusted base revision. It sends
eligible source and diffs to the configured provider. Review the provider's data
handling before enabling reviews of sensitive repositories.

Keep provider credentials in GitHub Actions secrets. Enable automatic reviews of
fork PRs and upload report artifacts only when appropriate for the repository.
Treat reports as source-bearing data and review their contents before sharing.
