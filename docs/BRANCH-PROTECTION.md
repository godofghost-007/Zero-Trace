# Branch protection and required checks

Branch protection is a repository setting, not a file in the worktree. This
repository does not have a git remote configured, so the rules below have not
been applied. Apply them before publishing the first release.

## Required status checks

Use the CI job names exactly:

- `Engine and migrations`
- `BFF and identity`
- `Frontend`
- `Runtime security and load smoke`
- `Observability config`
- `Container builds`
- `Analyze (python)` and `Analyze (javascript-typescript)` (from
  `.github/workflows/codeql.yml`)

## Main branch rules

- Require a pull request before merging.
- Require at least one approving review.
- Dismiss stale approvals when new commits are pushed.
- Require review thread resolution.
- Require status checks to pass and require branches to be up to date.
- Require linear history.
- Block force pushes and deletions.
- Do not allow bypass, including for administrators, unless an incident
  commander explicitly records the exception.

## Apply with the GitHub CLI

Create a ruleset from the repository root:

```bash
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  repos/$OWNER/$REPO/rulesets \
  --input .github/rulesets/main.json
```

Verify:

```bash
gh api repos/$OWNER/$REPO/rulesets
gh api repos/$OWNER/$REPO/branches/main/protection
```

The second command only works when classic branch protection is used. Rulesets
are the preferred mechanism.

## Release tags

- Tags matching `v*` trigger `.github/workflows/release.yml`.
- The release workflow signs images with cosign keyless signing and creates a
  provenance attestation.
- Do not create a release tag from a branch that has not passed all required
  checks.
- Do not move or re-create a published tag. Publish a new patch version.

## What is still manual

- The repository owner must enable the ruleset.
- The repository owner must enable private vulnerability reporting and the
  security advisory workflow.
- The release workflow requires GitHub Actions permissions for packages,
  attestations, and OIDC. Review them before the first tag.
- No signed release has been produced yet.
