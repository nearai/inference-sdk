# Dependency updates and audits

Dependabot checks the TypeScript, Python, and Rust SDKs and their example
projects weekly. Minor and patch version updates are grouped by ecosystem,
with a seven-day cooldown and at most five open version-update PRs per
ecosystem. Major version updates require manual maintenance. These version
update rules do not delay or suppress Dependabot security updates. GitHub
Actions receive the same update policy.

Python uses Dependabot's native `uv` ecosystem so updates include `uv.lock`.
TypeScript uses the `npm` ecosystem for pnpm. GitHub's supported-version table
currently lists pnpm through v10, while this repo uses v11 with lockfile format
9. Check the first Dependabot update logs for compatibility; the separate pnpm
audit jobs use the version declared in `js/package.json`.

The Security Audit workflow runs on PRs targeting `main`, pushes to `main`,
weekly on Monday at 09:00 UTC, and manually. It checks each SDK and example
independently:

| Language | Audit | Coverage |
| --- | --- | --- |
| TypeScript | `pnpm audit` | Runtime and development dependencies in each pnpm lockfile |
| Python | `pip-audit` | Hashed uv exports, including all dependency groups; local project entries are omitted |
| Rust | `cargo deny check advisories` | Locked RustSec checks across all features and targets, with shared `deny.toml` |

Audits initially run in **report-only mode** while existing dependency
findings are triaged. Each audit's exit status appears in the job summary,
and its full report appears in the
step log. A successful workflow does **not** mean there are no vulnerabilities:
audit failures, including scanner/network errors, do not block merges.
Separate setup and export failures remain blocking. No advisory allowlist is
configured. After triaging the backlog, remove `continue-on-error` from the
three audit steps to make them blocking.

The workflow uses read-only repository permissions and does not open issues,
publish check runs outside the workflow, or run dependency lifecycle scripts.
Its action references are pinned to commits. The Python scanner version is
pinned in the workflow and requires manual updates; Rust's scanner comes from
the pinned cargo-deny action.
