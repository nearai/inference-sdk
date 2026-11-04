# Dependency updates and audits

Dependabot is configured to open PRs only for security updates across the
TypeScript, Python, Rust, and Go SDKs, their example projects, and the Go DCAP
WebAssembly crate. Routine major, minor, and patch version updates to these
packages require manual maintenance.

These package ecosystems set `open-pull-requests-limit: 0` to disable
version-update PRs. Security-update PRs use a separate limit and remain
eligible. The weekly `schedule` is retained because Dependabot requires it in
the configuration; it does not delay security updates. See GitHub's
[configuration for security updates only](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/customizing-dependabot-security-prs#example-1-configuration-for-security-updates-only).

GitHub Actions receive weekly version updates, including major releases,
grouped into one PR with `open-pull-requests-limit: 1`. New releases become
eligible after a seven-day cooldown (`cooldown.default-days: 7`). These
updates keep the workflows' full commit SHA pins current. GitHub generates
Dependabot alerts for Actions using semantic-version references, but not SHA
references, so these pins rely on version updates for automated maintenance. See
[GitHub Actions alert support](https://docs.github.com/en/code-security/reference/supply-chain-security/dependency-graph-supported-package-ecosystems).

Automatic security PRs require the repository's dependency graph, Dependabot
alerts, and Dependabot security updates to be enabled in GitHub settings.
The YAML file does not enable these repository settings. A repository
administrator must verify them when applying this policy; see
[configuring Dependabot security updates](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-security-updates).

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
