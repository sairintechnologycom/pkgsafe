# Feedback

PkgSafe v1.0.1 feedback collection is focused on adoption, verification, and
scanner tuning without expanding GA scope. PkgSafe v1.0.0 is npm-first GA.
PyPI, Go, and Cargo are preview ecosystems and should be reported as preview
gaps when they differ from npm depth.

Do not paste secrets, tokens, private registry credentials, `.npmrc` auth
values, proprietary source code, or unreleased package contents into public
issues. Redact hostnames, scopes, package names, and paths when needed, but keep
rule IDs, decisions, risk scores, and sanitized command output.

## Taxonomy

Use these labels or issue title prefixes when reporting:

| Type | Use for |
|---|---|
| `false_positive` | PkgSafe returned `warn` or `block` for a package you believe should be allowed. |
| `false_block` | PkgSafe blocked an install or CI workflow that should not have been blocked. |
| `scanner_crash` | Panic, non-deterministic failure, malformed output, or unexpected command exit. |
| `performance_issue` | Slow scan, timeout, excessive network use, or large lockfile regression. |
| `docs_issue` | Incorrect, stale, or unclear documentation. |
| `ecosystem_preview_gap` | PyPI, Go, or Cargo behavior that is missing compared with npm GA coverage. |
| `private_registry_issue` | Private registry routing, redaction, fallback, or authentication problems. |
| `osv_update_issue` | OSV reachability, cache, `update-db`, or advisory database problems. |
| `github_action_issue` | GitHub Action configuration, SARIF upload, summary, or fail-on behavior problems. |

## What To Include

For false positives and false blocks, include:

- Package name, ecosystem, and version.
- Exact command or GitHub Action workflow snippet used.
- PkgSafe decision, risk score, and rule IDs.
- Sanitized `--json` output if possible.
- Whether lifecycle scripts are present.
- Whether a private registry or registry config was involved.
- Why you believe the decision should change.

For scanner crashes, include:

- `pkgsafe version`.
- OS and architecture.
- Exact command.
- Sanitized terminal output or stack trace.
- Whether the scan was online or `--offline`.

For private registry issues, include:

- Ecosystem and registry type.
- Whether scope/prefix routing was used.
- Sanitized registry config shape without tokens or credentials.
- Whether public fallback was expected or disabled.

For OSV or `update-db` issues, include:

- Command output from `pkgsafe update-db` or `pkgsafe doctor`.
- Ecosystem.
- Whether the problem happens online, offline, or both.
- Any rate-limit or reachability errors with tokens and internal URLs removed.

For GitHub Action issues, include:

- Workflow YAML with secrets removed.
- Action inputs used.
- Whether SARIF upload, PR comment, changed-only, or offline mode was enabled.
- The generated Markdown summary or JSON report if safe to share.

## Recommended Labels

If repository labels are configured, use:

- `false_positive`
- `false_block`
- `scanner_crash`
- `performance_issue`
- `docs_issue`
- `ecosystem_preview_gap`
- `private_registry_issue`
- `osv_update_issue`
- `github_action_issue`

Use the false-positive template for tuning over-strict rules and the scanner bug
template for crashes or broken command behavior. Security vulnerabilities in
PkgSafe itself should follow `SECURITY.md`, not public issues.
