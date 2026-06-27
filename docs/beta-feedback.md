# Beta Feedback

PkgSafe is in private beta (`v0.2.0-beta.1`). Feedback on decision accuracy,
ecosystem coverage, and rough edges is the point of this phase.

## Where to file

Open an issue and pick the matching template
([.github/ISSUE_TEMPLATE](../.github/ISSUE_TEMPLATE)). Blank issues are
disabled on purpose.

| Situation | Template |
|-----------|----------|
| Wrong output, crash, or broken behavior | **Bug report** |
| Package flagged `warn`/`block` that should be `allow` | **False positive** |
| Package `allow`ed (or only `warn`) that you believe is risky/malicious | **False negative** |
| Detection gap, hardening idea, advisory-coverage request | **Security-relevant report** |
| Vulnerability IN PkgSafe itself | **Do not file an issue** — see below |

## Sensitive vulnerabilities go to SECURITY.md

A vulnerability in PkgSafe itself (firewall bypass, exploitable extractor,
loopback API data leak, forgeable policy-pack signature) is **not** a public
issue. Follow the private disclosure in [SECURITY.md](../SECURITY.md) so it can
be triaged before public disclosure. The Security-relevant template is only for
non-sensitive observations.

## What to include

Every report should carry enough to reproduce the decision:

- **Version** — output of `pkgsafe version`.
- **Mode** — offline (`--offline`) or connected. Offline relies on synced/cached
  advisory data; connected fetches registry + OSV metadata. The same package can
  decide differently between the two.
- **Ecosystem** — `npm`, `pypi`, `go`, or `cargo`. Coverage is uneven; see
  [known-limitations.md](known-limitations.md).
- **Decision** — the `allow` / `warn` / `block` PkgSafe returned.
- **Policy** — `--policy` file or signed policy pack, or "embedded default".

## Capture scan output with `--json`

The `--json` flag emits the stable scan contract — `decision`, `risk_score`,
`thresholds`, and the `reasons` array. Paste this rather than retyping the human
output; the rule IDs in `reasons` are what we triage against.

```bash
pkgsafe scan-npm-package some-package --version 1.2.3 --json
pkgsafe scan-lockfile ./package-lock.json --json
```

For offline reports, sync first so the result is reproducible:

```bash
pkgsafe update-db --ecosystem all
pkgsafe scan-npm-package some-package --offline --json
```

## Good report = fast fix

Minimal repro + exact version + mode + `--json` output. That is usually enough
to confirm and classify a false positive or false negative without a round trip.
