# Production / GA checklist

Use this when promoting PkgSafe from public beta to a production GA claim.

Automated source of truth:

```bash
scripts/verify-ga-release.sh vX.Y.Z
# or: pkgsafe test production-readiness --json
# with PKGSAFE_RELEASE_ARTIFACT_DIR pointing at a full verified release download
```

`ga_ready` and `production_ready` are true only when **all** automated GA blockers are cleared.

## Stages

| Stage | Meaning |
|-------|---------|
| `PRIVATE_BETA_READY` | Foundation tests, corpus, policy, docs |
| `PUBLIC_BETA_READY` | + online accuracy, action assets, real-repo evidence |
| `PRODUCTION_GA_READY` | + local cosign + checksum + SBOM + provenance verification |

## Automated GA requirements

| Gate | Threshold |
|------|-----------|
| Real-repo validations | ≥ 15, 100% pass |
| npm real repos | ≥ 5 |
| False blocks / crashes | 0 |
| Critical detection | 100% |
| Known-good false block rate | 0% |
| Scan timing | reported + trustworthy |
| Behavior analysis default | `disabled` |
| Online benchmark | pass |
| Release checksums | verified against local artifacts |
| Cosign signature | verified locally (`checksums.txt`) |
| SBOM | present and parseable SPDX JSON |
| Build provenance | `gh attestation verify` succeeds for a release archive |

## Manual release steps

1. **Main is green** — unit tests, CI, no open P0 security issues.
2. **Docs match maturity** — README/install/action language for npm (and PyPI if claimed); Go/Cargo still preview unless evidence exists.
3. **Tag** a release (`vX.Y.Z` for stable Latest, or keep `*-beta.*` if still pre-release).
4. **Release workflow** succeeds (GoReleaser, cosign, SBOM, attestations).
5. **Run** `scripts/verify-ga-release.sh vX.Y.Z` on a clean host with `gh` + `cosign`.
6. **Record evidence** under `evidence/releases/vX.Y.Z/` (readiness JSON + short summary).
7. **Homebrew / install.sh** smoke-tested on macOS and Linux.
8. **Customer playbook** for production:
   - Intercept: `npm` / `pnpm` / `yarn` / `pip` / `uv` via shims
   - Agents: MCP check tools; WARN requires human
   - CI main/release: `pkgsafe ci scan --full --fail-on block`
   - OSV: document update/bundle cadence

## Production usage (after GA)

| Do | Don't |
|----|--------|
| Use as pre-install firewall | Treat as full SCA replacement |
| `--mode block` in automation | Rely on default warn-mode scan exit 0 |
| `--full` on main/release CI | Assume changed-only ALLOW = clean monorepo |
| Keep behavior analysis disabled by default | Enable heuristic host execution in CI without isolation |

## Not required for OSS GA

- macOS isolated behavior backend
- Enterprise SSO / central policy / hosted evidence
- Every package manager under the sun (Poetry/conda remain out of intercept scope)

## Related

- [Release verification](release-verification.md)
- [Release integrity](release-integrity.md)
- [Known limitations](known-limitations.md)
- [CI/CD](ci-cd.md)
