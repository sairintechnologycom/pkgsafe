# Loop 8 — npm Production Qualification

Date: 2026-07-12

## Scope

- Qualified the npm readiness gate against the validated external repository corpus.
- Confirmed the gate no longer reports synthetic zero-repo evidence when provided a real-repo list.
- Captured the remaining GA blockers as release-verification gaps, not benchmark noise.

## Validation command

```bash
env GOCACHE=/private/tmp/pkgsafe-gocache go run ./cmd/pkgsafe test production-readiness --json --repo-list /private/tmp/pkgsafe-loop4/real-repos.external.with-artifacts.json
```

## Result

- Final status: `PUBLIC_BETA_READY`
- Pass: `true`
- Real repo validations: `15 / 15`
- npm repos: `9`
- PyPI repos: `6`
- False blocks: `0`
- Scanner crashes: `0`
- Average scan duration: `1186ms`
- p95 scan duration: `1646ms`

## Remaining GA blockers

- Signed release artifacts not verified locally
- Build provenance not verified locally

## Interpretation

This is evidence that npm qualification is now strong enough for public beta posture, but not enough to promote to production trust without local release-verification evidence.
