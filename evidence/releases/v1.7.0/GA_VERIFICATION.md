# v1.7.0 GA verification

**Date:** 2026-07-13  
**Tag:** `v1.7.0`  
**Commit:** `6af3119`  
**Command:** `scripts/verify-ga-release.sh v1.7.0`

## Result

```text
final_status=PRODUCTION_GA_READY
ga_ready=True
production_ready=True
ga_blockers=[]
signing_verified=True
provenance_verified=True
real_repos=15/15
```

## Steps

1. Download all release assets for `v1.7.0`
2. `shasum -a 256 -c checksums.txt` → 12/12 OK
3. `cosign verify-blob` on checksums.txt → Verified OK
4. `gh attestation verify` on darwin_arm64 archive → exit 0
5. `pkgsafe test production-readiness` with `PKGSAFE_RELEASE_ARTIFACT_DIR` → PRODUCTION_GA_READY

Machine report: [production-readiness-ga.json](./production-readiness-ga.json)
