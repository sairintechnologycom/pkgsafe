# v1.7.0-beta.9 GA verification (local)

**Date:** 2026-07-13  
**Tag:** `v1.7.0-beta.9`  
**Commit:** `c336499`  
**Host:** macOS arm64, cosign + gh CLI  

## Result

```text
final_status: PRODUCTION_GA_READY
ga_ready: true
production_ready: true
ga_blockers: []
real_repo_validation_count: 15/15
signing_verified: true
provenance_verified: true
checksums_status: verified
sbom_status: present
```

Full machine report: [production-readiness-ga.json](./production-readiness-ga.json)

## Ritual performed

1. Downloaded all release assets for `v1.7.0-beta.9` into `dist/ga-verify/`  
   (`gh release download v1.7.0-beta.9`).
2. `shasum -a 256 -c checksums.txt` → **12/12 OK**.
3. `cosign verify-blob` on `checksums.txt` → **Verified OK**.
4. `gh attestation verify pkgsafe_1.7.0-beta.9_darwin_arm64.tar.gz \
     --repo sairintechnologycom/pkgsafe \
     --signer-workflow github.com/sairintechnologycom/pkgsafe/.github/workflows/release.yml`  
   → **exit 0**.
5. `PKGSAFE_RELEASE_ARTIFACT_DIR=$PWD/dist/ga-verify \
     PKGSAFE_GITHUB_REPO=sairintechnologycom/pkgsafe \
     ./dist/pkgsafe test production-readiness --json`  
   → **PRODUCTION_GA_READY**.

Repeatable automation:

```bash
scripts/verify-ga-release.sh v1.7.0-beta.9
```

## Notes

- Artifacts under `dist/` are gitignored; only this evidence JSON/summary is committed.
- Tag remains a **GitHub pre-release** (`*-beta.*`). Automated gate readiness does not
  by itself publish a stable “Latest” channel; cut a non-beta tag when marketing GA.
- Isolated behavior backend was unavailable on this host (macOS); not a GA blocker.
