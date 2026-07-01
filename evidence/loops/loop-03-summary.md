## PkgSafe Dependency Gate

**Decision:** BLOCK  
**Mode:** WARN  
**Fail On:** BLOCK  
**Workflow Result:** fails on BLOCK  
**Ecosystem:** npm  
**Lockfile:** testdata/ci-scenarios/warn/package-lock.json  
**Changed Only:** true  
**Baseline:** testdata/ci-scenarios/safe/package-lock.json (file)  
**Packages Scanned:** 1  

### Counts

| Allow | Warn | Block | Unknown | Vulnerabilities |
|---:|---:|---:|---:|---:|
| 0 | 0 | 1 | 0 | 2 |

**Vulnerabilities:** 2  
- high: 1
- medium: 1

### Warn / Block Findings

| Package | Version | Decision | Score | Top Reason |
|---|---:|---|---:|---|
| esbuild | 0.19.0 | BLOCK | 95 | Package version has a high severity advisory |

### Vulnerabilities

| Package | Version | Advisory | Severity | Fixed Versions |
|---|---:|---|---|---|
| esbuild | 0.19.0 | GHSA-67mh-4wv8-2f99 | medium | 0.25.0 |
| esbuild | 0.19.0 | GHSA-gv7w-rqvm-qjhr | high | 0.28.1 |

### Fixed Version Recommendations

- esbuild@0.19.0 -> 0.25.0
- esbuild@0.19.0 -> 0.28.1

### Recommended Action

Remove or replace blocked dependencies before merging. With `fail-on: block`, this workflow fails for BLOCK findings.

