# PkgSafe Full Product, Security, Architecture, and Commercial Readiness Review

Review date: 2026-07-11  
Reviewed commit: `df143fe6eec47d02632b757987c2babe14561981` (`v1.6.0-51-gdf143fe`)  
Review type: read-only product/security review; no product findings were fixed.

## 1. Executive Verdict

**Verdict: `NOT_READY`**

Overall production trust: **52/100**.

The three decisive reasons are:

1. Policy exceptions can downgrade registry-confusion/private-public-registry blocks because `ApplyEnterpriseControls` treats only malware, credential access, and selected strict-mode rules as non-overridable. This violates the stated hard-block invariant.
2. The public tree contains an implemented entitlement verifier and premium feature gates (`pkg/license`, `pkg/cli.RunConfig.Entitlement`) although the open-core document prohibits licensing enforcement and premium logic in public code; the boundary checker passes because its pattern only recognizes “license server,” not entitlement code.
3. The repository's own production-readiness command returns `BLOCKED`: zero real-repository validations, no trustworthy performance results, no locally verified signatures/provenance, and no isolated backend on the review host. npm/PyPI GA claims therefore exceed the available evidence.

The scanner, policy, MCP, archive-hardening, CI-output, and deterministic fixture foundations are substantial. They justify continued controlled alpha/private-beta evaluation after P0 correction, but not a trusted GA or external autonomous-agent install gate.

## 2. Current Product Behavior

The CLI dispatches repository, dependency-file, lockfile, and package scans to ecosystem parsers/scanners. Package scans resolve metadata/artifacts through registry clients, query local or online OSV intelligence, run static analyzers, compute a risk score, apply registry/trust/block/exception policy controls, and emit `allow`, `warn`, or `block`. `review_required` exists principally in agent dependency-diff/audit contracts, not as a consistently available core scan decision.

Behavior analysis defaults to `disabled`. `heuristic` invokes lifecycle commands on the host with a fake HOME, cleaned environment, and timeout; network denial is explicitly not enforced. `isolated` selects a Linux bubblewrap backend and does not silently fall back, but it was unavailable on this macOS host.

Pre-install enforcement exists through npm/pip/python interceptors, `npm-install`, generic `run`, shell shims, and MCP check tools. Native guarded installers are not provided for pnpm, Yarn, uv, Poetry, `go get`, or `cargo add`; their dependency files are partly scannable, but enforcement depends on external integration. The MCP check tools do not execute installs.

Evidence is distributed across scan JSON, CI JSON/SARIF/Markdown, reports, local audit history, SPDX release SBOM, and ZIP evidence packs. There is no single `package profile` command. `explain`/`explain-pypi`, package scan JSON, policy evidence, and audit records form a partial distributed profile, but confidence, unified provenance, stable evidence references, approvals, and alternative remediation are not consistently present together.

## 3. Implemented Feature Inventory

| Capability | Status | Evidence/qualification |
| --- | --- | --- |
| npm manifest/import inventory | Implemented | Deterministic corpus covers dependency groups, workspaces, scoped packages, imports/require/exports, dynamic-import reporting, duplicates, and malformed files. |
| npm lockfiles | Implemented, not production-proven | package-lock v1/v2 fixtures; parser supports current packages layout, Yarn and pnpm parsers. No independent real-repo accuracy evidence. |
| PyPI dependency files | Partial | requirements, pyproject, Poetry, uv, and Pipfile lock parsers exist; artifact static analysis covers wheel/sdist/setup/build metadata. Real-repo and false-block gates are absent. |
| Go | Partial/preview | go.mod parser, OSV, and some source rules exist; no demonstrated module ZIP/checksum/private-module/vendor depth. |
| Cargo | Partial/preview | Cargo.toml/Cargo.lock parsing and source rules exist; no demonstrated crates.io archive/checksum/yank/private-registry depth. |
| OSV | Implemented with degraded-state gaps | Local DB reported 260,056 records and offline-ready, but stale. Online validation had zero reachable packages. |
| Static malicious behavior | Implemented, incomplete | Broad rule catalog and explainable rule IDs; coverage is heuristic and corpus-small. Rule documentation is not complete per rule. |
| Typosquat/AI squatting | Partial | edit/name heuristics, popular alternatives, and AI-agent signals exist; repository/popularity/maintainer evidence is not a complete transparent identity profile. |
| Registry governance | Partial with P0 bypass | Private scope/prefix routing and redaction tests exist; exceptions can downgrade confusion/source blocks. |
| Policy engine | Functional with P0 bypass | Validation, explanation, thresholds, block/trust lists, scoped rules, expiry, and exceptions exist; non-overridable classes are incomplete. |
| Safe install | Partial | npm and pip intercept paths plus generic wrapper; no first-class equivalent for all requested managers. |
| Trusted package profile | Distributed/partial | No `package profile` command or single central object. |
| JSON/Markdown/SARIF | Implemented | CI readiness generated all three. |
| SPDX SBOM | Partial | Release SBOM is a minimal one-package Makefile document, not dependency scan SBOM evidence. CycloneDX not found. |
| Evidence ZIP | Implemented, unsigned OSS | Checksums/manifests exist; no OSS signature verification implementation for signed bundles/evidence. |
| GitHub Action | Functional but unhardened | Inputs are wired; third-party actions use mutable major tags, toolchain is `stable`, action builds from source, and entrypoint logs arguments. |
| MCP guardrail | Functional | 14 tools include required equivalents; stdio test passed. Go/Cargo package validation is not exposed by primary package tool schema. |
| Team evidence | Partial/local | Local GA/beta/evidence reports exist; `team-evidence` is a private gate/stub. |
| Enterprise services | Missing by design | Central policy, hosted history, approval workflow, SSO/RBAC, SIEM/ServiceNow/Azure DevOps are not public implementations. |

Misleading documentation includes npm and PyPI “GA” claims in `docs/install.md`, `docs/github-action.md`, `docs/README.md`, `docs/architecture.md`, and issue templates despite the product brief declaring npm primary GA and repository evidence showing zero real-repo production validation. `docs/roadmap.md` also contains stale “do not implement isolated behavior execution yet” wording while a Linux backend exists. `--help` is documented by convention but exits 1 as an unknown command.

## 4. Architecture Assessment

Major modules are dependency inventory (`internal/deps/*`), ecosystem analyzers/scanners, registry clients, OSV/database/bundles, risk/policy, interceptors, behavior runners, CI/output/reporting, MCP/API, audit/feedback, validation, and the importable CLI.

The main trust boundaries are registry HTTP/artifact extraction, local policy loading, host process execution, local database/bundle import, MCP stdio, package-manager execution, and evidence serialization. Positive controls include bounded extraction, path/link rejection, URL/token redaction, isolated MCP stdout, default-disabled behavior, strict install decisions, and stale/offline metadata.

Important bypasses/coupling:

- `risk.ApplyEnterpriseControls` conflates score blocks, hard blocks, trust, scoped policy, and exceptions. An exception can reduce any `BLOCK` to `WARN` unless `hasMalware` is true; registry-confusion and source-trust rules are not in that set.
- Offline selection and behavior selection are independent. A caller can request offline plus heuristic host execution, whose network mode is advisory only.
- `ApplyEnterpriseControls`, enterprise-named policy fields, entitlement code, and private feature dispatch are embedded in OSS core rather than isolated behind implementation-free interfaces.
- `pkg/cli/main.go` is a very large dispatcher/orchestrator, increasing cross-command drift risk.
- Decision vocabulary differs: scan paths primarily return allow/warn/block while agent diff paths add review-required.
- A single package trust object is absent, so evidence contracts drift across CLI, CI, MCP, and reports.

## 5. Developer Workflow Assessment

Installation is a static binary with install scripts and release verification documentation. The CLI exposes a broad command set, but global `--help` fails, command-specific help is inconsistent, and long readiness operations provide no progress for roughly four minutes. The first offline scan is usable but can reuse old cached `scanned_at` values without an obvious top-level confidence warning. False-positive issue templates and feedback bundles exist. Baseline/diff support exists in CI and MCP but suppression/approval UX is policy-file centric.

The product is usable by motivated security-aware developers, not yet by an average developer without specialist context. The absence of a unified profile/explanation command, uneven package-manager interception, stale intelligence warnings in decisions, and incomplete alternatives/remediation are the main adoption friction.

## 6. Security and AppSec Assessment

AppSec teams can define and validate local policy, configure registries/private scopes, inspect reasons/rule IDs, manage dated exceptions, emit SARIF and evidence packs, and query local audit history. Expired exceptions are ignored. Malformed policy tests and readiness checks fail safely.

They cannot yet rely on a formally enumerated hard-block taxonomy, signed local policy delivery, tamper-evident audit/evidence history, complete package provenance, organization assignment, central approvals, or real-corpus accuracy. Release provenance is configured separately from scanned-package provenance; the latter is incomplete and must not inherit release claims.

## 7. AI-Agent and Vibe-Coding Assessment

MCP implements `check_package`, `check_install_command`, `review_dependency_diff`, `explain_policy_decision`, `record_agent_decision`, `suggest_safe_alternative`, guidance, governance, and compatibility tools. Responses include decisions, reasons, risk, evidence/guidance fields across tools; the exact complete contract is not uniform. The rollout suite passed JSON-RPC-only stdout, structured errors, `BLOCK` no-install, and `WARN` human-approval behavior.

Diff review recognizes package.json/npm locks/pnpm/Yarn, requirements/pyproject/Poetry/uv, go.mod, and Cargo manifests/locks. Pipfile locks are parsed elsewhere but absent from the MCP diff supported-file map. Detection is file-parser based; lifecycle introduction, typosquat replacement, and registry-source changes are not comprehensively demonstrated end to end.

Codex, Claude Code, Gemini CLI, Cursor, and Copilot integration docs exist, but enforcement depends on those agents actually invoking MCP/shims. There is no universal interception of recommendations or commits. Because policy hard blocks are bypassable by exceptions and Go/Cargo are not primary MCP package ecosystems, autonomous use should remain advisory/gated.

## 8. Ecosystem Maturity Matrix

| Ecosystem | Assigned maturity | Reason |
| --- | --- | --- |
| npm | `PUBLIC_BETA` | Strongest parser/scanner, lifecycle/static analysis, registry, OSV, CI/MCP, and 30-fixture corpus. Zero real-repo run in current readiness evidence and a hard-block policy bypass prevent GA trust. |
| PyPI | `PUBLIC_BETA` | Broad file/artifact static coverage exists, but 10/10 live benchmark packages were unreachable and 10/10 offline package entries were skipped; no qualifying real-repo/corpus false-block evidence. Public GA claims are premature. |
| Go | `PREVIEW` | go.mod inventory/OSV and limited source rules; missing demonstrated artifact/checksum/vendor/private-module and behavior depth. |
| Cargo | `PREVIEW` | manifest/lock inventory/OSV and limited static rules; missing demonstrated crate archive/checksum/yank/build/proc-macro/private registry depth. |

## 9. Security Invariant Results

| # | Invariant | Result | Evidence |
| ---: | --- | --- | --- |
| 1 | BLOCK package never executes | PASS (tested scope) | MCP and rollout tests report blocked fixture behavior not executed. |
| 2 | Heuristic not described as isolated | PASS | Code/docs clearly label host execution; action input is honest. |
| 3 | Private package never public-falls-back | PASS routing test / FAIL policy invariant | Routing readiness passes, but an active exception can downgrade the resulting registry-confusion block. |
| 4 | No secret/token output | PASS (fixture scope) | Rollout checked JSON, SARIF, Markdown, HTML, CSV, and evidence ZIP. |
| 5 | Offline performs no network | FAIL (code path) | Offline does not forbid heuristic behavior; heuristic `network_mode=disabled` is explicitly unenforced. Registry/OSV offline paths passed. |
| 6 | MCP stdout JSON-RPC only | PASS | Rollout stdio gate passed. |
| 7 | Agent cannot override BLOCK | PASS (tested scope) | Agent guidance/install tests passed; policy exception bypass remains upstream risk. |
| 8 | WARN never auto-installs in agent mode | PASS | Rollout enforcement gate passed. |
| 9 | Trust cannot bypass hard blocks | PARTIAL | Malware/credential tests pass; hard-block taxonomy is incomplete. |
| 10 | Expired exception ineffective | PASS | `FindActiveException` skips expired entries; validation fixture exists. |
| 11 | Invalid policy rejected | PASS | Readiness malformed-input gate and invalid fixtures. |
| 12 | Tampered bundle rejected | PASS checksum scope | Bundle checksum/DB hash tests pass; signed OSS bundles are unsupported rather than verified. |
| 13 | Archive traversal rejected | PASS | Rollout exercised traversal, absolute path, links, bombs, malformed archives. |
| 14 | Malformed package input does not crash | PASS | Corpus/readiness malformed fixtures passed. |
| 15 | Check parser does not execute input | PASS (tested scope) | Interceptor/parser separation and rollout install gate; no broad shell MCP tool. |
| 16 | No public premium implementation | FAIL | Public entitlement verifier, feature lists/gates, and enterprise dispatch code contradict boundary document. |

## 10. Open-Core Boundary Assessment

`make check-public-boundary` passes, and a `/tmp` negative fixture containing “premium implementation” correctly fails. The test is insufficient: it is a keyword scan, excludes several paths, and allows licensing/entitlement implementation because its license pattern is only “license server.” Public `pkg/license/license.go`, `RunConfig.Entitlement`, enterprise feature gates/tests, and private command dispatch are implementation rather than a minimal interface. This is a P0 against the required boundary, even though no signing key, customer data, hosted backend, SSO/RBAC, or private feed was found.

## 11. Test and Evidence Results

| Command | Result |
| --- | --- |
| `go run ./cmd/pkgsafe --help` | FAIL: usage printed, then unknown command, exit 1 |
| `gofmt -l .` | FAIL quality gate: 12 files listed (read-only equivalent used to avoid review mutation) |
| `go test ./...` | PASS; 27 tested packages plus packages with no tests |
| `go test -race ./...` | PASS |
| `go vet ./...` | PASS |
| `make build` | PASS |
| `make package` | PASS; cross-platform binaries/checksums/minimal SPDX generated locally |
| `make check-public-boundary` | PASS, but false-negative described above |
| boundary negative fixture in `/tmp` | PASS: script exited 1 |
| `pkgsafe test corpus --json` | PASS: 30/30 deterministic fixtures |
| `pkgsafe test benchmark --json --offline` | Exit 0; only 1/25 packages scanned, 24 skipped, 0 real repos |
| `pkgsafe test rollout-readiness --json` | Exit 0, `PRIVATE_BETA_READY`; synthetic/security gates passed |
| `pkgsafe test production-readiness --json` | Exit 1, `BLOCKED` |
| `pkgsafe db status --json` | PASS; 260,056 vulnerability records, stale, offline-ready |
| `pkgsafe policy validate default-policy.yaml` | PASS |
| `pkgsafe inventory . --json` | PASS; also inventories test/fixture/generated editor files when run at repository root |
| `pkgsafe scan . --offline --json` | PASS using cached Go results; behavior disabled |

Unit event counting observed 389 passing named test events and zero skipped named tests; the authoritative package command exited 0. No connected package benchmark succeeded because network was unavailable in the validation environment. No Linux bubblewrap runtime test was possible on macOS. No signed release artifact/provenance verification was completed. The configured “real repositories” are 15 local synthetic fixture directories (11 npm, 3 PyPI, 1 mixed), not external repositories; the executed run counted zero real repositories.

## 12. Prioritized Findings

| ID | Priority | Finding/evidence | Impact | Recommended fix and test | Loop | Destination |
| --- | --- | --- | --- | --- | --- | --- |
| PSR-001 | P0 | `internal/risk/policy_controls.go`: exceptions downgrade registry-confusion/private-source blocks | Dependency confusion can become WARN | Define non-overridable rule metadata; apply before exceptions; table tests for trust/exception/agent/modes | Hard-block invariants | OSS |
| PSR-002 | P0 | `pkg/license`, `pkg/cli/main.go`, enterprise gates in public tree; boundary script passes | Violates open-core promise/public premium invariant | Move implementation/tests to private repo; retain minimal interfaces; structural boundary test | Open-core correction | OSS + private |
| PSR-003 | P0 | Offline and behavior modes combine; heuristic network denial unenforced | “Offline” can execute code capable of networking | Reject heuristic in offline or enforce isolated no-network; integration test with local listener/DNS trap | Offline semantics | OSS |
| PSR-004 | P1 | Production readiness: zero real repos, timings absent, live packages unreachable | GA accuracy/performance unsupported | Curate reproducible external corpus; record failures/false decisions/artifacts | Real-corpus evidence | OSS |
| PSR-005 | P1 | npm/PyPI GA claims conflict with evidence and declared npm-first posture | Misleading adoption claim | Gate maturity labels from evidence; claim audit test | Claims integrity | OSS |
| PSR-006 | P1 | 24 offline cache misses counted `passed:true` and aggregate pass/candidate | False readiness signal | Skips must not count passed; enforce minimum executed sample | Benchmark semantics | OSS |
| PSR-007 | P1 | No unified trust profile/confidence/evidence contract | Inconsistent decisions/audit | Introduce shared package profile schema and compatibility tests | Trust object | OSS |
| PSR-008 | P1 | Minimal release-only SPDX; no scan dependency SBOM/provenance unity | Weak auditor evidence | Generate dependency SPDX with hashes/sources; validate schema | Evidence model | OSS |
| PSR-009 | P1 | Action dependencies use mutable tags and stable Go | CI supply-chain drift | Pin actions by SHA and Go version; action integration test | CI hardening | OSS |
| PSR-010 | P1 | Public signed intelligence verification unavailable; evidence packs not signed | Air-gap tamper/audit gap | Define OSS signature verification interface/format; tamper tests | Signed evidence | OSS interface/private key ops |
| PSR-011 | P2 | Global `--help` exits 1 | Poor first experience | Treat help flags as success; CLI golden tests | CLI polish | OSS |
| PSR-012 | P2 | First-class interception absent for pnpm/Yarn/uv/Poetry/Go/Cargo | Agent/manager bypass | Add parsers/wrappers only after core hardening; injection matrix | Manager coverage | OSS |
| PSR-013 | P2 | 12 files are not gofmt-clean | Contributor/release quality | Format in implementation loop; CI gofmt gate | Quality | OSS |
| PSR-014 | P2 | Long readiness commands have no progress | Operational ambiguity | stderr progress/events; JSON stdout unchanged | DX | OSS |
| PSR-015 | P2 | PyPI/Go/Cargo evidence shallow; Pipfile absent in MCP diff map | Coverage gaps | Ecosystem-specific corpora and diff fixtures | Ecosystem depth | OSS |
| PSR-016 | P3 | No central signed policy/history/approvals/retention/RBAC/exporters | Enterprise sale incomplete | Private services consuming stable OSS interfaces | Enterprise platform | Private enterprise |
| PSR-017 | P3 | No commercial package-trust history/dashboard | Limited Team/Business value | Hosted evidence/search/comparison after OSS trust schema | Commercial evidence | Private enterprise |
| PSR-018 | P4 | CycloneDX, broader IDE/package-manager/ecosystem depth absent | Future reach | Add after trust and corpus gates | Expansion | OSS/interface as appropriate |

## 13. Scores and Monetization Readiness

| Area | /5 | Explanation |
| --- | ---: | --- |
| npm scanner | 3 | Functional, broad fixtures; no qualifying real-corpus/GA proof. |
| PyPI scanner | 3 | Good static depth; insufficient live/corpus evidence. |
| Go scanner | 2 | Metadata/OSV and limited rules only. |
| Cargo scanner | 2 | Metadata/OSV and limited rules only. |
| dependency inventory | 3 | Strong deterministic coverage; repo-root scope/noise and real recall unproven. |
| vulnerability intelligence | 3 | Large offline DB and update/bundle paths; stale/live-degraded confidence gaps. |
| malicious-package detection | 3 | Explainable broad rules; limited corpus/false-positive proof. |
| typosquat detection | 2 | Useful heuristics, incomplete identity evidence. |
| registry governance | 2 | Routing controls exist; exception hard-block bypass. |
| policy engine | 2 | Rich local engine; hard-block precedence defect. |
| evidence and reports | 3 | Many formats/packs; fragmented and unsigned. |
| SBOM and provenance | 2 | Minimal release SPDX, configured build provenance, incomplete package provenance. |
| GitHub Action | 3 | Functional outputs; mutable dependencies and source build. |
| MCP and agent guardrail | 3 | Broad tool set and safe stdio; enforcement remains opt-in and contract fragmented. |
| offline support | 2 | DB/bundles work; behavior/network semantic violation. |
| behavior analysis | 3 | Honest default/modes and Linux backend; heuristic is hazardous and host-unverified isolation here. |
| developer experience | 3 | Broad CLI/docs; help, progress, remediation, manager gaps. |
| AppSec experience | 3 | Local policy/evidence strong; hard-block/audit/provenance gaps. |
| reliability and performance | 2 | Tests/race pass; no trustworthy real-repo timing. |
| OSS/Enterprise boundary | 1 | Documented boundary contradicted by public entitlement implementation. |
| documentation accuracy | 2 | Good safety caveats, inaccurate maturity and stale roadmap claims. |
| release engineering | 3 | Cross-build/checksum/SBOM/signing config; local signed provenance unverified. |
| monetization readiness | 2 | OSS foundation exists; trust blockers and premium platform absent. |

Aggregate scores:

- Developer readiness: **62/100**
- AppSec readiness: **59/100**
- AI-agent readiness: **64/100**
- Enterprise readiness: **35/100**
- Monetization readiness: **31/100**
- Overall production trust: **52/100**

PkgSafe Team is not commercially ready until hard-block semantics, evidence schema, and real-repo validation are credible. Business additionally needs signed policy/evidence history and registry templates. Enterprise needs private central policy, approvals, retention/search, RBAC/SSO, audit history, and exporters. Pricing can be designed independently, but product capability does not yet support a strong enterprise trust claim.

## 14. Recommended Loop Roadmap

Only one loop should be active: **Hard-block invariants and offline semantics**.

```text
Feature Spec
  Define non-overridable rule classes and strict offline execution semantics
  ↓
Build Loop
  Centralize precedence; prohibit offline host behavior; preserve explicit decisions
  ↓
Validation Loop
  Exception/trust/agent/mode matrix plus network-trap and BLOCK-no-exec tests
  ↓
Review Loop
  Independent security review of every decision and execution entry point
  ↓
Evidence Loop
  Publish deterministic invariant results and sanitized artifacts
  ↓
Learning Loop
  Analyze false blocks and bypass attempts before selecting the next loop
```

After that loop closes, execute sequentially: open-core boundary correction; benchmark/readiness truthfulness; real-repository npm corpus; unified trust profile/evidence; CI/release hardening; then PyPI maturity. Do not expand ecosystems or premium services in parallel with unresolved trust semantics.

## 15. Final Recommendation

Safe to release today: source snapshots or clearly labelled internal/experimental builds for local static scanning with behavior disabled, accompanied by explicit limitations. Keep npm and PyPI at public beta at most; keep Go/Cargo preview; keep isolated behavior experimental/Linux-only; do not offer heuristic behavior as an offline or security boundary.

Fix PSR-001, PSR-002, and PSR-003 first. Hard-block/offline/boundary corrections belong in OSS; entitlement implementation and all hosted policy/evidence/approval/RBAC/export services belong in private Enterprise. External autonomous-agent pilots should not begin. A small supervised design-partner pilot may begin only after P0 closure, with behavior disabled, no auto-install on WARN/REVIEW_REQUIRED, and evidence retained.
