# Loop Engineering Roadmap

PkgSafe moves forward one validated loop at a time. Do not implement the full
roadmap at once.

## Operating Model

Each loop follows this sequence:

```text
Feature Spec
Build Loop
Validation Loop
Review Loop
Evidence Loop
Learning Loop
```

## Global Rules

- Implement only one loop at a time.
- Start with the first incomplete loop.
- Inspect the repository before building and enhance existing work instead of
  duplicating it.
- Do not start the next loop until the current loop passes validation and
  evidence is recorded.
- Keep PkgSafe npm-first unless a loop explicitly promotes another ecosystem.
- Do not introduce SaaS, billing, SSO, or hosted services unless the loop
  explicitly asks for it.
- Keep behavior analysis disabled by default.
- Do not describe heuristic behavior analysis as sandboxing or secure
  containment.
- Preserve GA release verification and readiness behavior.

## Loop Summary

1. v1.0.1 Post-GA Stabilization: install docs, release verification docs,
   GitHub Action examples, feedback docs, false-positive/scanner-bug templates,
   and scheduled OSV cache warmup.
2. Team Evidence Pack: local-first multi-repo team evidence ZIP.
3. GitHub Action Pro Foundation: better PR summaries, changed dependency scans,
   baseline support, outputs, and examples.
4. False-Positive Feedback Workflow: structured local feedback generation with
   sanitized JSON/Markdown and stable finding fingerprints.
5. Enterprise Policy Pack Foundation: policy validation, explanation, tests,
   pack creation, and verification.
6. Private Registry Governance: dependency confusion protection, private scope
   routing, no-public-fallback enforcement, and token redaction evidence.
7. MCP / AI Agent Guardrail Pro Foundation: deterministic agent-facing install
   validation, explanations, alternatives, and audit events.
8. PyPI Production Depth: improve Python dependency and artifact coverage while
   keeping PyPI preview until readiness gates pass.
9. Offline Intelligence Bundle: signed offline OSV/threat DB export, import,
   verification, and freshness reporting.
10. Isolated Behavior Backend: real opt-in Linux isolation backend with network
    disabled by default and clean teardown.

## Loop Execution Protocol

For each loop:

1. Create or update a tracking issue.
2. Create a `loop-XX-short-name` branch.
3. Implement only that loop.
4. Run full validation.
5. Generate loop evidence.
6. Summarize what was built, reused, deferred, tested, and generated.
7. Stop and wait for review before starting the next loop.
