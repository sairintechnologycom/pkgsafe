# Loop 05 - Unified Trusted Package Profile

Date: 2026-07-12  
Status: accepted

## Feature result

Loop 05 introduces a canonical `package_profile` object shared by the main
package-assessment surfaces:

- `internal/types.ScanResult`
- CI findings
- MCP package-check and policy-explain responses
- `pkgsafe sandbox profile --json`

The profile schema captures:

- schema version
- package identity
- decision
- risk score
- confidence
- hard blocks
- top reasons
- vulnerabilities
- behavior signals
- identity risk
- registry risk
- provenance
- policy context
- remediation
- evidence ID

## Implementation notes

The canonical profile is assembled in `internal/risk.BuildPackageProfile` and
attached at the end of `internal/risk.ApplyPolicyControls`.

Key fields now available on scan results:

- `package_profile.schema_version`
- `package_profile.package.{ecosystem,name,requested_version,resolved_version,registry}`
- `package_profile.decision`
- `package_profile.risk_score`
- `package_profile.confidence`
- `package_profile.hard_blocks`
- `package_profile.top_reasons`
- `package_profile.behavior_signals`
- `package_profile.provenance`
- `package_profile.policy`
- `package_profile.evidence_id`

The MCP tool responses now include the same `package_profile` payload instead of
only ad hoc decision strings, scores, and top-reason lists.

## Validation evidence

Focused unit coverage:

```text
go test ./internal/risk
PASS

go test ./internal/mcp
PASS

go test ./internal/ci
PASS
```

Repo-wide validation after the schema change:

```text
go test ./...
PASS

go test -race ./...
PASS

go vet ./...
PASS
```

Direct CLI evidence:

```text
go run ./cmd/pkgsafe sandbox profile axios --version 1.6.0 --json
```

The JSON output now contains the canonical profile object, including:

- `schema_version: "1.0"`
- `package.ecosystem: "npm"`
- `package.name: "axios"`
- `decision: "block"`
- `risk_score: 100`
- `confidence: "high"`
- `evidence_id: "profile-..."`
- `policy.mode: "warn"`
- `behavior_signals[0].mode: "disabled"`

## Observed behavior

The profile is now a first-class machine-readable object instead of a command-
specific shape. It can be consumed directly by agents and CI parsers without
reconstructing package identity, decision, risk, and evidence metadata from
separate payloads.

The sandbox-profile CLI text output still retains a human-readable summary, but
its JSON mode now emits the canonical package profile.

## Completion gate

| Gate | State |
| --- | --- |
| PSR-007 | CLOSED |
| canonical schema used across primary outputs | PASS |
| schema compatibility tests | PASS |
| decision drift tests | PASS |
