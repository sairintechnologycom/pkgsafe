# Enterprise Reporting + Governance Evidence Export Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement enterprise-ready report generation, evidence exporting, SIEM integration, and ServiceNow/Azure DevOps compatibility for PkgSafe.

**Architecture:** Create a new `internal/report` package to manage report models and formatting (Markdown, JSON, HTML, CSV, SIEM JSONL, ZIP). Create `internal/git` for repository metadata detection and `internal/audit` for reading and filtering audit logs. Add CLI subcommands to wire these features up.

**Tech Stack:** Go (Golang) standard library, `archive/zip` for evidence packaging, HTML/CSS for executive report rendering.

---

### Task 1: Git Metadata Detection
**Files:**
- Create: `internal/git/metadata.go`
- Test: `internal/git/metadata_test.go`

**Step 1: Write the failing test**
Create a test that verifies `DetectMetadata` extracts the root directory, redacts URL credentials/tokens, reads the current branch, commit SHA, dirty status, and tag.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/git/...`
Expected: Fail (package git doesn't exist yet)

**Step 3: Write minimal implementation**
Implement git command invocation and regex-based credential stripping in URL.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/git/...`
Expected: PASS

**Step 5: Commit**
`git add internal/git/ && git commit -m "feat: add git metadata detection with credential redaction"`

---

### Task 2: Audit Log Reader
**Files:**
- Create: `internal/audit/reader.go`
- Test: `internal/audit/reader_test.go`

**Step 1: Write the failing test**
Verify `ReadAuditLog` parses a JSONL file, filters by overrides/decisions, redacts tokens in commands, and computes allowed-by-policy and malware-attempted fields.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/audit/...`
Expected: Fail

**Step 3: Write minimal implementation**
Implement JSONL reader, user identification, and metadata inference from policy controls.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/audit/...`
Expected: PASS

**Step 5: Commit**
`git add internal/audit/ && git commit -m "feat: add audit log parser and filter"`

---

### Task 3: Report Models and Generator
**Files:**
- Create: `internal/report/model.go`
- Create: `internal/report/generator.go`
- Test: `internal/report/generator_test.go`

**Step 1: Write the failing test**
Verify report generator collects dependencies from npm and PyPI lockfiles, checks cache, loads policy metadata, exceptions, registry configs, and builds a comprehensive `RepositoryRiskReport` struct.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/report/...`
Expected: Fail

**Step 3: Write minimal implementation**
Define all structs matching the required schemas and implement the generator functions.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/report/...`
Expected: PASS

**Step 5: Commit**
`git add internal/report/ && git commit -m "feat: implement report models and data generator"`

---

### Task 4: Exporters (Markdown, JSON, HTML, CSV, SIEM, ServiceNow, Azure DevOps)
**Files:**
- Create: `internal/report/markdown.go`
- Create: `internal/report/json.go`
- Create: `internal/report/html.go`
- Create: `internal/report/csv.go`
- Create: `internal/report/siem.go`
- Create: `internal/report/servicenow.go`
- Create: `internal/report/azure_devops.go`

**Step 1: Write the failing test**
Verify all exporters generate expected schemas/contents (markdown table, valid JSON, self-contained HTML with styling, CSV columns, JSONL events, ServiceNow payload, Azure DevOps summary).

**Step 2: Run test to verify it fails**
Run: `go test ./internal/report/...` (including format tests)
Expected: Fail

**Step 3: Write minimal implementation**
Implement string/template generation for each format. Ensure no external CDNs are used in HTML, and no secrets/tokens are leaked in any output format.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/report/...`
Expected: PASS

**Step 5: Commit**
`git add internal/report/ && git commit -m "feat: add markdown, json, html, csv, siem, servicenow, devops report exporters"`

---

### Task 5: Evidence Pack ZIP Generation
**Files:**
- Create: `internal/report/evidence_pack.go`
- Test: `internal/report/evidence_pack_test.go`

**Step 1: Write the failing test**
Verify evidence pack builds a ZIP file with manifest.json containing checksums, all report types, and excludes secrets.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/report/...` (pack tests)
Expected: Fail

**Step 3: Write minimal implementation**
Write ZIP generation, SHA-256 manifest calculation, and files bundling.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/report/...`
Expected: PASS

**Step 5: Commit**
`git add internal/report/ && git commit -m "feat: add zip evidence pack creation with sha256 checksum manifest"`

---

### Task 6: CLI Integration (Subcommands and Flags)
**Files:**
- Modify: `cmd/pkgsafe/main.go`
- Create: `cmd/pkgsafe/report.go`
- Test: `cmd/pkgsafe/main_test.go`

**Step 1: Write the failing test**
Add command-line invocation tests for all the new report commands.

**Step 2: Run test to verify it fails**
Run: `go test ./cmd/pkgsafe/...`
Expected: Fail

**Step 3: Write minimal implementation**
Hook up the commands `report generate`, `report evidence-pack`, `report exceptions`, `report overrides`, `report policy`, `report ci`, `report siem-export`, `report servicenow-export`, `report azure-devops-export`.

**Step 4: Run test to verify it passes**
Run: `go test ./cmd/pkgsafe/...`
Expected: PASS

**Step 5: Commit**
`git add cmd/pkgsafe/ && git commit -m "feat: wire up report commands in Go CLI"`

---

### Task 7: GitHub Action + MCP Integration
**Files:**
- Modify: `action.yml`
- Modify: `internal/mcp/protocol.go`
- Modify: `internal/mcp/server.go`
- Create: `internal/mcp/report_tools.go`

**Step 1: Write the failing test**
Add tests to verify MCP tools `generate_governance_report`, `get_recent_package_decisions`, and `get_policy_evidence` return valid responses.

**Step 2: Run test to verify it fails**
Run: `go test ./internal/mcp/...`
Expected: Fail

**Step 3: Write minimal implementation**
Update `action.yml` inputs and update MCP tool list and tool handlers.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/mcp/...`
Expected: PASS

**Step 5: Commit**
`git add action.yml internal/mcp/ && git commit -m "feat: update github action and add mcp reporting tools"`
