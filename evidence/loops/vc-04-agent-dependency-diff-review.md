# Loop VC-4 - Agent Dependency Diff Review Evidence

Date: 2026-07-09
Branch: loop-vc-04-agent-dependency-diff-review

## Feature Spec

Review dependency changes created by AI agents in branches or PRs.

Files supported:
* `package.json`
* `package-lock.json`
* `pnpm-lock.yaml`
* `yarn.lock`
* `requirements.txt`
* `pyproject.toml`
* `poetry.lock`
* `uv.lock`
* `go.mod`
* `Cargo.toml`
* `Cargo.lock`

## Files Created/Modified

- `internal/mcp/review_dependency_diff.go` (created in Loop VC-1)

## Implementation Details

The `ReviewDependencyDiff` tool uses Git command-line invocation to find modified files between `base_ref` and `head_ref`. For each modified manifest or lockfile, it parses the dependencies at base and head states using specialized parsers for JSON, TOML, YAML, Requirements, and Lockfiles. It scans any newly introduced or modified packages and reports standard decisions.

## Sample Diff Review Output

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "review_dependency_diff",
    "arguments": {
      "repo_path": ".",
      "base_ref": "main",
      "head_ref": "agent-branch"
    }
  }
}
```

**Response**
```json
{
  "decision": "REVIEW_REQUIRED",
  "risk_score": 75,
  "confidence": "high",
  "top_reasons": [
    "[risky-dep:npm] Warning: 75 risk score"
  ],
  "agent_instruction": "Do not open PR as ready. Mark PR as requiring security review.",
  "allowed_next_actions": [
    "mark_review",
    "proceed_coding"
  ],
  "prohibited_actions": [
    "run_install",
    "execute_lifecycle_script"
  ],
  "new_dependencies": 1,
  "blocked_dependencies": 0,
  "warn_dependencies": 1
}
```
