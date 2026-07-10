# Agent skills and slash commands

Reusable prompts that map agent “slash commands” to PkgSafe MCP tools. Use with
Claude Code, Codex, Cursor, or any agent that supports custom commands/skills.

## Commands

### `/pkgsafe-check-deps`

Scan project manifests for policy issues.

```text
Locate dependency manifests (package.json, requirements.txt, poetry.lock,
go.mod, Cargo.toml, etc.). Use check_package / validate_package_install (or
score_lockfile when a lockfile exists). Summarize: package, version, decision
(ALLOW/WARN/BLOCK), top reasons.
```

### `/pkgsafe-review-pr`

Review dependency changes vs base branch.

```text
Identify base branch (e.g. main) and current head. Call review_dependency_diff
with the right refs. Report new deps, warn count, block count, and each changed
package with risk. If anything is BLOCK, say the PR needs human security review.
```

### `/pkgsafe-explain-risk`

Explain one package decision.

```text
Call explain_policy_decision or explain_package_risk for the given package
(e.g. npm:lodash@4.17.21). List violated rules, risk score, and remediations
(including suggest_safe_alternative when useful).
```

### `/pkgsafe-fix-deps`

Propose safer replacements for blocked packages.

```text
For each BLOCK/WARN package, use suggest_safe_alternative and check_package.
Propose manifest edits. Only install after ALLOW (or human approval on WARN).
Re-scan after changes.
```

## Tips

- Always honor **BLOCK**; never auto-install on **WARN**.
- Prefer MCP tools over raw shell install.
- Pair with the [GitHub Action](../github-action.md) for hard CI gates.

## Related

- [Claude Code](claude-code.md)
- [Codex](codex.md)
- [Generic MCP](../mcp-generic-client.md)
- [AI agent install safety](../ai-agent-install-safety.md)
