# PkgSafe Agent Skills & Slash-Command Packs

To make package safety checks intuitive, developers can configure vibe coding agents (like Claude Code, Codex, and Cursor) with reusable slash commands. These commands map directly to PkgSafe MCP tools and CLI actions.

## 1. Slash Command Definitions

### `/pkgsafe-check-deps`
*   **Purpose:** Scan all project dependency manifests for policy violations.
*   **Agent Prompt Template:**
    ```text
    Locate all dependency manifest files (e.g., package.json, requirements.txt, go.mod, Cargo.toml) in the project. Call the check_install_command tool or scan the individual packages using check_package to verify their policy alignment. Present a summary table showing: Package, Version, Decision (ALLOW/WARN/BLOCK), and Top Reasons.
    ```

### `/pkgsafe-review-pr`
*   **Purpose:** Review dependency modifications between the base branch and the current head branch.
*   **Agent Prompt Template:**
    ```text
    Determine the base branch (e.g., main) and the current head branch. Call the review_dependency_diff tool with the appropriate refs. Present the new dependencies count, warn count, blocked count, and a list of all modified packages with their risk status. If any package is blocked, advise that the PR should remain as a draft or requires human security review.
    ```

### `/pkgsafe-explain-risk`
*   **Purpose:** Explains why a specific package was blocked and provides remediation paths.
*   **Agent Prompt Template:**
    ```text
    Use the explain_policy_decision tool for the package specified (e.g., npm:lodash@1.0.0). Output the specific policy rules violated, the risk score, and all provided remediation instructions (e.g., suggesting a secure internal mirror or package alternatives).
    ```

### `/pkgsafe-fix-deps`
*   **Purpose:** Locate safe alternatives and automatically replace a blocked package.
*   **Agent Prompt Template:**
    ```text
    For the package that is blocked or flagged, look up safe alternatives using check_package or suggest_safe_alternative. Locate the manifest file where the blocked package is defined, replace it with the chosen safe alternative, run the appropriate dependency update command (e.g., npm install), and verify that the manifest/lockfile is updated successfully.
    ```

---

## 2. Integration Prompts for Specific Agents

### Claude Code Custom Instructions

Add the following to your custom instructions in Claude Code (`~/.claude/config.json`):

```json
{
  "customInstructions": "You are equipped with PkgSafe MCP tools. Implement the following slash commands:\n- /pkgsafe-check-deps: Scan all manifests and summarize package risks.\n- /pkgsafe-review-pr: Review dependency changes between main and your branch.\n- /pkgsafe-explain-risk <pkg>: Explain policy violations for a package.\n- /pkgsafe-fix-deps <pkg>: Replace a blocked package with a safe alternative."
}
```

### Codex System Prompt Override

Add the following instructions to your Codex system prompt:

```text
As a Codex coding agent, you must respect the following package safety slash commands:
- /pkgsafe-check-deps: Locate manifest files, check package safety, and present a risk summary table.
- /pkgsafe-review-pr: Compare dependency files against base branch (main) and list newly added package decisions.
- /pkgsafe-explain-risk: Explain rules violated for <package> using explain_policy_decision.
- /pkgsafe-fix-deps: Find a safe alternative for <package>, swap it in the manifest, and update lockfiles.
```
