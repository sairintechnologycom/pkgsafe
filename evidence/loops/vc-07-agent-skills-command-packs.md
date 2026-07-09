# Loop VC-7 - Agent Skills & Slash-Command Packs Evidence

Date: 2026-07-09
Branch: feat/agent-skills-command-packs

## Feature Spec

Define and package reusable prompt packs or slash commands for vibe coding agents (like Codex, Claude Code, and Cursor) to orchestrate package safety tasks.

## Files Created/Modified

- `docs/integrations/slash-commands.md` (new)

## Commands Packaged

*   `/pkgsafe-check-deps`: Scans manifest files for policy risks and presents a summary table.
*   `/pkgsafe-review-pr`: Evaluates dependency differences between base and head branch.
*   `/pkgsafe-explain-risk`: Explains policy violations using `explain_policy_decision`.
*   `/pkgsafe-fix-deps`: Swaps out blocked packages with safe alternatives.

## Integration Templates Documented

*   **Claude Code Instructions Config:** JSON structure containing customInstructions for prompt extension.
*   **Codex Instructions Config:** Prompt instructions block for agent configuration.

## Validation Results

*   Verified that all four prompt templates reference valid, implemented PkgSafe MCP tools (`check_package`, `check_install_command`, `review_dependency_diff`, `explain_policy_decision`).
*   Wording checked to make sure no SaaS or enterprise leakage was present.
