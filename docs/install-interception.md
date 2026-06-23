# PkgSafe Multi-Ecosystem Install Interception

## Purpose

PkgSafe is designed to act as a proactive safety guardrail for developers, CI/CD pipelines, and AI coding agents. Intercepting package installation commands ensures that malicious or high-risk dependencies are analyzed and validated against security policies *before* they are installed on the local system or in execution environments.

## Architecture

PkgSafe intercepts commands through explicit wrapped execution or shell aliases/shims. When a command is run, PkgSafe:

1. **Parses the Input**: Resolves which package manager (`npm`, `pip`, `python -m pip`) and subcommands/arguments are targeted.
2. **Identifies Target Packages**: Extracts requested packages, version specifiers, and locks.
3. **Checks Policy Rules**: Compares against local rules, known vulnerability intelligence (OSV), typosquatting targets, and optionally executes static analysis / sandboxing.
4. **Applies Enforcement Matrix**:
   - **ALLOW**: Installs the dependency safely via delegation to the real package manager.
   - **WARN**: Prompts the developer in interactive sessions, or rejects in non-interactive/AI agent environments unless explicit override flags are passed.
   - **BLOCK**: Halts the installation entirely, logging a security audit event and returning exit code 1.

## Explicit Interception Commands

Instead of calling the package manager directly, prepend `pkgsafe`:

```bash
# NPM package installation
pkgsafe npm install axios
pkgsafe npm add lodash

# Pip package installation
pkgsafe pip install requests
pkgsafe python -m pip install Django
```

## Generic Subcommand Interception

You can also run interception using the generic command gate:

```bash
pkgsafe run -- npm install lodash
pkgsafe run -- pip install requests
```

## Safety Settings and Flags

You can customize runtime behavior by adding safety flags at command invocation:

- `--mode <warn|block|audit>`: Overrides current enforcement mode.
- `--policy <path>`: Uses a custom YAML policy file.
- `--sandbox`: Enables sandboxed execution of installation behaviors (where supported).
- `--offline`: Runs checks offline using the local cache and threat DB.
- `--dry-run`: Completes security checks and prints recommendations without invoking the real package manager.
- `--yes`: Answers "Yes" to warnings (for non-interactive shell executions).
- `--json`: Outputs validation details in structured JSON formats.
- `--force-risk-accept --reason "text"`: Bypasses policy blocks under strict conditions (logged in local audit logs).
