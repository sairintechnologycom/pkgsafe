# PkgSafe Architecture

## MVP flow

1. Developer runs `pkgsafe scan-npm-package <name>` or `pkgsafe npm-install <name>`.
2. CLI resolves npm metadata and latest version.
3. Static analyzer inspects lifecycle scripts and metadata.
4. Typosquat detector compares the name against a curated popular-package list.
5. Risk engine generates `allow`, `warn`, or `block`.
6. Result is printed as human text or JSON and cached locally.
7. MCP server exposes the same validation to AI coding agents.

## Future phases

- OSV vulnerability ingestion
- Known malware feed ingestion
- Tarball extraction and deep static scanning
- Shadow install sandbox
- Credential canary detection
- PyPI support
- VS Code/Cursor integration
- Enterprise policy sync
