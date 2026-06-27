# Security Policy

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the maintainers before public
disclosure. Include the affected command, package ecosystem, input files, and a
minimal reproduction when possible.

## Current security model

PkgSafe is a local-first advisory tool. Registry metadata, OSV advisory sync,
policy evaluation, artifact extraction, report generation, MCP stdio, and install
interception are intended to fail closed for unsafe or unavailable inputs.

Lifecycle behavior analysis is best-effort only: scripts run on the host with a
cleaned environment and fake home directory, but without OS-level containment.
Do not run behavior analysis on code you would not execute in your own
environment.

The REST API is intended for loopback use. Do not expose it on a non-loopback
interface without token authentication and TLS.
