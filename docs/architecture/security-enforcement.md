# Security Enforcement Classes

PkgSafe classifies findings by enforcement semantics rather than inferring
override behavior from names, severity, or risk score.

## Classes and precedence

```text
security_block
  -> explicit policy_block
  -> controlled active exception
  -> trusted-package adjustment
  -> advisory score and thresholds
  -> ALLOW / WARN / BLOCK / REVIEW_REQUIRED
```

- `security_block` is a product safety invariant. Trust, exceptions, score
  reductions, agent requests, and audit/warn/block operating modes cannot
  downgrade it.
- `policy_block` is an explicit governance decision. A valid controlled
  exception may change its outcome where policy permits.
- `advisory` contributes evidence and risk score. Threshold policy determines
  its outcome.

The canonical taxonomy is `policy.SecurityBlockRuleIDs`. The current security
block IDs are:

- `known_malware_indicator`
- `credential_path_reference`
- `credential_canary_read`
- `credential_canary_exfiltration_attempt`
- `npm_token_access`
- `ssh_key_access`
- `env_secret_access`
- `pypi_setup_py_credential_access`
- `pypi_credential_path_access`
- `pypi_env_secret_access`
- `cloud_metadata_access`
- `pypi_cloud_metadata_access`
- `shell_download_execute`
- `pypi_setup_py_network_call`
- `dependency_confusion_candidate`
- `private_scope_public_registry`
- `private_prefix_public_registry`
- `unapproved_registry_url`
- `provenance_identity_mismatch` (reserved until detector implementation)
- `archive_traversal_attempt` (reserved; extraction rejects before scoring)

`known_vulnerability_critical` is an explicit `policy_block`: trust cannot
reduce it, but an active controlled human exception can downgrade it according
to policy. `blocked_package` is also a `policy_block`.

Policies may declare `enforcement_class`, but built-in security-block IDs
cannot be weakened. Invalid or weakened classes make the policy invalid.

## Strict offline behavior

Offline behavior validation occurs inside ecosystem scanners so CLI, CI, API,
MCP, interceptors, and downstream callers receive identical enforcement:

- `offline + disabled`: allowed;
- `offline + heuristic`: rejected before cache access or runner selection;
- `offline + isolated`: allowed only with `network_mode=disabled` and an
  available isolated backend;
- isolated unavailability never falls back to heuristic execution.

The Linux isolated backend uses a private network namespace. Dedicated runtime
tests trap host-loopback access and DNS resolution.
