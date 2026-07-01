# Private Registry Guide

PkgSafe supports private npm scope routing and PyPI package-prefix routing through policy or a registry config file.

Required production behavior:

- Private npm scopes must not fall back to public npm.
- Private PyPI prefixes are normalized before routing.
- Disabled public fallback blocks unresolved private package names.
- Registry credentials are redacted from reports and logs.

Example controls:

```yaml
registries:
  registries:
    npm:
      npm-internal:
        type: private
        enabled: true
        url: https://npm.company.example/
        scopes: ["@company"]
      public:
        type: public
        enabled: false
        url: https://registry.npmjs.org/
    pypi:
      pypi-internal:
        type: private
        enabled: true
        url: https://pypi.company.example/simple/
        package_prefixes: ["company-internal"]
```

Validate routing:

```bash
pkgsafe registry test --policy .pkgsafe/policy.yaml npm-internal
pkgsafe registry test --policy .pkgsafe/policy.yaml pypi-internal
pkgsafe registry test --policy .pkgsafe/policy.yaml --ecosystem npm --package @company/api
pkgsafe registry test --policy .pkgsafe/policy.yaml --ecosystem pypi --package company_internal_pkg
```

The package routing test prints the resolved registry, whether a private
scope/prefix matched, whether public fallback would occur, and a `BLOCK` status
when the policy disables fallback. PyPI package names are normalized first, so
`company_internal_pkg`, `company.internal.pkg`, and `Company-Internal-Pkg` match
the same `company-internal` private prefix.

To fail closed for internal packages, keep the public default disabled for the
ecosystem that must not fall back:

```yaml
registries:
  npm:
    npm-internal:
      type: private
      enabled: true
      url: https://npm.company.example/
      scopes: ["@company"]
    default:
      type: public
      enabled: false
      url: https://registry.npmjs.org/
```
