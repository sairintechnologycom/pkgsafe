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
pkgsafe registry test npm-internal
pkgsafe registry test pypi-internal
```
