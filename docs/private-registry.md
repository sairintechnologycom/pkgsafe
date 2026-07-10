# Private registry guide

Route internal packages to your private npm or PyPI registry through policy.
Public fallback for private scopes/prefixes should stay **off** in production so
dependency confusion is blocked.

## Rules of thumb

- Private **npm scopes** must not fall back to the public registry.
- Private **PyPI prefixes** are normalized before match (`_`, `.`, case).
- If public fallback is disabled, unresolved private names **BLOCK**.
- Credentials are redacted from reports and logs — never paste them into issues.

## Example policy snippet

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

Fail closed for internal npm (public default disabled):

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

## Test routing

```bash
pkgsafe registry test --policy .pkgsafe/policy.yaml npm-internal
pkgsafe registry test --policy .pkgsafe/policy.yaml pypi-internal
pkgsafe registry test --policy .pkgsafe/policy.yaml --ecosystem npm --package @company/api
pkgsafe registry test --policy .pkgsafe/policy.yaml --ecosystem pypi --package company_internal_pkg
```

Output shows the resolved registry, whether a private scope/prefix matched,
whether public fallback would run, and BLOCK when fallback is disabled.

PyPI names are normalized: `company_internal_pkg`, `company.internal.pkg`, and
`Company-Internal-Pkg` all match prefix `company-internal`.

## Related

- [Policy guide](policy-guide.md)
- [Troubleshooting](troubleshooting.md)
- [Feedback](feedback.md) (use `private_registry_issue` label)
