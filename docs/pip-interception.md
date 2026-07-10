# pip interception

How `pkgsafe pip …` and `pkgsafe python -m pip …` treat common pip installs.

## Supported install forms

```bash
pkgsafe pip install requests
pkgsafe pip install requests==2.31.0
pkgsafe pip install "requests>=2.28"
pkgsafe pip install -r requirements.txt
pkgsafe python -m pip install Django
pkgsafe python -m pip install -r requirements.txt
```

## Behavior

| Case | What PkgSafe does |
|------|-------------------|
| Exact pin (`==`) | Scans that version |
| Ranges | Resolves a concrete candidate when possible; may check latest suitable release |
| `-r requirements.txt` | Parses the file and validates each package; unpinned names may warn |

If any package **BLOCK**s under policy, the real pip install does not run.

## Advanced inputs

These often fail closed as unsupported advanced inputs (not half-scanned):

- `--index-url` / `--extra-index-url` (use [private-registry.md](private-registry.md) policy routing instead)
- VCS URLs (`git+https://…`)
- Local paths and editable installs
- Arbitrary local wheels outside normal registry flow

## Related

- [Install interception](install-interception.md)
- [Shell shims](shell-shims.md)
- [Policy guide](policy-guide.md)
- [PyPI limitations](known-limitations.md)
