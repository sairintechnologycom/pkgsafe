# npm interception

How `pkgsafe npm …` treats common npm commands.

## Install-style commands (scanned)

- `npm install` / `npm i` / `npm add` (with or without package names)
- Versioned installs: `npm install lodash@4`
- Dev deps: `--save-dev` / `-D`
- Project install: `npm install` (no args) → lockfile or `package.json`
- Clean install: `npm ci` → `package-lock.json`

```bash
pkgsafe npm install axios
pkgsafe npm install -D typescript
pkgsafe npm ci
```

### Behavior

| Case | What PkgSafe does |
|------|-------------------|
| Named package | Resolve version, scan, then allow/warn/block |
| Bare `npm install` | Prefer `package-lock.json`; else scan `package.json` deps |
| `npm ci` | Scan lockfile; only then run real `npm ci` |

## Non-install commands (pass-through)

Commands that are not installs (for example `npm run build`, `npm test`,
`npm publish`) are **passed through** to the real npm binary so normal
workflows keep working.

```bash
pkgsafe npm run build   # no package scan; real npm runs
```

## Advanced inputs

Local paths, tarballs, and git URLs may be treated as unsupported advanced
inputs and fail closed rather than half-scanned. Prefer registry package names
or scan the project lockfile.

## Shims

```bash
alias npm="pkgsafe npm"
```

See [shell-shims.md](shell-shims.md) and [install-interception.md](install-interception.md).
