# NPM Command Interception

## Supported Commands (P0)

PkgSafe parses and intercepts the following NPM commands:

- `npm install <package>`
- `npm i <package>`
- `npm add <package>`
- `npm install <package>@<version>`
- `npm install --save-dev <package>`
- `npm install -D <package>`
- `npm install` (project-level scan)
- `npm ci` (lockfile scan)

## Scanning Behaviors

### 1. Explicit Package Additions

When running `pkgsafe npm install <package>`, PkgSafe:
- Detects the requested version (resolves caret/tilde specifiers to target packages).
- Blocks installation if package name matches blocklists or exceeds risk scores.
- Automatically handles dev dependencies (`--save-dev`, `-D`) by flagging them accordingly in safety logs.

### 2. Project Installation (`npm install` with no args)

If no package name is specified:
1. PkgSafe looks for `package-lock.json` in the current working directory.
   - If present, it scans the exact pinned versions of all locked dependencies.
2. If `package-lock.json` is missing, PkgSafe reads `package.json` and scans all dependencies listed under `dependencies` and `devDependencies`.
3. If risk thresholds are violated, the command blocks execution of the real `npm install`.

### 3. CI Installation (`npm ci`)

When executing `pkgsafe npm ci`:
- PkgSafe scans `package-lock.json` directly.
- The installation only proceeds if the lockfile conforms fully to security policies.

## Unsupported Commands

Unsupported commands (like `npm run build`, `npm publish`, `npm test`) are detected and rejected with exit code 7 (`ExitUnsupportedCommand`) to prevent accidental bypass.
To run normal NPM tasks when shims are active, temporarily bypass using `unalias npm` or set `PKGSAFE_INTERCEPT_ACTIVE=1` environment variable.
