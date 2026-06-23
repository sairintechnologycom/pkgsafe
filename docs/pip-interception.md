# Pip Command Interception

## Supported Commands (P0)

PkgSafe intercepts and validates the following Pip command formats:

- `pip install <package>`
- `pip install <package>==<version>`
- `pip install "package>=version"`
- `pip install -r requirements.txt`
- `python -m pip install <package>`
- `python -m pip install -r requirements.txt`

## Scanning Behaviors

### 1. Version Specifiers Parsing

Pip supports complex version comparison operators: `==`, `>=`, `<=`, `>`, `<`, `!=`, `~=`.
PkgSafe extracts the package name and cleans range specifiers to resolve targets:
- Exact bounds like `requests==2.31.0` evaluate the exact version.
- Complex ranges fallback to checking the latest version if they cannot be reduced to a single exact version candidate.

### 2. Requirements File Parsing

When running `pkgsafe pip install -r requirements.txt`:
1. PkgSafe parses the file (supporting standard python requirement file formats).
2. It validates every defined package.
3. **Unpinned dependencies warning**: If a dependency is unpinned (e.g. `requests` instead of `requests==2.31.0`), PkgSafe prints a warning to `stderr` recommending pinning.
4. The installation is blocked if any package violates security policies.

## Unsupported Advanced Inputs

Advanced Pip options, alternative index registries (e.g. `--index-url`, `--extra-index-url`), VCS links (`git+https://`), or local wheels are classified as unsupported advanced inputs.
PkgSafe warns the user and fails safely with exit code 7 (`ExitUnsupportedCommand`).
