# Shell aliases and shims

Route everyday `npm` and `pip` commands through PkgSafe so installs are checked
automatically.

## Setup

```bash
pkgsafe init shell
```

That prints aliases you can add to `~/.zshrc`, `~/.bashrc`, or `~/.profile`:

```bash
# PkgSafe package install guard
alias npm="pkgsafe npm"
alias pip="pkgsafe pip"
```

Reload the shell (or `source` the profile), then:

```bash
npm install lodash    # scanned, then real npm if allowed
npm run build         # passes through (not an install)
```

Details: [install-interception.md](install-interception.md).

## Temporary bypass

```bash
unalias npm
unalias pip
```

Or call the real binary by full path when you must skip the guard for a one-off
admin task. Prefer fixing policy over long-term bypass.

## Related

- [Getting started](getting-started.md)
- [npm interception](npm-interception.md)
- [pip interception](pip-interception.md)
