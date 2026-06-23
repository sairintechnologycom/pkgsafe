# Shell Aliases and Shims

To make package command validation seamless, developers can alias `npm` and `pip` commands to route through PkgSafe automatically.

## Initializing Shell Guidance

Run the initialization command to display setup guidance:

```bash
pkgsafe init shell
```

This outputs standard alias commands to insert into your shell profile:

```bash
# PkgSafe package install guard
alias npm="pkgsafe npm"
alias pip="pkgsafe pip"
```

Copy and paste these commands into your active profile (e.g. `~/.zshrc`, `~/.bashrc`, or `~/.profile`).

## Disabling Interception Temporarily

If you need to bypass interception (for example, to run administrative package tasks or unsupported commands):

```bash
# Temporarily disable aliases
unalias npm
unalias pip

# Or set the active environment variable to bypass
export PKGSAFE_INTERCEPT_ACTIVE=1
```
