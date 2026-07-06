# PkgSafe demo — supply-chain firewall for AI coding agents.
# Render with:  vhs demo/pkgsafe-demo.tape   (run from the repo root)
# Requires: vhs (github.com/charmbracelet/vhs). Uses ./dist/pkgsafe.

Output demo/pkgsafe-demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1160
Set Height 800
Set Padding 22
Set TypingSpeed 30ms
Set Theme "Catppuccin Mocha"

# --- hidden setup: put ./dist on PATH, use a clean prompt ---
Hide
Type `export PATH="$PWD/dist:$PATH"; export PS1='\[\e[38;5;39m\]$\[\e[0m\] '; clear`
Enter
Show

Sleep 800ms
Type "# Your AI agent wants to install packages. Check each one FIRST."
Sleep 700ms
Enter
Sleep 500ms

# 1) Safe, trusted package -> ALLOW
Type "pkgsafe scan-local-npm ./testdata/npm/safe-package --mode block"
Sleep 300ms
Enter
Sleep 2s

# 2) Typosquat of axios ('axois') -> WARN — exactly what an LLM hallucinates
Type "# A typosquat of 'axios' — the kind of name an LLM invents:"
Enter
Sleep 300ms
Type "pkgsafe scan-local-npm ./testdata/npm/typosquat --mode block"
Sleep 300ms
Enter
Sleep 2500ms

# 3) Credential theft in a postinstall hook -> BLOCK
Type "# This one reads your AWS credentials in a postinstall hook:"
Enter
Sleep 300ms
Type "pkgsafe scan-local-npm ./testdata/npm/reads-credentials --mode block"
Sleep 300ms
Enter
Sleep 3s

# 4) The point: wire it into the agent over MCP
Type "# Add PkgSafe as an MCP server so the agent must ask before installing."
Enter
Sleep 2500ms
