package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
)

func InitShell(args []string) error {
	fs := flag.NewFlagSet("init-shell", flag.ContinueOnError)
	install := fs.Bool("install", false, "automatically install aliases to shell profile")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *install {
		return autoInstallAliases()
	}

	// PkgSafe init shell prints the alias instructions to stdout.
	intercept.PrintShellAliases(os.Stdout)
	return nil
}

func autoInstallAliases() error {
	shell := os.Getenv("SHELL")
	var profilePath string
	var shellName string

	if strings.Contains(shell, "zsh") {
		shellName = "zsh"
		profilePath = filepath.Join(os.Getenv("HOME"), ".zshrc")
	} else if strings.Contains(shell, "bash") {
		shellName = "bash"
		profilePath = filepath.Join(os.Getenv("HOME"), ".bashrc")
	} else if strings.Contains(shell, "fish") {
		shellName = "fish"
		profilePath = filepath.Join(os.Getenv("HOME"), ".config/fish/config.fish")
	} else {
		return fmt.Errorf("unsupported shell %q. Supported shells: zsh, bash, fish", shell)
	}

	if isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		fmt.Printf("Detected %s shell. Append PkgSafe shims to %s? [y/N]: ", shellName, profilePath)
		var answer string
		_, _ = fmt.Scanln(&answer)
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Installation cancelled.")
			return nil
		}
	}

	// Read existing content
	content := ""
	if _, err := os.Stat(profilePath); err == nil {
		b, err := os.ReadFile(profilePath)
		if err != nil {
			return fmt.Errorf("read shell profile: %w", err)
		}
		content = string(b)
	} else {
		// Ensure directory exists
		dir := filepath.Dir(profilePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create profile directory: %w", err)
		}
	}

	// Check if already installed
	shimMark := "# PkgSafe package install guard"
	if strings.Contains(content, shimMark) {
		fmt.Printf("Shims already present in %s.\n", profilePath)
		return nil
	}

	// Create backup
	if content != "" {
		backupPath := profilePath + ".bak"
		if err := os.WriteFile(backupPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("create backup profile: %w", err)
		}
		fmt.Printf("Created backup of shell profile at %s\n", backupPath)
	}

	// Append shims
	var shims string
	if shellName == "fish" {
		shims = "\n# PkgSafe package install guard\n" +
			"function npm\n    pkgsafe npm $argv\nend\n" +
			"function pnpm\n    pkgsafe pnpm $argv\nend\n" +
			"function yarn\n    pkgsafe yarn $argv\nend\n" +
			"function pip\n    pkgsafe pip $argv\nend\n" +
			"function uv\n    pkgsafe uv $argv\nend\n"
	} else {
		shims = "\n# PkgSafe package install guard\n" +
			"alias npm=\"pkgsafe npm\"\n" +
			"alias pnpm=\"pkgsafe pnpm\"\n" +
			"alias yarn=\"pkgsafe yarn\"\n" +
			"alias pip=\"pkgsafe pip\"\n" +
			"alias uv=\"pkgsafe uv\"\n"
	}

	f, err := os.OpenFile(profilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open shell profile: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(shims); err != nil {
		return fmt.Errorf("write shell profile: %w", err)
	}

	// Color support check
	color := false
	if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		color = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	}
	green := ""
	bold := ""
	reset := ""
	if color {
		green = "\033[32m"
		bold = "\033[1m"
		reset = "\033[0m"
	}

	fmt.Printf("%s✓ Installed PkgSafe shims to %s.%s\n", green, profilePath, reset)
	fmt.Printf("To apply changes, run: %ssource %s%s\n", bold, profilePath, reset)
	return nil
}
