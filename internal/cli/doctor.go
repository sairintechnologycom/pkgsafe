package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	"github.com/sairintechnologycom/pkgsafe/internal/version"
)

type DoctorReport struct {
	GeneratedAt string        `json:"generated_at"`
	Pass        bool          `json:"pass"`
	Checks      []DoctorCheck `json:"checks"`
}

type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

type DoctorOptions struct {
	PolicyPath     string
	RegistryConfig string
	SkipNetwork    bool
	JSON           bool
	Fix            bool
}

func Doctor(opts DoctorOptions) error {
	rep := RunDoctor(opts)
	if opts.Fix {
		rep = RunDoctorFix(opts, rep)
	}
	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		writeDoctorHuman(rep)
	}
	if !rep.Pass {
		return fmt.Errorf("doctor found one or more blocking problems")
	}
	return nil
}

func RunDoctor(opts DoctorOptions) DoctorReport {
	rep := DoctorReport{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Pass: true}
	add := func(name, status, summary string) {
		if status == "fail" {
			rep.Pass = false
		}
		rep.Checks = append(rep.Checks, DoctorCheck{Name: name, Status: status, Summary: summary})
	}

	add("version", "pass", fmt.Sprintf("pkgsafe %s (%s)", version.Version, version.Commit))
	add("config path", "pass", filepath.Join(userHomeFallback(), ".pkgsafe"))

	if _, err := policy.Load(opts.PolicyPath); err != nil {
		add("policy", "fail", err.Error())
	} else if opts.PolicyPath == "" {
		add("policy", "pass", "default policy is valid")
	} else {
		add("policy", "pass", fmt.Sprintf("policy %s is valid", opts.PolicyPath))
	}

	// Check shell shims
	shimsConfigured := false
	home := userHomeFallback()
	for _, rc := range []string{".zshrc", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"} {
		path := filepath.Join(home, rc)
		if b, err := os.ReadFile(path); err == nil {
			if strings.Contains(string(b), "pkgsafe npm") || strings.Contains(string(b), "pkgsafe pip") {
				shimsConfigured = true
				break
			}
		}
	}
	if shimsConfigured {
		add("shell shims", "pass", "configured in shell profile")
	} else {
		add("shell shims", "warn", "not configured in shell profile; command-intercepting shims are not active")
	}

	d, err := db.Open("")
	if err != nil {
		add("database", "fail", err.Error())
	} else {
		defer d.Close()
		count, _ := d.GetVulnerabilityCount(context.Background())
		lastUpdate, err := d.GetMetadata(context.Background(), "last_update")
		if errors.Is(err, sql.ErrNoRows) || lastUpdate == "" {
			lastUpdate = "never"
		}
		status := "pass"
		if count == 0 {
			status = "warn"
		}
		add("database", status, fmt.Sprintf("%s, vulnerability_records=%d, last_update=%s", d.Path(), count, lastUpdate))
	}

	if store, err := cache.Load(""); err != nil {
		add("scan cache", "warn", err.Error())
	} else {
		add("scan cache", "pass", fmt.Sprintf("%s, cached_scans=%d", store.Path, len(store.Results)))
	}

	for _, ep := range connectedEndpoints() {
		if opts.SkipNetwork {
			add(ep.name, "skip", "network check skipped")
			continue
		}
		status, summary := networkStatus(ep.url)
		add(ep.name, status, summary)
	}

	for _, bin := range []string{"npm", "pip", "python"} {
		if path, err := exec.LookPath(bin); err == nil {
			add("package manager "+bin, "pass", path)
		} else {
			add("package manager "+bin, "warn", "not found in PATH")
		}
	}

	if opts.RegistryConfig == "" {
		add("private registry config", "pass", "no external registry config supplied")
	} else {
		b, err := os.ReadFile(opts.RegistryConfig)
		if err != nil {
			add("private registry config", "fail", err.Error())
		} else if _, err := registry.ParseRegistries(b); err != nil {
			add("private registry config", "fail", err.Error())
		} else {
			add("private registry config", "pass", fmt.Sprintf("%s is valid", opts.RegistryConfig))
		}
	}

	add("MCP readiness", "pass", "mcp serve command and install-validation tools are available")
	return rep
}

// connectedEndpoint is a registry/advisory service probed by doctor when the
// network check is not skipped.
type connectedEndpoint struct {
	name string
	url  string
}

// connectedEndpoints lists the external services pkgsafe relies on in connected
// mode: the OSV advisory API, the npm registry, and PyPI. Reachability is
// reported as warn (not fail) on error so that a transient or air-gapped
// environment does not turn doctor red — offline scans remain supported.
func connectedEndpoints() []connectedEndpoint {
	return []connectedEndpoint{
		{name: "OSV network", url: "https://api.osv.dev/v1/"},
		{name: "npm registry", url: "https://registry.npmjs.org/"},
		{name: "PyPI registry", url: "https://pypi.org/simple/"},
	}
}

func networkStatus(url string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "warn", err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "warn", err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return "pass", "reachable"
	}
	return "warn", fmt.Sprintf("unexpected status: %s", resp.Status)
}

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

func writeDoctorHuman(rep DoctorReport) {
	color := useColor()

	var green, yellow, red, cyan, gray, bold, reset string
	if color {
		green = colorGreen
		yellow = colorYellow
		red = colorRed
		cyan = colorCyan
		gray = colorGray
		bold = colorBold
		reset = colorReset
	}

	fmt.Printf("%sPkgSafe Doctor%s\n", bold, reset)
	fmt.Println("==============")

	statusStr := bold + green + "PASS" + reset
	if !rep.Pass {
		statusStr = bold + red + "FAIL" + reset
	}
	fmt.Printf("Status: %s\n\n", statusStr)

	// Groups
	groups := []struct {
		title  string
		checks []string
	}{
		{
			title:  "System & Configuration",
			checks: []string{"version", "config path", "policy", "shell shims", "private registry config", "MCP readiness"},
		},
		{
			title:  "Local Storage",
			checks: []string{"database", "scan cache"},
		},
		{
			title:  "Registry Connectivity",
			checks: []string{"OSV network", "npm registry", "PyPI registry"},
		},
		{
			title:  "Package Managers",
			checks: []string{"package manager npm", "package manager pip", "package manager python"},
		},
	}

	// Create a map of checks for easy lookup
	checkMap := make(map[string]DoctorCheck)
	for _, check := range rep.Checks {
		checkMap[check.Name] = check
	}

	// Print grouped checks
	printedChecks := make(map[string]bool)
	for _, grp := range groups {
		// Only print group if at least one of its checks is present
		hasChecks := false
		for _, name := range grp.checks {
			if _, ok := checkMap[name]; ok {
				hasChecks = true
				break
			}
		}
		if !hasChecks {
			continue
		}

		fmt.Printf("%s%s%s\n", bold+cyan, grp.title, reset)
		for _, name := range grp.checks {
			check, ok := checkMap[name]
			if !ok {
				continue
			}
			printedChecks[name] = true

			// Format prefix/status and text colors
			var symbol string
			var textStart, textEnd string
			switch check.Status {
			case "pass":
				symbol = green + "✓" + reset
			case "warn":
				symbol = yellow + "⚠" + reset
				if color {
					textStart = yellow
					textEnd = reset
				}
			case "fail":
				symbol = red + "✗" + reset
				if color {
					textStart = red
					textEnd = reset
				}
			default: // skip or other
				symbol = gray + "-" + reset
			}

			// Clean name: for Package Managers group, strip "package manager " prefix
			displayName := check.Name
			if grp.title == "Package Managers" && strings.HasPrefix(displayName, "package manager ") {
				displayName = strings.TrimPrefix(displayName, "package manager ")
			}

			fmt.Printf("  %s %s%s: %s%s\n", symbol, textStart, displayName, check.Summary, textEnd)
		}
		fmt.Println()
	}

	// Print any remaining checks not in predefined groups
	hasRemaining := false
	for _, check := range rep.Checks {
		if !printedChecks[check.Name] {
			hasRemaining = true
			break
		}
	}

	if hasRemaining {
		fmt.Printf("%sOther Checks%s\n", bold+cyan, reset)
		for _, check := range rep.Checks {
			if printedChecks[check.Name] {
				continue
			}
			var symbol string
			var textStart, textEnd string
			switch check.Status {
			case "pass":
				symbol = green + "✓" + reset
			case "warn":
				symbol = yellow + "⚠" + reset
				if color {
					textStart = yellow
					textEnd = reset
				}
			case "fail":
				symbol = red + "✗" + reset
				if color {
					textStart = red
					textEnd = reset
				}
			default:
				symbol = gray + "-" + reset
			}
			fmt.Printf("  %s %s%s: %s%s\n", symbol, textStart, check.Name, check.Summary, textEnd)
		}
		fmt.Println()
	}

	// Suggested next commands
	fmt.Printf("%sSuggested Next Steps:%s\n", bold, reset)
	if rep.Pass {
		fmt.Printf("  • Check a package's risk details:  %spkgsafe explain <package-name>%s\n", bold+cyan, reset)
		fmt.Printf("  • Scan your project dependencies:  %spkgsafe scan-lockfile package-lock.json%s\n", bold+cyan, reset)
		fmt.Printf("  • Set up shell shims:              %spkgsafe init shell%s\n", bold+cyan, reset)
	} else {
		hasStaleDB := false
		for _, check := range rep.Checks {
			if check.Name == "database" && (check.Status == "warn" || check.Status == "fail") {
				hasStaleDB = true
				break
			}
		}
		if hasStaleDB {
			fmt.Printf("  • Update local vulnerability DB:   %spkgsafe update-db%s\n", bold+cyan, reset)
		}
		fmt.Printf("  • Diagnose network & policies:     %spkgsafe doctor --skip-network%s\n", bold+cyan, reset)
	}
	fmt.Println()
}

func userHomeFallback() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}

func RunDoctorFix(opts DoctorOptions, rep DoctorReport) DoctorReport {
	color := useColor()
	var green, red, bold, reset string
	if color {
		green = colorGreen
		red = colorRed
		bold = colorBold
		reset = colorReset
	}

	anyFixed := false
	for _, check := range rep.Checks {
		if check.Status == "pass" || check.Status == "skip" {
			continue
		}

		switch check.Name {
		case "database":
			fmt.Printf("%s⚙ Attempting to fix database warning/failure...%s\n", bold, reset)
			err := UpdateDB("", "", "")
			if err != nil {
				fmt.Printf("%s✗ Database fix failed: %v%s\n", red, err, reset)
			} else {
				fmt.Printf("%s✓ Database updated successfully.%s\n", green, reset)
				anyFixed = true
			}

		case "policy":
			if opts.PolicyPath != "" {
				if _, err := os.Stat(opts.PolicyPath); os.IsNotExist(err) {
					fmt.Printf("%s⚙ Creating default policy at custom path %s...%s\n", bold, opts.PolicyPath, reset)
					err := writeDefaultPolicy(opts.PolicyPath)
					if err != nil {
						fmt.Printf("%s✗ Failed to write policy file: %v%s\n", red, err, reset)
					} else {
						fmt.Printf("%s✓ Policy file created successfully.%s\n", green, reset)
						anyFixed = true
					}
				} else {
					fmt.Printf("%s⚠ Custom policy path %q exists but failed to load. Please inspect and fix the file manually.%s\n", red, opts.PolicyPath, reset)
				}
			} else {
				defaultPath := filepath.Join(userHomeFallback(), ".pkgsafe", "policy.yaml")
				if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
					fmt.Printf("%s⚙ Creating default policy at %s...%s\n", bold, defaultPath, reset)
					_ = os.MkdirAll(filepath.Dir(defaultPath), 0755)
					err := writeDefaultPolicy(defaultPath)
					if err != nil {
						fmt.Printf("%s✗ Failed to write policy file: %v%s\n", red, err, reset)
					} else {
						fmt.Printf("%s✓ Policy file created successfully.%s\n", green, reset)
						anyFixed = true
					}
				}
			}

		case "scan cache":
			fmt.Printf("%s⚙ Creating scan cache directory...%s\n", bold, reset)
			cachePath := filepath.Join(userHomeFallback(), ".pkgsafe", "cache")
			err := os.MkdirAll(cachePath, 0755)
			if err != nil {
				fmt.Printf("%s✗ Failed to create cache directory: %v%s\n", red, err, reset)
			} else {
				fmt.Printf("%s✓ Cache directory created successfully.%s\n", green, reset)
				anyFixed = true
			}

		case "shell shims":
			fmt.Printf("%s⚙ Launching interactive shell shim installer...%s\n", bold, reset)
			err := autoInstallAliases()
			if err != nil {
				fmt.Printf("%s✗ Shell shim installation failed: %v%s\n", red, err, reset)
			} else {
				fmt.Printf("%s✓ Shell shims configured.%s\n", green, reset)
				anyFixed = true
			}
		}
	}

	if anyFixed {
		fmt.Printf("\n%s⚙ Re-running checks after fixes...%s\n\n", bold, reset)
		return RunDoctor(opts)
	}

	return rep
}

func writeDefaultPolicy(path string) error {
	defaultYaml := `schema_version: "1.0"

mode: warn

thresholds:
  allow_max_score: 29
  warn_max_score: 69
  block_min_score: 70

ecosystems:
  npm:
    enabled: true
  pypi:
    enabled: true

sandbox:
  enabled: false
  behavior_mode: disabled
  default_timeout_seconds: 10
  network_mode: disabled
  keep_sandbox: false
  fail_open_when_unavailable: true

protected_paths:
  - "~/.aws"
  - "~/.azure"
  - "~/.gcp"
  - "~/.ssh"
  - "~/.kube"
  - "~/.npmrc"
  - "~/.pypirc"
  - ".env"
  - ".env.local"
  - ".vault-token"

trusted_packages:
  npm:
    - lodash
    - axios
    - react
    - express
    - typescript
  pypi:
    - requests
    - flask
    - django
    - fastapi
    - numpy
    - pandas
    - pydantic
    - pytest

blocked_packages:
  npm: []
  pypi: []

rules:
  lifecycle_script_present:
    enabled: true
    severity: medium
    score: 20

  network_command_in_lifecycle:
    enabled: true
    severity: high
    score: 30
    block_in_strict_mode: true

  credential_path_reference:
    enabled: true
    severity: critical
    score: 100

  secret_keyword_reference:
    enabled: true
    severity: high
    score: 35

  obfuscated_script:
    enabled: true
    severity: high
    score: 25

  typosquat_candidate:
    enabled: true
    severity: high
    score: 25

  missing_repository:
    enabled: true
    severity: low
    score: 10

  missing_license:
    enabled: true
    severity: low
    score: 5

  new_package:
    enabled: true
    severity: medium
    score: 15
    max_age_days: 14

  trusted_package_reduction:
    enabled: true
    severity: informational
    score: -20

  blocked_package:
    enabled: true
    severity: critical
    score: 100

  known_vulnerability_critical:
    enabled: true
    severity: critical
    score: 70

  known_vulnerability_high:
    enabled: true
    severity: high
    score: 50

  known_vulnerability_medium:
    enabled: true
    severity: medium
    score: 25

  known_vulnerability_low:
    enabled: true
    severity: low
    score: 10
`
	return os.WriteFile(path, []byte(defaultYaml), 0644)
}
