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
	"time"

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
}

func Doctor(opts DoctorOptions) error {
	rep := RunDoctor(opts)
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
		return "pass", fmt.Sprintf("reachable: %s", resp.Status)
	}
	return "warn", fmt.Sprintf("unexpected status: %s", resp.Status)
}

func writeDoctorHuman(rep DoctorReport) {
	fmt.Println("PkgSafe Doctor")
	fmt.Println()
	status := "PASS"
	if !rep.Pass {
		status = "FAIL"
	}
	fmt.Printf("Status: %s\n\n", status)
	for _, check := range rep.Checks {
		fmt.Printf("- [%s] %s: %s\n", check.Status, check.Name, check.Summary)
	}
}

func userHomeFallback() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}
