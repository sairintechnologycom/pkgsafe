package api

import (
	"encoding/json"
	"net/http"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	spypi "github.com/niyam-ai/pkgsafe/internal/scanner/pypi"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type Config struct {
	Port          string
	Token         string
	DefaultPolicy string
	DefaultMode   string
	Offline       bool
	Version       string
	Commit        string
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Router() *http.ServeMux {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
	s.mux.HandleFunc("/api/v1/scan", s.handleScan)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": s.cfg.Version,
		"commit":  s.cfg.Commit,
	})
}

type ScanRequest struct {
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PolicyPath string `json:"policy_path"`
	Mode       string `json:"mode"`
	Offline    *bool  `json:"offline"`
	Sandbox    *bool  `json:"sandbox"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	if req.Ecosystem == "" {
		req.Ecosystem = "npm"
	}

	if req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "name is required"})
		return
	}

	if req.Ecosystem != "npm" && req.Ecosystem != "pypi" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid ecosystem: must be npm or pypi"})
		return
	}

	policyPath := req.PolicyPath
	if policyPath == "" {
		policyPath = s.cfg.DefaultPolicy
	}
	mode := req.Mode
	if mode == "" {
		mode = s.cfg.DefaultMode
	}

	pol, err := policy.ResolvePolicy("", "", policyPath, mode, "")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to resolve policy: " + err.Error()})
		return
	}

	offline := s.cfg.Offline
	if req.Offline != nil {
		offline = *req.Offline
	}

	sandbox := pol.Sandbox.Enabled
	if req.Sandbox != nil {
		sandbox = *req.Sandbox
	}

	var result types.ScanResult
	var scanErr error

	if req.Ecosystem == "npm" {
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = offline
		scanner.SandboxEnabled = sandbox
		scanner.RequestedBy = "api"
		scanner.Environment = "api"
		result, scanErr = scanner.ScanPackage(req.Name, req.Version)
	} else {
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = offline
		scanner.SandboxEnabled = sandbox
		scanner.RequestedBy = "api"
		scanner.Environment = "api"
		result, scanErr = scanner.ScanPackage(req.Name, req.Version)
	}

	if scanErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": scanErr.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(result)
}
