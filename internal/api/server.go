package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

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
	s.mux.Handle("/api/v1/status", s.wrap(http.HandlerFunc(s.handleStatus)))
	s.mux.Handle("/api/v1/scan", s.wrap(http.HandlerFunc(s.handleScan)))
	s.mux.Handle("/api/v1/policy", s.wrap(http.HandlerFunc(s.handlePolicy)))
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

type PolicyRequest struct {
	PolicyPath string `json:"policy_path"`
	Mode       string `json:"mode"`
	PolicyPack string `json:"policy_pack"`
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}

	var req PolicyRequest
	if r.Body != nil && r.ContentLength != 0 {
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil && err.Error() != "EOF" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}
	}

	policyPath := req.PolicyPath
	if policyPath == "" {
		policyPath = s.cfg.DefaultPolicy
	}
	mode := req.Mode
	if mode == "" {
		mode = s.cfg.DefaultMode
	}

	pol, err := policy.ResolvePolicy(req.PolicyPack, "", policyPath, mode, "")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to resolve policy: " + err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(pol)
}

func (s *Server) wrap(handler http.Handler) http.Handler {
	handler = s.localhostOnly(handler)
	if s.cfg.Token != "" {
		handler = s.tokenAuth(s.cfg.Token, handler)
	}
	return handler
}

func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) localhostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalhost(r.RemoteAddr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: request must originate from localhost"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) tokenAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		// Compare the presented token in constant time to avoid a timing side-channel
		// that could let a caller recover the token byte-by-byte.
		presented := strings.TrimPrefix(auth, prefix)
		if !strings.HasPrefix(auth, prefix) || subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized: invalid or missing bearer token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Serve sets up the Server, prints a start message, and listens on localhost.
func Serve(cfg Config) error {
	s := NewServer(cfg)
	port := cfg.Port
	if strings.HasPrefix(port, ":") {
		port = port[1:]
	}
	fmt.Printf("Starting PkgSafe REST API server on http://127.0.0.1:%s...\n", port)
	return http.ListenAndServe("127.0.0.1:"+port, s.Router())
}
