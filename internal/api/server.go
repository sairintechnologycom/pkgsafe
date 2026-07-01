package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// Hardening defaults. Override via Config.
const (
	defaultMaxBodyBytes      = 1 << 20 // 1 MiB cap on request bodies
	defaultRateLimitPerMin   = 120     // requests per minute per client IP
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 60 * time.Second
	defaultIdleTimeout       = 120 * time.Second
)

type Config struct {
	Port          string
	Token         string
	DefaultPolicy string
	DefaultMode   string
	Offline       bool
	Version       string
	Commit        string

	// BindAddress is the interface to listen on. Defaults to 127.0.0.1 (loopback).
	// Binding to a non-loopback address requires both Token and TLS or Serve fails closed.
	BindAddress string
	// TLSCertFile/TLSKeyFile enable HTTPS when both are set.
	TLSCertFile string
	TLSKeyFile  string
	// MaxBodyBytes caps request body size (<=0 uses the default).
	MaxBodyBytes int64
	// RateLimitPerMinute caps requests per client IP per minute (<=0 uses the default).
	RateLimitPerMinute int
	// AllowNonLoopback skips the localhost-only middleware. Set automatically by
	// Serve when binding a non-loopback address with auth + TLS in place.
	AllowNonLoopback bool
}

type Server struct {
	cfg     Config
	mux     *http.ServeMux
	limiter *rateLimiter
}

func NewServer(cfg Config) *Server {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
		cfg.MaxBodyBytes = maxBody
	}
	rpm := cfg.RateLimitPerMinute
	if rpm <= 0 {
		rpm = defaultRateLimitPerMin
		cfg.RateLimitPerMinute = rpm
	}
	s := &Server{
		cfg:     cfg,
		mux:     http.NewServeMux(),
		limiter: newRateLimiter(rpm),
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
	Behavior   string `json:"behavior_mode"`
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

	behaviorMode := types.NormalizeBehaviorMode(pol.Sandbox.BehaviorMode, pol.Sandbox.Enabled)
	if req.Behavior != "" {
		switch types.BehaviorMode(req.Behavior) {
		case types.BehaviorDisabled, types.BehaviorHeuristic, types.BehaviorIsolated:
			behaviorMode = types.BehaviorMode(req.Behavior)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "behavior_mode must be disabled, heuristic, or isolated"})
			return
		}
	}
	if req.Sandbox != nil {
		behaviorMode = types.BehaviorDisabled
		if *req.Sandbox {
			behaviorMode = types.BehaviorHeuristic
		}
	}
	sandbox := behaviorMode != types.BehaviorDisabled

	var result types.ScanResult
	var scanErr error

	if req.Ecosystem == "npm" {
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = offline
		scanner.SandboxEnabled = sandbox
		scanner.BehaviorMode = behaviorMode
		scanner.RequestedBy = "api"
		scanner.Environment = "api"
		result, scanErr = scanner.ScanPackage(req.Name, req.Version)
	} else {
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = offline
		scanner.SandboxEnabled = sandbox
		scanner.BehaviorMode = behaviorMode
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
	// Innermost first: body cap runs closest to the handler; auth and rate
	// limiting run before we touch the body; the network guard runs first.
	handler = s.limitBody(handler)
	if s.cfg.Token != "" {
		handler = s.tokenAuth(s.cfg.Token, handler)
	}
	handler = s.rateLimit(handler)
	if !s.cfg.AllowNonLoopback {
		handler = s.localhostOnly(handler)
	}
	return handler
}

// limitBody caps the request body to defend against memory-exhaustion DoS.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit applies a per-client-IP token bucket.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !s.limiter.allow(host) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a minimal per-key token bucket (no external deps).
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	// refill rate in tokens per second
	refill float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]*bucket),
		capacity: float64(perMinute),
		refill:   float64(perMinute) / 60.0,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.capacity - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * rl.refill
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
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

// Serve sets up the Server and listens with hardened transport settings. It
// binds to loopback by default; binding a non-loopback interface requires both
// a token and TLS, otherwise it fails closed.
func Serve(cfg Config) error {
	bind := cfg.BindAddress
	if bind == "" {
		bind = "127.0.0.1"
	}
	port := cfg.Port
	if strings.HasPrefix(port, ":") {
		port = port[1:]
	}

	tlsEnabled := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""

	if !isLoopbackHost(bind) {
		// Non-loopback exposure must be authenticated and encrypted.
		if cfg.Token == "" {
			return fmt.Errorf("refusing to bind non-loopback address %q without --token (auth required for remote exposure)", bind)
		}
		if !tlsEnabled {
			return fmt.Errorf("refusing to bind non-loopback address %q without TLS (--tls-cert and --tls-key required for remote exposure)", bind)
		}
		cfg.AllowNonLoopback = true
	}

	s := NewServer(cfg)
	addr := net.JoinHostPort(bind, port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	fmt.Printf("Starting PkgSafe REST API server on %s://%s...\n", scheme, addr)
	if tlsEnabled {
		return srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
