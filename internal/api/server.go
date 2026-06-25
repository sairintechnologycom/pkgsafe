package api

import (
	"encoding/json"
	"net/http"
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
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": s.cfg.Version,
		"commit":  s.cfg.Commit,
	})
}
