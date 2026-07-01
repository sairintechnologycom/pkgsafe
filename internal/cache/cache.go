package cache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type Store struct {
	Path    string
	Results map[string]types.ScanResult `json:"results"`
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".pkgsafe-cache.json"
	}
	return filepath.Join(home, ".pkgsafe", "cache.json")
}

func Load(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	s := &Store{Path: path, Results: map[string]types.ScanResult{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Results == nil {
		s.Results = map[string]types.ScanResult{}
	}
	return s, nil
}

func (s *Store) Put(result types.ScanResult) error {
	if s.Results == nil {
		s.Results = map[string]types.ScanResult{}
	}
	s.Results[key(result.Package.Ecosystem, result.Package.Name, result.Package.Version)] = result
	return s.Save()
}

func (s *Store) Get(ecosystem, name, version string) (types.ScanResult, bool) {
	r, ok := s.Results[key(ecosystem, name, version)]
	if ok {
		return r, true
	}
	if version != "" {
		r, ok = s.Results[key(ecosystem, name, "")]
	}
	return r, ok
}

func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, b, 0o600)
}

func key(ecosystem, name, version string) string {
	return ecosystem + ":" + name + "@" + version
}
