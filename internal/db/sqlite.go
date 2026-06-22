package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	path string
}

func Open(path string) (*DB, error) {
	if path == "" {
		path = DefaultDBPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	d := &DB{DB: db, path: path}
	if err := d.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
	}
	return d, nil
}

func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".pkgsafe.db"
	}
	return filepath.Join(home, ".pkgsafe", "pkgsafe.db")
}

func (d *DB) Path() string {
	return d.path
}
