package db

import (
	"fmt"
	"strings"
)

func (d *DB) Migrate() error {
	// A single OSV advisory can affect many packages, so the primary key must
	// include the package, not just the advisory id. Older databases used an
	// id-only primary key; drop that table so it is recreated with the
	// composite key below. The data is regenerable advisory data, so dropping
	// it is safe (a re-sync repopulates it).
	var existingDDL string
	_ = d.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='vulnerability_records'`).Scan(&existingDDL)
	if existingDDL != "" && !strings.Contains(existingDDL, "PRIMARY KEY (id, ecosystem, package_name)") {
		if _, err := d.Exec(`DROP TABLE vulnerability_records`); err != nil {
			return fmt.Errorf("rebuild vulnerability_records: %w", err)
		}
	}

	schema := []string{
		`CREATE TABLE IF NOT EXISTS vulnerability_records (
			id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package_name TEXT NOT NULL,
			version TEXT,
			summary TEXT,
			details TEXT,
			severity TEXT,
			aliases TEXT,
			affected_ranges TEXT,
			fixed_versions TEXT,
			references_json TEXT,
			source TEXT NOT NULL,
			published_at TEXT,
			modified_at TEXT,
			fetched_at TEXT NOT NULL,
			PRIMARY KEY (id, ecosystem, package_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_records_pkg
			ON vulnerability_records (ecosystem, package_name);`,
		`CREATE TABLE IF NOT EXISTS package_vulnerability_index (
			ecosystem TEXT NOT NULL,
			package_name TEXT NOT NULL,
			version TEXT NOT NULL,
			vulnerability_id TEXT NOT NULL,
			matched_at TEXT NOT NULL,
			PRIMARY KEY (ecosystem, package_name, version, vulnerability_id)
		);`,
		`CREATE TABLE IF NOT EXISTS threat_db_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}

	for _, q := range schema {
		if _, err := d.Exec(q); err != nil {
			return fmt.Errorf("executing migration query %q: %w", q, err)
		}
	}
	for _, col := range []struct {
		name string
		def  string
	}{
		{"version", "TEXT"},
		{"details", "TEXT"},
		{"published_at", "TEXT"},
		{"modified_at", "TEXT"},
	} {
		if _, err := d.Exec(fmt.Sprintf(`ALTER TABLE vulnerability_records ADD COLUMN %s %s`, col.name, col.def)); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return fmt.Errorf("add vulnerability_records.%s: %w", col.name, err)
		}
	}
	return nil
}
