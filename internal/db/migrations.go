package db

import "fmt"

func (d *DB) Migrate() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS vulnerability_records (
			id TEXT PRIMARY KEY,
			ecosystem TEXT NOT NULL,
			package_name TEXT NOT NULL,
			summary TEXT,
			severity TEXT,
			aliases TEXT,
			affected_ranges TEXT,
			fixed_versions TEXT,
			references_json TEXT,
			source TEXT NOT NULL,
			fetched_at TEXT NOT NULL
		);`,
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
	return nil
}
