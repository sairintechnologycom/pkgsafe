package db

import (
	"context"
	"time"
)

func (d *DB) SetMetadata(ctx context.Context, key, val string) error {
	_, err := d.ExecContext(ctx, `
		INSERT INTO threat_db_metadata (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value
	`, key, val)
	return err
}

func (d *DB) GetMetadata(ctx context.Context, key string) (string, error) {
	var val string
	err := d.QueryRowContext(ctx, `
		SELECT value FROM threat_db_metadata WHERE key = ?
	`, key).Scan(&val)
	return val, err
}

func (d *DB) NeedsUpdate(ctx context.Context, threshold time.Duration) bool {
	return d.needsUpdateKey(ctx, "last_update", threshold)
}

// NeedsUpdateEcosystem reports whether the named OSV ecosystem's advisory data
// is older than threshold (or has never been synced). Staleness is tracked per
// ecosystem so syncing one does not mask another being out of date.
func (d *DB) NeedsUpdateEcosystem(ctx context.Context, ecosystem string, threshold time.Duration) bool {
	return d.needsUpdateKey(ctx, "last_update_"+ecosystem, threshold)
}

func (d *DB) needsUpdateKey(ctx context.Context, key string, threshold time.Duration) bool {
	val, err := d.GetMetadata(ctx, key)
	if err != nil {
		return true
	}
	lastUpdate, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return true
	}
	return time.Since(lastUpdate) > threshold
}
