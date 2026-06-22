package db

import (
	"context"
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
