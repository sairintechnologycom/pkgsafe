package db

import (
	"context"
)

type PopularPackage struct {
	Ecosystem      string
	Name           string
	DownloadsCount int
}

func (d *DB) SavePopularPackages(ctx context.Context, pkgs []PopularPackage) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO popular_packages (ecosystem, name, downloads_count)
		VALUES (?, ?, ?)
		ON CONFLICT(ecosystem, name) DO UPDATE SET downloads_count = excluded.downloads_count
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range pkgs {
		_, err = stmt.ExecContext(ctx, p.Ecosystem, p.Name, p.DownloadsCount)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) GetPopularPackages(ctx context.Context, ecosystem string) ([]PopularPackage, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT ecosystem, name, downloads_count
		FROM popular_packages
		WHERE ecosystem = ?
		ORDER BY downloads_count DESC
	`, ecosystem)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pkgs []PopularPackage
	for rows.Next() {
		var p PopularPackage
		if err := rows.Scan(&p.Ecosystem, &p.Name, &p.DownloadsCount); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}
