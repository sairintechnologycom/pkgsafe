package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
)

func DBStatus(dbPath string) error {
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	ctx := context.Background()

	lastUpdate, err := d.GetMetadata(ctx, "last_update")
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lastUpdate = "never"
		} else {
			lastUpdate = "unknown"
		}
	}

	vulnCount, err := d.GetVulnerabilityCount(ctx)
	if err != nil {
		vulnCount = 0
	}

	// Load cache size
	store, err := cache.Load("")
	cacheCount := 0
	if err == nil {
		cacheCount = len(store.Results)
	}

	offlineReady := "no"
	if vulnCount > 0 {
		offlineReady = "yes"
	}

	fmt.Println("PkgSafe Database Status")
	fmt.Println()
	fmt.Printf("Database: %s\n", d.Path())
	fmt.Printf("Initialized: yes\n")
	fmt.Printf("Last OSV update: %s\n", lastUpdate)
	fmt.Printf("Known vulnerability records: %d\n", vulnCount)
	fmt.Printf("Cached package scans: %d\n", cacheCount)
	fmt.Printf("Offline ready: %s\n", offlineReady)

	return nil
}
