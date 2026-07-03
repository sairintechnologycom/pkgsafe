package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/dbbundle"
)

type DBStatusReport struct {
	Database           string            `json:"database"`
	Initialized        bool              `json:"initialized"`
	LastUpdates        map[string]string `json:"last_updates,omitempty"`
	Freshness          map[string]string `json:"freshness,omitempty"`
	Stale              bool              `json:"stale"`
	VulnerabilityCount int               `json:"vulnerability_count"`
	CachedScans        int               `json:"cached_scans"`
	OfflineReady       bool              `json:"offline_ready"`
}

func BuildDBStatusReport(dbPath string) (DBStatusReport, error) {
	d, err := db.Open(dbPath)
	if err != nil {
		return DBStatusReport{}, fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	ctx := context.Background()
	lastUpdates := map[string]string{}
	for _, key := range dbbundle.LastUpdateKeys {
		val, err := d.GetMetadata(ctx, key)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) && key == "last_update" {
				lastUpdates[key] = "unknown"
			}
			continue
		}
		lastUpdates[key] = val
	}
	freshness, stale := dbbundle.EvaluateFreshness(lastUpdates, dbbundle.StaleAfter)

	vulnCount, err := d.GetVulnerabilityCount(ctx)
	if err != nil {
		vulnCount = 0
	}
	store, err := cache.Load("")
	cacheCount := 0
	if err == nil {
		cacheCount = len(store.Results)
	}
	return DBStatusReport{
		Database:           d.Path(),
		Initialized:        true,
		LastUpdates:        lastUpdates,
		Freshness:          freshness,
		Stale:              stale,
		VulnerabilityCount: vulnCount,
		CachedScans:        cacheCount,
		OfflineReady:       vulnCount > 0,
	}, nil
}

func DBStatus(dbPath string) error {
	return DBStatusWithOptions(dbPath, false)
}

func DBStatusWithOptions(dbPath string, asJSON bool) error {
	report, err := BuildDBStatusReport(dbPath)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	lastUpdate := report.LastUpdates["last_update"]
	if lastUpdate == "" {
		lastUpdate = "never"
	}
	fmt.Println("PkgSafe Database Status")
	fmt.Println()
	fmt.Printf("Database: %s\n", report.Database)
	fmt.Printf("Initialized: yes\n")
	fmt.Printf("Last OSV update: %s\n", lastUpdate)
	for _, key := range dbbundle.LastUpdateKeys {
		if status, ok := report.Freshness[key]; ok {
			fmt.Printf("Freshness (%s): %s\n", key, status)
		}
	}
	if report.Stale {
		fmt.Println("Advisory data is stale: run `pkgsafe update-db` or import a fresher offline bundle.")
	}
	fmt.Printf("Known vulnerability records: %d\n", report.VulnerabilityCount)
	fmt.Printf("Cached package scans: %d\n", report.CachedScans)
	offlineReady := "no"
	if report.OfflineReady {
		offlineReady = "yes"
	}
	fmt.Printf("Offline ready: %s\n", offlineReady)
	return nil
}
