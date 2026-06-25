package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/intel/osv"
)

func UpdateDB(dbPath, ecosystem, source string) error {
	return updateDB(dbPath, ecosystem, source, false)
}

func UpdateDBAsync(dbPath, ecosystem, source string, threshold time.Duration) {
	d, err := db.Open(dbPath)
	if err != nil {
		return
	}
	needsUpdate := d.NeedsUpdate(context.Background(), threshold)
	d.Close()

	if needsUpdate {
		go func() {
			_ = updateDB(dbPath, ecosystem, source, true)
		}()
	}
}

func updateDB(dbPath, ecosystem, source string, silent bool) error {
	if ecosystem == "" {
		ecosystem = "npm"
	}
	if source == "" {
		source = "osv"
	}

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	// Load previously scanned packages from cache
	store, err := cache.Load("")
	if err != nil {
		return fmt.Errorf("load cache: %w", err)
	}

	uniquePackages := make(map[string]bool)
	for _, res := range store.Results {
		if res.Package.Name != "" {
			uniquePackages[res.Package.Name] = true
		}
	}

	// For MVP, if no packages have been scanned, we can seeding some default common packages
	// to make update-db look nice and work on a clean environment.
	if len(uniquePackages) == 0 {
		for _, name := range []string{"lodash", "axios", "react", "express", "typescript"} {
			uniquePackages[name] = true
		}
	}

	ctx := context.Background()
	client := osv.NewClient()
	updatedCount := 0

	for name := range uniquePackages {
		rawVulns, err := client.Query(ctx, osv.QueryRequest{
			Package: &osv.Package{Name: name, Ecosystem: ecosystem},
		})
		if err != nil {
			// Fail silently or log error for this package, but continue with others
			continue
		}

		var dbVulns []db.Vulnerability
		for _, v := range rawVulns {
			dbV := osv.MapVulnerability(v, name, ecosystem)
			dbVulns = append(dbVulns, dbV)
		}

		if len(dbVulns) > 0 {
			err = d.SaveVulnerabilities(ctx, dbVulns)
			if err == nil {
				updatedCount += len(dbVulns)
			}
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	_ = d.SetMetadata(ctx, "last_update", nowStr)

	if !silent {
		fmt.Println("PkgSafe threat DB updated.")
		fmt.Println()
		fmt.Printf("Source: %s\n", source)
		fmt.Printf("Ecosystem: %s\n", ecosystem)
		fmt.Printf("Records updated: %d\n", updatedCount)
		fmt.Printf("Last updated: %s\n", nowStr)
		fmt.Printf("Database: %s\n", d.Path())
	}

	return nil
}

