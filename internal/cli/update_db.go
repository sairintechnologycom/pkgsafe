package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/intel/osv"
	"github.com/sairintechnologycom/pkgsafe/internal/logging"
)

// saveBatchSize bounds how many advisory rows are written per transaction.
const saveBatchSize = 1000

func UpdateDB(dbPath, ecosystem, source string) error {
	return updateDB(dbPath, ecosystem, source, false)
}

// UpdateDBAsync triggers a background sync for the given ecosystem if its
// advisory data is older than threshold. Staleness is tracked per ecosystem so
// scanning one ecosystem does not suppress refreshing another.
func UpdateDBAsync(dbPath, ecosystem, source string, threshold time.Duration) {
	d, err := db.Open(dbPath)
	if err != nil {
		return
	}
	bucket, ok := osv.EcosystemBucket(ecosystem)
	var needsUpdate bool
	if ok {
		needsUpdate = d.NeedsUpdateEcosystem(context.Background(), bucket, threshold)
	} else {
		needsUpdate = d.NeedsUpdate(context.Background(), threshold)
	}
	d.Close()

	if needsUpdate {
		go func() {
			_ = updateDB(dbPath, ecosystem, source, true)
		}()
	}
}

func updateDB(dbPath, ecosystem, source string, silent bool) error {
	if source == "" {
		source = "osv"
	}

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()

	ctx := context.Background()

	// Resolve which OSV ecosystems to sync. An empty value or "all" syncs every
	// supported ecosystem; otherwise the single named ecosystem is synced.
	var buckets []string
	if ecosystem == "" || strings.EqualFold(ecosystem, "all") {
		buckets = osv.AllEcosystems()
	} else {
		bucket, ok := osv.EcosystemBucket(ecosystem)
		if !ok {
			return fmt.Errorf("unsupported ecosystem %q (want npm, pypi, go, or cargo)", ecosystem)
		}
		buckets = []string{bucket}
	}

	total := 0
	var failures []string
	for _, bucket := range buckets {
		n, err := syncEcosystem(ctx, d, bucket)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", bucket, err))
			logging.Warn("OSV sync failed for ecosystem", "ecosystem", bucket, "error", err)
			if !silent {
				fmt.Fprintf(os.Stderr, "Warning: OSV sync for %s failed: %v\n", bucket, err)
			}
			continue
		}
		total += n
		_ = d.SetMetadata(ctx, "last_update_"+bucket, time.Now().UTC().Format(time.RFC3339))
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	_ = d.SetMetadata(ctx, "last_update", nowStr)

	if !silent {
		fmt.Println("PkgSafe threat DB updated.")
		fmt.Println()
		fmt.Printf("Source: %s\n", source)
		fmt.Printf("Ecosystems: %s\n", strings.Join(buckets, ", "))
		fmt.Printf("Advisory rows written: %d\n", total)
		fmt.Printf("Last updated: %s\n", nowStr)
		fmt.Printf("Database: %s\n", d.Path())
		if len(failures) > 0 {
			fmt.Printf("Failed: %s\n", strings.Join(failures, "; "))
		}

		// Suggested next steps
		color := false
		if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
			color = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
		}
		var bold, cyan, reset string
		if color {
			bold = "\033[1m"
			cyan = "\033[36m"
			reset = "\033[0m"
		}
		fmt.Println()
		fmt.Printf("%sSuggested Next Steps:%s\n", bold, reset)
		fmt.Printf("  • Verify environment setup:     %spkgsafe doctor%s\n", bold+cyan, reset)
		fmt.Printf("  • Scan project dependencies:     %spkgsafe scan-lockfile package-lock.json%s\n", bold+cyan, reset)
	}

	// Fail closed: if every requested ecosystem failed, surface an error rather
	// than reporting a successful "update" that wrote nothing.
	if len(buckets) > 0 && len(failures) == len(buckets) {
		return fmt.Errorf("all ecosystem syncs failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

// syncEcosystem downloads the OSV bulk archive for one ecosystem and writes one
// advisory row per affected package, in batched transactions. Returns the
// number of rows written.
func syncEcosystem(ctx context.Context, d *db.DB, bucket string) (int, error) {
	records, err := osv.FetchBulk(ctx, bucket)
	if err != nil {
		return 0, err
	}

	written := 0
	batch := make([]db.Vulnerability, 0, saveBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := d.SaveVulnerabilities(ctx, batch); err != nil {
			return err
		}
		written += len(batch)
		batch = batch[:0]
		return nil
	}

	for _, rec := range records {
		for _, aff := range rec.Affected {
			if aff.Package.Ecosystem != bucket || aff.Package.Name == "" {
				continue
			}
			batch = append(batch, osv.MapVulnerability(rec, aff.Package.Name, aff.Package.Ecosystem))
			if len(batch) >= saveBatchSize {
				if err := flush(); err != nil {
					return written, err
				}
			}
		}
	}
	if err := flush(); err != nil {
		return written, err
	}
	return written, nil
}
