package ci

import (
	"sync"

	"github.com/niyam-ai/pkgsafe/internal/logging"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

// defaultScanConcurrency bounds how many dependency scans run at once. Scans are
// network-bound, so a small pool keeps registries/OSV happy while cutting the
// wall-clock of large lockfiles.
const defaultScanConcurrency = 8

// parallelScan scans items concurrently with a bounded worker pool, preserving
// input order in the returned slice. It never aborts the whole run on a single
// failure: a failed scan is recorded to stderr and surfaced as a
// DecisionUnknown result so one bad dependency can't blind the entire report
// (and can't be mistaken for a clean ALLOW).
//
// key extracts (name, version) from an item; scan performs the actual scan.
// scan must be safe for concurrent use — callers pass a closure that copies the
// scanner per call.
func parallelScan[T any](items []T, key func(T) (string, string), scan func(name, version string) (types.ScanResult, error)) []types.ScanResult {
	out := make([]types.ScanResult, len(items))
	sem := make(chan struct{}, defaultScanConcurrency)
	var wg sync.WaitGroup
	for i, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, item T) {
			defer wg.Done()
			defer func() { <-sem }()
			name, version := key(item)
			res, err := scan(name, version)
			if err != nil {
				logging.Warn("dependency scan failed; marking unknown and continuing",
					"package", name, "version", version, "error", err)
				res = unknownScanResult(name, version)
			}
			out[i] = res
		}(i, item)
	}
	wg.Wait()
	return out
}

// unknownScanResult represents a dependency that could not be scanned. It is
// explicitly DecisionUnknown — never a clean ALLOW.
func unknownScanResult(name, version string) types.ScanResult {
	return types.ScanResult{
		Package:  types.PackageIdentity{Name: name, Version: version},
		Decision: types.DecisionUnknown,
		Reasons: []types.Reason{{
			ID:          "package_not_scanned",
			Severity:    "medium",
			Description: "Package could not be scanned; risk is unknown.",
		}},
	}
}
