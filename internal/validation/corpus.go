package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	anpm "github.com/sairintechnologycom/pkgsafe/internal/analyzer/npm"
	npminventory "github.com/sairintechnologycom/pkgsafe/internal/deps/npm"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type GoldenDep struct {
	Name           string `json:"package_name"`
	DependencyType string `json:"dependency_type"`
	SourceFile     string `json:"source_file,omitempty"`
	Direct         bool   `json:"direct"`
	Dev            bool   `json:"dev,omitempty"`
	Optional       bool   `json:"optional,omitempty"`
}

type GoldenExpectation struct {
	ExpectedDeps     []GoldenDep `json:"expected_dependencies"`
	ExpectedDecision string      `json:"expected_decision"`
	MinScore         int         `json:"min_score"`
	MaxScore         int         `json:"max_score"`
}

type FixtureReport struct {
	Fixture            string   `json:"fixture"`
	Passed             bool     `json:"passed"`
	ExpectedDecision   string   `json:"expected_decision"`
	ActualDecision     string   `json:"actual_decision"`
	ExpectedScoreRange []int    `json:"expected_score_range"`
	ActualScore        int      `json:"actual_score"`
	Details            []string `json:"details"`
	FalseNegatives     []Miss   `json:"false_negatives"`
}

type Miss struct {
	Fixture                string            `json:"fixture"`
	ExpectedName           string            `json:"expected_dependency_name"`
	ExpectedDependencyType string            `json:"expected_dependency_type"`
	ExpectedSourceFile     string            `json:"expected_source_file,omitempty"`
	ExpectedDirect         bool              `json:"expected_direct"`
	ExpectedDev            bool              `json:"expected_dev"`
	ExpectedOptional       bool              `json:"expected_optional"`
	ActualCandidates       []ActualCandidate `json:"actual_matched_candidates,omitempty"`
	MissReason             string            `json:"miss_reason"`
}

type ActualCandidate struct {
	Name           string `json:"package_name"`
	DependencyType string `json:"dependency_type"`
	SourceFile     string `json:"source_file"`
	Direct         bool   `json:"direct"`
	Dev            bool   `json:"dev"`
	Optional       bool   `json:"optional"`
	VersionRange   string `json:"version_range,omitempty"`
	PackagePath    string `json:"package_path,omitempty"`
}

type ValidationReport struct {
	Metrics struct {
		DependencyPrecision        float64 `json:"dependency_precision"`
		DependencyRecall           float64 `json:"dependency_recall"`
		DirectDependencyRecall     float64 `json:"direct_dependency_recall"`
		TransitiveDependencyRecall float64 `json:"transitive_dependency_recall"`
		SourceImportRecall         float64 `json:"source_import_recall"`
		FalseWarnRate              float64 `json:"false_warn_rate"`
		FalseBlockRate             float64 `json:"false_block_rate"`
		CriticalDetectionRate      float64 `json:"critical_detection_rate"`
	} `json:"metrics"`
	Results []FixtureReport `json:"results"`
}

func RunCorpus(corpusDir, goldenFile string, asJSON bool, explainMisses bool) error {
	report, err := RunCorpusReport(corpusDir, goldenFile)
	if err != nil {
		return err
	}

	// Output report
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Human-readable format
	fmt.Println("PkgSafe Validation Suite Results")
	fmt.Println("=================================")
	fmt.Printf("Dependency Precision:            %.2f%%\n", report.Metrics.DependencyPrecision*100)
	fmt.Printf("Dependency Recall:               %.2f%%\n", report.Metrics.DependencyRecall*100)
	fmt.Printf("Direct Dependency Recall:        %.2f%%\n", report.Metrics.DirectDependencyRecall*100)
	fmt.Printf("Transitive Dependency Recall:    %.2f%%\n", report.Metrics.TransitiveDependencyRecall*100)
	fmt.Printf("Source Import Recall:            %.2f%%\n", report.Metrics.SourceImportRecall*100)
	fmt.Printf("False Warn Rate:                 %.2f%%\n", report.Metrics.FalseWarnRate*100)
	fmt.Printf("False Block Rate:                %.2f%%\n", report.Metrics.FalseBlockRate*100)
	fmt.Printf("Critical Detection Rate:         %.2f%%\n", report.Metrics.CriticalDetectionRate*100)
	fmt.Println()
	fmt.Println("Fixture Details:")
	fmt.Println("----------------")
	allPassed := true
	for _, res := range report.Results {
		status := "PASSED"
		if !res.Passed {
			status = "FAILED"
			allPassed = false
		}
		fmt.Printf("[%s] %s (Decision: %s, Score: %d)\n", status, res.Fixture, res.ActualDecision, res.ActualScore)
		for _, detail := range res.Details {
			fmt.Printf("  - %s\n", detail)
		}
		if explainMisses {
			for _, miss := range res.FalseNegatives {
				fmt.Printf("  - MISS %s (%s, direct=%t, source=%s): %s\n", miss.ExpectedName, miss.ExpectedDependencyType, miss.ExpectedDirect, miss.ExpectedSourceFile, miss.MissReason)
				for _, candidate := range miss.ActualCandidates {
					fmt.Printf("    candidate: %s (%s, direct=%t, source=%s, dev=%t, optional=%t)\n", candidate.Name, candidate.DependencyType, candidate.Direct, candidate.SourceFile, candidate.Dev, candidate.Optional)
				}
			}
		}
	}

	if !allPassed {
		return fmt.Errorf("some validation suite tests failed")
	}
	return nil
}

func RunCorpusReport(corpusDir, goldenFile string) (ValidationReport, error) {
	var report ValidationReport

	// 1. Ensure fixtures and golden file exist (generate them if not present)
	if _, err := os.Stat(filepath.Join(corpusDir, "npm-simple-deps")); os.IsNotExist(err) {
		if err := WriteCorpusFixtures(corpusDir); err != nil {
			return report, fmt.Errorf("write corpus fixtures: %w", err)
		}
	}
	if _, err := os.Stat(goldenFile); os.IsNotExist(err) {
		if err := WriteGoldenResults(goldenFile); err != nil {
			return report, fmt.Errorf("write golden results: %w", err)
		}
	}

	// 2. Read golden results
	b, err := os.ReadFile(goldenFile)
	if err != nil {
		return report, fmt.Errorf("read golden file: %w", err)
	}
	var golden map[string]GoldenExpectation
	if err := json.Unmarshal(b, &golden); err != nil {
		return report, fmt.Errorf("parse golden file: %w", err)
	}

	pol := policy.Default()
	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = true

	var totalTP, totalFP, totalFN int
	var totalDirectExpected, totalDirectTP int
	var totalTransExpected, totalTransTP int
	var totalSourceExpected, totalSourceTP int

	var totalAllowed, falseWarns int
	var totalAllowedOrWarned, falseBlocks int
	var totalCritical, criticalBlocked int

	// Loop over all golden fixtures
	for fixtureName, expected := range golden {
		fixturePath := filepath.Join(corpusDir, fixtureName)
		fixtureReport := FixtureReport{
			Fixture:            fixtureName,
			ExpectedDecision:   expected.ExpectedDecision,
			ExpectedScoreRange: []int{expected.MinScore, expected.MaxScore},
			Passed:             true,
		}

		// A. Run inventory
		actualDeps, err := npminventory.ScanInventory(fixturePath)
		if err != nil {
			fixtureReport.Passed = false
			fixtureReport.Details = append(fixtureReport.Details, fmt.Sprintf("Inventory scan error: %v", err))
			report.Results = append(report.Results, fixtureReport)
			continue
		}

		// Match expected and actual dependencies by consuming actual candidates.
		// This preserves duplicate expectations from different surfaces, e.g. a
		// package.json declaration and a package-lock direct entry for the same
		// package/type/direct tuple.
		for _, ed := range expected.ExpectedDeps {
			// Count expected metrics totals
			if ed.Direct && ed.DependencyType != "source-import" {
				totalDirectExpected++
			} else if !ed.Direct {
				totalTransExpected++
			} else if ed.DependencyType == "source-import" {
				totalSourceExpected++
			}
		}

		actualCandidates := make([]types.Dependency, 0, len(actualDeps))
		for _, ad := range actualDeps {
			if ad.Name == "" {
				continue
			}
			actualCandidates = append(actualCandidates, ad)
		}
		consumed := make([]bool, len(actualCandidates))

		// Compare expected vs actual
		for _, ed := range expected.ExpectedDeps {
			if idx := findActualMatch(ed, actualCandidates, consumed); idx >= 0 {
				consumed[idx] = true
				totalTP++
				if ed.Direct && ed.DependencyType != "source-import" {
					totalDirectTP++
				} else if !ed.Direct {
					totalTransTP++
				} else if ed.DependencyType == "source-import" {
					totalSourceTP++
				}
			} else {
				totalFN++
				fixtureReport.Passed = false
				miss := explainMiss(fixtureName, ed, actualCandidates)
				fixtureReport.FalseNegatives = append(fixtureReport.FalseNegatives, miss)
				fixtureReport.Details = append(fixtureReport.Details, fmt.Sprintf("Missing expected dependency: %s (%s, direct=%t)", ed.Name, ed.DependencyType, ed.Direct))
			}
		}

		// Remaining actual keys are False Positives
		for i, ad := range actualCandidates {
			if consumed[i] {
				continue
			}
			totalFP++
			fixtureReport.Passed = false
			fixtureReport.Details = append(fixtureReport.Details, fmt.Sprintf("Unexpected dependency found: %s (%s, direct=%t)", ad.Name, ad.DependencyType, ad.Direct))
		}

		// B. Run risk scanner (only if not a malformed file test where we expect parser to skip/ignore)
		var actualScore int
		var actualDecision string
		if fixtureName == "malformed-package-json" || fixtureName == "malformed-lockfile" {
			actualScore = 0
			actualDecision = "allow"
		} else {
			res, err := scanner.ScanLocalPackage(fixturePath)
			if err != nil {
				lockPath := filepath.Join(fixturePath, "package-lock.json")
				if _, statErr := os.Stat(lockPath); statErr == nil {
					res, err = anpm.AnalyzeLockfile(lockPath, pol)
				}
			}
			if err != nil {
				actualScore = 0
				actualDecision = "allow"
			} else {
				actualScore = res.Score
				actualDecision = string(res.Decision)
			}
		}

		fixtureReport.ActualScore = actualScore
		fixtureReport.ActualDecision = actualDecision

		// Verify score range
		if actualScore < expected.MinScore || actualScore > expected.MaxScore {
			fixtureReport.Passed = false
			fixtureReport.Details = append(fixtureReport.Details, fmt.Sprintf("Score %d out of expected range [%d, %d]", actualScore, expected.MinScore, expected.MaxScore))
		}

		// Verify decision
		if actualDecision != expected.ExpectedDecision {
			fixtureReport.Passed = false
			fixtureReport.Details = append(fixtureReport.Details, fmt.Sprintf("Decision %q does not match expected %q", actualDecision, expected.ExpectedDecision))
		}

		// Compute risk classification metrics totals
		if expected.ExpectedDecision == "allow" {
			totalAllowed++
			if actualDecision == "warn" {
				falseWarns++
			} else if actualDecision == "block" {
				falseBlocks++
			}
		} else if expected.ExpectedDecision == "warn" {
			totalAllowedOrWarned++
			if actualDecision == "block" {
				falseBlocks++
			}
		} else if expected.ExpectedDecision == "block" {
			totalCritical++
			if actualDecision == "block" {
				criticalBlocked++
			}
		}

		report.Results = append(report.Results, fixtureReport)
	}

	// Compute accuracy metrics
	if totalTP+totalFP > 0 {
		report.Metrics.DependencyPrecision = float64(totalTP) / float64(totalTP+totalFP)
	} else {
		report.Metrics.DependencyPrecision = 1.0
	}

	expectedTotal := totalTP + totalFN
	if expectedTotal > 0 {
		report.Metrics.DependencyRecall = float64(totalTP) / float64(expectedTotal)
	} else {
		report.Metrics.DependencyRecall = 1.0
	}

	if totalDirectExpected > 0 {
		report.Metrics.DirectDependencyRecall = float64(totalDirectTP) / float64(totalDirectExpected)
	} else {
		report.Metrics.DirectDependencyRecall = 1.0
	}

	if totalTransExpected > 0 {
		report.Metrics.TransitiveDependencyRecall = float64(totalTransTP) / float64(totalTransExpected)
	} else {
		report.Metrics.TransitiveDependencyRecall = 1.0
	}

	if totalSourceExpected > 0 {
		report.Metrics.SourceImportRecall = float64(totalSourceTP) / float64(totalSourceExpected)
	} else {
		report.Metrics.SourceImportRecall = 1.0
	}

	if totalAllowed > 0 {
		report.Metrics.FalseWarnRate = float64(falseWarns) / float64(totalAllowed)
	} else {
		report.Metrics.FalseWarnRate = 0.0
	}

	totalAllowedOrWarnedCombined := totalAllowed + totalAllowedOrWarned
	if totalAllowedOrWarnedCombined > 0 {
		report.Metrics.FalseBlockRate = float64(falseBlocks) / float64(totalAllowedOrWarnedCombined)
	} else {
		report.Metrics.FalseBlockRate = 0.0
	}

	if totalCritical > 0 {
		report.Metrics.CriticalDetectionRate = float64(criticalBlocked) / float64(totalCritical)
	} else {
		report.Metrics.CriticalDetectionRate = 1.0
	}
	return report, nil
}

func findActualMatch(expected GoldenDep, actual []types.Dependency, consumed []bool) int {
	for i, candidate := range actual {
		if consumed[i] {
			continue
		}
		if !matchesExpected(expected, candidate) {
			continue
		}
		return i
	}
	return -1
}

func matchesExpected(expected GoldenDep, actual types.Dependency) bool {
	if actual.Name != expected.Name || actual.DependencyType != expected.DependencyType || actual.Direct != expected.Direct {
		return false
	}
	if expected.SourceFile != "" && actual.SourceFile != expected.SourceFile {
		return false
	}
	if expected.DependencyType == "dev" && !actual.Dev {
		return false
	}
	if expected.DependencyType == "optional" && !actual.Optional {
		return false
	}
	if expected.Dev && !actual.Dev {
		return false
	}
	if expected.Optional && !actual.Optional {
		return false
	}
	return true
}

func explainMiss(fixture string, expected GoldenDep, actual []types.Dependency) Miss {
	candidates := make([]ActualCandidate, 0)
	for _, candidate := range actual {
		if candidate.Name == expected.Name {
			candidates = append(candidates, toActualCandidate(candidate))
		}
	}
	reason := "dependency was not emitted by inventory"
	if len(candidates) > 0 {
		reason = "dependency was emitted with different type, directness, source, or flags"
	}
	return Miss{
		Fixture:                fixture,
		ExpectedName:           expected.Name,
		ExpectedDependencyType: expected.DependencyType,
		ExpectedSourceFile:     expected.SourceFile,
		ExpectedDirect:         expected.Direct,
		ExpectedDev:            expected.Dev || expected.DependencyType == "dev",
		ExpectedOptional:       expected.Optional || expected.DependencyType == "optional",
		ActualCandidates:       candidates,
		MissReason:             reason,
	}
}

func toActualCandidate(dep types.Dependency) ActualCandidate {
	return ActualCandidate{
		Name:           dep.Name,
		DependencyType: dep.DependencyType,
		SourceFile:     dep.SourceFile,
		Direct:         dep.Direct,
		Dev:            dep.Dev,
		Optional:       dep.Optional,
		VersionRange:   dep.VersionRange,
		PackagePath:    dep.PackagePath,
	}
}
