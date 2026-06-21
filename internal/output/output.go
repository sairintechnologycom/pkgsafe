package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

func Write(w io.Writer, result types.ScanResult, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(string(result.Decision)))
	fmt.Fprintf(w, "Package: %s/%s@%s\n", result.Package.Ecosystem, result.Package.Name, emptyLatest(result.Package.Version))
	fmt.Fprintf(w, "Risk Score: %d/100\n", result.Score)
	if len(result.Lifecycle) > 0 {
		fmt.Fprintf(w, "Lifecycle Scripts: %s\n", strings.Join(result.Lifecycle, ", "))
	}
	if len(result.Reasons) > 0 {
		fmt.Fprintln(w, "\nReasons:")
		for _, r := range result.Reasons {
			fmt.Fprintf(w, "- [%s] %s", strings.ToUpper(r.Severity), r.Description)
			if r.Evidence != "" {
				fmt.Fprintf(w, " — %s", r.Evidence)
			}
			if r.ScoreImpact != 0 {
				fmt.Fprintf(w, " (+%d)", r.ScoreImpact)
			}
			fmt.Fprintln(w)
		}
	}
	if len(result.SafeAlternates) > 0 {
		fmt.Fprintf(w, "\nPossible safe alternatives: %s\n", strings.Join(result.SafeAlternates, ", "))
	}
	fmt.Fprintf(w, "\nRecommended Action:\n%s\n", recommendedAction(result.Decision))
	return nil
}

func emptyLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

func recommendedAction(decision types.Decision) string {
	switch decision {
	case types.DecisionBlock:
		return "Do not install this package."
	case types.DecisionWarn:
		return "Review package behavior before installing."
	default:
		return "Package appears safe to install based on current checks."
	}
}
