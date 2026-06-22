package intel

import (
	"strings"
)

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func NormalizeSeverity(osvSeverity []OSVSeverity, dbSpecific, ecoSpecific map[string]any) string {
	for _, m := range []map[string]any{dbSpecific, ecoSpecific} {
		if m == nil {
			continue
		}
		if s, ok := m["severity"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "low":
				return "low"
			case "medium", "moderate":
				return "medium"
			case "high":
				return "high"
			case "critical":
				return "critical"
			}
		}
		if cvss, ok := m["cvss"].(map[string]any); ok {
			if scoreVal, ok := cvss["score"]; ok {
				if scoreFloat, ok := toFloat(scoreVal); ok {
					return cvssScoreToSeverity(scoreFloat)
				}
			}
			if s, ok := cvss["severity"].(string); ok {
				switch strings.ToLower(strings.TrimSpace(s)) {
				case "low":
					return "low"
				case "medium", "moderate":
					return "medium"
				case "high":
					return "high"
				case "critical":
					return "critical"
				}
			}
		}
	}

	for _, sev := range osvSeverity {
		if scoreFloat, ok := toFloat(sev.Score); ok {
			return cvssScoreToSeverity(scoreFloat)
		}
		// If score is a CVSS vector, we can scan for some key indicators or fallback to high if it has C:H/I:H/A:H
		vector := strings.ToUpper(sev.Score)
		if strings.Contains(vector, "C:H") && strings.Contains(vector, "I:H") {
			return "high"
		}
	}
	return "medium"
}

func toFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	}
	return 0, false
}

func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
