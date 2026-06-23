package git

import (
	"testing"
)

func TestRedactGitURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://user:password@github.com/org/repo.git", "https://[REDACTED]@github.com/org/repo.git"},
		{"https://token@github.com/org/repo.git", "https://[REDACTED]@github.com/org/repo.git"},
		{"http://user:pass@gitlab.com/org/repo.git", "http://[REDACTED]@gitlab.com/org/repo.git"},
	}

	for _, tc := range tests {
		got := RedactGitURL(tc.input)
		if got != tc.expected {
			t.Errorf("RedactGitURL(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestDetectMetadata(t *testing.T) {
	meta, err := DetectMetadata(".")
	if err != nil {
		t.Fatalf("DetectMetadata(\".\") returned error: %v", err)
	}
	if meta.Root == "" || meta.Root == "unknown" {
		t.Errorf("expected detected Root to be populated, got %q", meta.Root)
	}
	if meta.Branch == "" || meta.Branch == "unknown" {
		t.Errorf("expected detected Branch to be populated, got %q", meta.Branch)
	}
	if meta.Commit == "" || meta.Commit == "unknown" {
		t.Errorf("expected detected Commit to be populated, got %q", meta.Commit)
	}
}
