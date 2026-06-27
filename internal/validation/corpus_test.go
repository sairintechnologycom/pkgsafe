package validation

import (
	"os"
	"testing"
)

func TestValidationSuite(t *testing.T) {
	tmp, err := os.MkdirTemp("", "pkgsafe-validation-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	goldenFile := tmp + "-golden.json"
	defer os.Remove(goldenFile)

	err = RunCorpus(tmp, goldenFile, false, false)
	if err != nil {
		t.Errorf("RunCorpus failed: %v", err)
	}
}
