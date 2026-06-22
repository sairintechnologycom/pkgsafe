package main

import (
	"reflect"
	"testing"
)

func TestReorderFlagsAllowsTrailingCommandFlags(t *testing.T) {
	got := reorderFlags([]string{"is-number", "--version", "7.0.0", "--json"})
	want := []string{"--version", "7.0.0", "--json", "is-number"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reorderFlags() = %v, want %v", got, want)
	}
}

func TestCIScanCommandRouting(t *testing.T) {
	err := run([]string{"ci", "scan", "--lockfile", "nonexistent-lockfile-for-main-test.json"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	eErr, ok := err.(exitError)
	if !ok {
		t.Fatalf("expected exitError, got %T", err)
	}
	if eErr.code != 5 {
		t.Fatalf("expected exit code 5 (lockfile error), got %d", eErr.code)
	}
}

func TestCIScanUsageError(t *testing.T) {
	err := run([]string{"ci", "scan", "--lockfile", "nonexistent-lockfile-for-main-test.json", "--fail-on", "invalid-value"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	eErr, ok := err.(exitError)
	if !ok {
		t.Fatalf("expected exitError, got %T", err)
	}
	if eErr.code != 2 {
		t.Fatalf("expected exit code 2 (usage error), got %d", eErr.code)
	}
}
