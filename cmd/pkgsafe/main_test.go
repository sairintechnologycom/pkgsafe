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
