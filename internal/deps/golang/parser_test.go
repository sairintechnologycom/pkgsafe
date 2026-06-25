package golang

import (
	"reflect"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := []byte(`module github.com/niyam-ai/pkgsafe

go 1.25.0

require (
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
)

require github.com/google/uuid v1.6.0
require github.com/mattn/go-isatty v0.0.20 // inline comment
`)

	expected := []Dependency{
		{Name: "github.com/Masterminds/semver/v3", Version: "v3.5.0"},
		{Name: "github.com/dustin/go-humanize", Version: "v1.0.1"},
		{Name: "github.com/google/uuid", Version: "v1.6.0"},
		{Name: "github.com/mattn/go-isatty", Version: "v0.0.20"},
	}

	got, err := ParseGoMod(content)
	if err != nil {
		t.Fatalf("unexpected error parsing go.mod: %v", err)
	}

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("ParseGoMod() =\n%+v\nwant\n%+v", got, expected)
	}
}
