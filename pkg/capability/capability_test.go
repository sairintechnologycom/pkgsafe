package capability

import (
	"context"
	"testing"
)

func TestLocalGrantsNoDownstreamCapabilities(t *testing.T) {
	enabled, err := (Local{}).Enabled(context.Background(), "example")
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("OSS local provider must not grant downstream capabilities")
	}
}
