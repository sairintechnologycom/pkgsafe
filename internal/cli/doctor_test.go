package cli

import "testing"

func TestRunDoctorSkipNetwork(t *testing.T) {
	rep := RunDoctor(DoctorOptions{SkipNetwork: true})
	if len(rep.Checks) == 0 {
		t.Fatal("expected doctor checks")
	}

	// Every connected endpoint must be reported as skipped (not silently
	// dropped) when the network check is skipped.
	skipped := map[string]bool{}
	for _, check := range rep.Checks {
		if check.Status == "skip" {
			skipped[check.Name] = true
		}
	}
	for _, ep := range connectedEndpoints() {
		if !skipped[ep.name] {
			t.Errorf("expected %q to be skipped, got checks %+v", ep.name, rep.Checks)
		}
	}
}

func TestConnectedEndpointsCoverNpmAndPyPIAndOSV(t *testing.T) {
	names := map[string]bool{}
	for _, ep := range connectedEndpoints() {
		names[ep.name] = true
	}
	for _, want := range []string{"OSV network", "npm registry", "PyPI registry"} {
		if !names[want] {
			t.Errorf("connected endpoints missing %q; have %v", want, names)
		}
	}
}
