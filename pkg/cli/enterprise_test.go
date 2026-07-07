package cli

import (
	"errors"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// resetEnterpriseHooks clears the injection seams so a test starts from the
// OSS default and cannot leak state into sibling tests.
func resetEnterpriseHooks(t *testing.T) {
	t.Helper()
	EnterpriseCommandFunc = nil
	LoadSignedPolicyFunc = nil
	t.Cleanup(func() {
		EnterpriseCommandFunc = nil
		LoadSignedPolicyFunc = nil
	})
}

// TestOSSDefault_EnterpriseCommandsStubbedByteIdentical asserts that with no
// hook registered (the public binary) every enterprise command returns the
// exact historical stub message.
func TestOSSDefault_EnterpriseCommandsStubbedByteIdentical(t *testing.T) {
	resetEnterpriseHooks(t)

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"team-evidence"}, "report team-evidence is private-enterprise functionality; use pkgsafe-enterprise"},
		{[]string{"exceptions"}, "report exceptions is private-enterprise functionality; use pkgsafe-enterprise"},
		{[]string{"overrides"}, "report overrides is private-enterprise functionality; use pkgsafe-enterprise"},
		{[]string{"policy"}, "report policy is private-enterprise functionality; use pkgsafe-enterprise"},
		{[]string{"siem-export"}, "report siem-export is private-enterprise functionality; use pkgsafe-enterprise"},
		{[]string{"servicenow-export"}, "report servicenow-export is private-enterprise functionality; use pkgsafe-enterprise"},
		{[]string{"azure-devops-export"}, "report azure-devops-export is private-enterprise functionality; use pkgsafe-enterprise"},
	}
	for _, c := range cases {
		err := cmdReport(c.args)
		if err == nil || err.Error() != c.want {
			t.Errorf("cmdReport(%v) = %v, want %q", c.args, err, c.want)
		}
	}
}

func TestOSSDefault_PolicyPackStubbedByteIdentical(t *testing.T) {
	resetEnterpriseHooks(t)
	want := "signed policy archive commands are private-enterprise functionality; use pkgsafe-enterprise"
	err := cmdPolicy([]string{"pack", "some.zip"})
	if err == nil || err.Error() != want {
		t.Fatalf("policy pack = %v, want %q", err, want)
	}
}

func TestOSSDefault_SignedPolicyLoadStubbedByteIdentical(t *testing.T) {
	resetEnterpriseHooks(t)
	want := "signed policy archives are private-enterprise functionality; use pkgsafe-enterprise"
	_, err := loadPolicy("", "", "pack.zip", "")
	if err == nil || err.Error() != want {
		t.Fatalf("loadPolicy with pack = %v, want %q", err, want)
	}
}

// TestEnterpriseHook_RoutesAndAllows verifies a registered handler receives the
// command and its "allow" result (nil error) propagates.
func TestEnterpriseHook_RoutesAndAllows(t *testing.T) {
	resetEnterpriseHooks(t)

	var gotName string
	var gotArgs []string
	EnterpriseCommandFunc = func(name string, args []string) (bool, error) {
		gotName, gotArgs = name, args
		return true, nil // handled, allowed
	}

	if err := cmdReport([]string{"team-evidence", "--history-dir", "x"}); err != nil {
		t.Fatalf("expected nil error when handler allows, got %v", err)
	}
	if gotName != "report team-evidence" {
		t.Errorf("handler name = %q, want %q", gotName, "report team-evidence")
	}
	if len(gotArgs) != 2 || gotArgs[0] != "--history-dir" || gotArgs[1] != "x" {
		t.Errorf("handler args = %v, want [--history-dir x]", gotArgs)
	}
}

// TestEnterpriseHook_RoutesAndDenies verifies a handler's denial error (e.g.
// license withheld) propagates unchanged.
func TestEnterpriseHook_RoutesAndDenies(t *testing.T) {
	resetEnterpriseHooks(t)
	denied := errors.New("report team-evidence requires a valid pkgsafe-enterprise license")
	EnterpriseCommandFunc = func(name string, args []string) (bool, error) {
		return true, denied
	}
	err := cmdReport([]string{"team-evidence"})
	if !errors.Is(err, denied) {
		t.Fatalf("expected denial error to propagate, got %v", err)
	}
}

// TestEnterpriseHook_FallThroughWhenUnhandled verifies handled=false degrades
// to the OSS stub — the fail-open path when a handler defers.
func TestEnterpriseHook_FallThroughWhenUnhandled(t *testing.T) {
	resetEnterpriseHooks(t)
	called := false
	EnterpriseCommandFunc = func(name string, args []string) (bool, error) {
		called = true
		return false, nil // not handled → fall through
	}
	want := "report team-evidence is private-enterprise functionality; use pkgsafe-enterprise"
	err := cmdReport([]string{"team-evidence"})
	if !called {
		t.Error("handler should have been consulted")
	}
	if err == nil || err.Error() != want {
		t.Fatalf("fall-through = %v, want stub %q", err, want)
	}
}

// TestLoadSignedPolicyHook_Routes verifies a registered signed-policy loader is
// used for --policy-pack.
func TestLoadSignedPolicyHook_Routes(t *testing.T) {
	resetEnterpriseHooks(t)
	sentinel := policy.Policy{Mode: "enterprise-signed"}
	var gotPack string
	LoadSignedPolicyFunc = func(policyPack, path, mode, registryConfig string) (policy.Policy, error) {
		gotPack = policyPack
		return sentinel, nil
	}
	got, err := loadPolicy("", "", "acme.zip", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPack != "acme.zip" {
		t.Errorf("loader got pack %q, want acme.zip", gotPack)
	}
	if got.Mode != sentinel.Mode {
		t.Errorf("loadPolicy returned %+v, want injected sentinel", got)
	}
}
