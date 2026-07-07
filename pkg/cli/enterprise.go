package cli

import (
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// This file defines the seams through which the private pkgsafe-enterprise
// distribution injects real implementations of enterprise-only commands. The
// public OSS binary never sets these hooks, so every enterprise command falls
// through to the same stub error it returns today — OSS behavior is unchanged.
//
// The enterprise binary resolves a license once at startup (see
// pkg/license) and registers a handler that closure-captures the
// resolved *license.Entitlement, gating each command. When the license does
// not grant a feature the handler returns handled=false, so the user sees the
// identical OSS "private-enterprise functionality" message — a lapsed or
// missing license degrades premium commands to their OSS stub and never
// disables scanning.

// EnterpriseCommandFunc, when set by a downstream distribution, handles
// enterprise-only CLI subcommands. It is passed the canonical command name
// (e.g. "report team-evidence") and the remaining args, and returns
// handled=false to fall through to the OSS stub. A nil value (the OSS default)
// stubs out every enterprise command.
var EnterpriseCommandFunc func(name string, args []string) (handled bool, err error)

// LoadSignedPolicyFunc, when set, resolves a signed policy archive supplied via
// --policy-pack. The OSS default (nil) keeps signed policy archives as
// private-enterprise functionality.
var LoadSignedPolicyFunc func(policyPack, path, mode, registryConfig string) (policy.Policy, error)

// enterpriseOrElse routes an enterprise subcommand through EnterpriseCommandFunc
// when a downstream distribution registered one and it handles the command;
// otherwise it returns the OSS stub produced by fallback. Keeping fallback a
// thunk lets each call site preserve its exact historical error text.
func enterpriseOrElse(name string, args []string, fallback func() error) error {
	if EnterpriseCommandFunc != nil {
		if handled, err := EnterpriseCommandFunc(name, args); handled {
			return err
		}
	}
	return fallback()
}

// enterpriseOr is enterpriseOrElse with the standard privateEnterpriseCommand
// stub as the fallback.
func enterpriseOr(name string, args []string) error {
	return enterpriseOrElse(name, args, func() error {
		return privateEnterpriseCommand(name)
	})
}
