// Package capability defines a neutral extension contract for downstream
// distributions. The OSS module contains no commercial entitlement parsing,
// feature catalog, premium dispatch, or hidden capability implementation.
package capability

import "context"

// Provider answers whether a downstream-defined capability is available.
// Capability names and commercial policy belong to the downstream module.
type Provider interface {
	Enabled(ctx context.Context, capability string) (bool, error)
}

// Local is the OSS provider. It grants no downstream capabilities and has no
// external dependencies or hidden policy.
type Local struct{}

func (Local) Enabled(context.Context, string) (bool, error) { return false, nil }
