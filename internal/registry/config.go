package registry

import (
	"fmt"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"gopkg.in/yaml.v3"
)

type RegistryAuth = policy.RegistryAuth
type RegistryTrust = policy.RegistryTrust
type RegistryConfig = policy.RegistryConfig
type RegistriesConfig = policy.RegistriesConfig

func ParseRegistries(data []byte) (RegistriesConfig, error) {
	var cfg RegistriesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unmarshal registries: %w", err)
	}
	return cfg, nil
}
