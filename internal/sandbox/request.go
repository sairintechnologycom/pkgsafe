package sandbox

import (
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

type SandboxRequest struct {
	Ecosystem     string
	PackageName   string
	Version       string
	PackagePath   string
	ScriptName    string
	ScriptCommand string
	Timeout       time.Duration
	NetworkMode   string
	KeepSandbox   bool
	Policy        policy.Policy
}
