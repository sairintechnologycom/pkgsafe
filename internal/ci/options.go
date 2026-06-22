package ci

import "time"

type ScanOptions struct {
	LockfilePath         string
	DependencyFile       string
	Ecosystem            string
	PolicyPath           string
	Mode                 string // audit, warn, block
	FailOn               string // none, warn, block
	JsonOutput           string
	SarifOutput          string
	SummaryOutput        string
	ChangedOnlySpecified bool
	ChangedOnly          bool
	Baseline             string
	SandboxSpecified     bool
	Sandbox              bool
	Offline              bool
	Timeout              time.Duration
}
