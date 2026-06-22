package sandbox

import "github.com/niyam-ai/pkgsafe/internal/types"

type SandboxResult struct {
	ScriptName      string                 `json:"name"`
	ExitCode        int                    `json:"exit_code"`
	TimedOut        bool                   `json:"timed_out"`
	DurationMs      int64                  `json:"duration_ms"`
	FileReads       []FileAccess           `json:"file_reads,omitempty"`
	FileWrites      []FileAccess           `json:"file_writes,omitempty"`
	ProcessExecs    []ProcessExec          `json:"process_execs,omitempty"`
	NetworkAttempts []NetworkAttempt       `json:"network_attempts,omitempty"`
	EnvAccesses     []EnvAccess            `json:"env_accesses,omitempty"`
	CanaryAccesses  []CanaryAccess         `json:"canary_accesses,omitempty"`
	Findings        []types.SandboxFinding `json:"findings,omitempty"`
}

type FileAccess struct {
	Path string `json:"path"`
}

type ProcessExec struct {
	Command string `json:"command"`
}

type NetworkAttempt struct {
	Host string `json:"host"`
}

type EnvAccess struct {
	Name string `json:"name"`
}

type CanaryAccess struct {
	Path string `json:"path"`
}
