package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type FileInfoRecord struct {
	Size       int64
	ModTime    time.Time
	AccessTime time.Time
}

func RecordFileInfo(sandboxRoot string) map[string]FileInfoRecord {
	records := make(map[string]FileInfoRecord)
	for relPath := range Canaries {
		path := filepath.Join(sandboxRoot, relPath)
		fi, err := os.Stat(path)
		if err == nil {
			records[relPath] = FileInfoRecord{
				Size:       fi.Size(),
				ModTime:    fi.ModTime(),
				AccessTime: getAccessTime(fi),
			}
		}
	}
	return records
}

func checkCanaryAccesses(sandboxRoot string, before map[string]FileInfoRecord, stdout, stderr, cmdStr string) (accessed []string, modified []string) {
	for relPath, oldRecord := range before {
		path := filepath.Join(sandboxRoot, relPath)
		fi, err := os.Stat(path)
		if err == nil {
			newAtime := getAccessTime(fi)
			if newAtime.After(oldRecord.AccessTime) {
				accessed = append(accessed, relPath)
			}
			if fi.Size() != oldRecord.Size || fi.ModTime().After(oldRecord.ModTime) {
				modified = append(modified, relPath)
			}
		}
	}

	tokenMap := map[string]string{
		"AKIAIOSFODNN7EXAMPLE":                  "home/.aws/credentials",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE": "home/.aws/credentials",
		"npm_s7Y2Rz9F3Kj1Lm5Np9Qr2St8Uv4Wx1Yz":  "home/.npmrc",
		"pypi-AgFBQUFBQUFBQUFBQUFBQUFBQUFBQUF":  "home/.pypirc",
		"k8s-token-f8b2c4e6a8d0":                "home/.kube/config",
		"YWRtaW46c3VwZXJzZWNyZXRwYXNzd29yZA==":  "home/.docker/config.json",
		"fake_token_data":                       "home/.azure/accessTokens.json",
		"GOCSPX-fake-secret-key-12345":          "home/.config/gcloud/application_default_credentials.json",
		"hvs.CAESIEx1234567890abcdef":           "home/.vault-token",
		"sec_9f3d8a1c6b5e4072f8a1":              "workspace/.env",
		"sec_7a2b9c3d5e8f4160a2c5":              "workspace/.env.local",
	}

	for token, relPath := range tokenMap {
		if strings.Contains(stdout, token) || strings.Contains(stderr, token) {
			found := false
			for _, a := range accessed {
				if a == relPath {
					found = true
					break
				}
			}
			if !found {
				accessed = append(accessed, relPath)
			}
		}
	}

	for relPath := range before {
		basename := filepath.Base(relPath)
		if strings.Contains(cmdStr, basename) {
			found := false
			for _, a := range accessed {
				if a == relPath {
					found = true
					break
				}
			}
			if !found {
				accessed = append(accessed, relPath)
			}
		}
	}

	return accessed, modified
}

func AnalyzeBehavior(req SandboxRequest, sandboxRoot string, beforeCanaries map[string]FileInfoRecord, exitCode int, timedOut bool, stdout, stderr string) []types.SandboxFinding {
	var findings []types.SandboxFinding

	addFinding := func(ruleID, desc string) {
		rule, ok := policy.RuleFor(req.Policy, ruleID)
		if !ok {
			return
		}
		findings = append(findings, types.SandboxFinding{
			RuleID:      ruleID,
			Severity:    rule.Severity,
			Score:       rule.Score,
			Description: desc,
		})
	}

	cmdLower := strings.ToLower(req.ScriptCommand)
	outLower := strings.ToLower(stdout + "\n" + stderr)

	if exitCode != 0 {
		addFinding("lifecycle_script_nonzero_exit", "Lifecycle script exited with non-zero exit code")
	}

	accessed, _ := checkCanaryAccesses(sandboxRoot, beforeCanaries, stdout, stderr, req.ScriptCommand)

	awsRead := false
	sshRead := false
	npmRead := false
	dotenvRead := false
	anyCanaryRead := false

	for _, p := range accessed {
		anyCanaryRead = true
		if strings.Contains(p, "aws") {
			awsRead = true
		}
		if strings.Contains(p, "ssh") {
			sshRead = true
		}
		if strings.Contains(p, "npmrc") {
			npmRead = true
		}
		if strings.Contains(p, ".env") {
			dotenvRead = true
		}
	}

	if anyCanaryRead {
		addFinding("credential_canary_read", "Lifecycle script attempted to read credential canary")
	}
	if awsRead {
		addFinding("env_secret_access", "Lifecycle script attempted to access environment secrets")
	}
	if sshRead {
		addFinding("ssh_key_access", "Lifecycle script attempted to access SSH keys")
	}
	if npmRead {
		addFinding("npm_token_access", "Lifecycle script attempted to access npm registry token")
	}
	if dotenvRead {
		addFinding("env_secret_access", "Lifecycle script attempted to access environment secrets")
	}

	hasNetworkCmd := false
	netCmds := []string{
		"curl", "wget", "invoke-webrequest", "fetch", "axios",
		"http.request", "https.request", "net.connect", "nc", "ncat", "telnet",
	}
	for _, cmd := range netCmds {
		if strings.Contains(cmdLower, cmd) || strings.Contains(outLower, cmd) {
			hasNetworkCmd = true
			break
		}
	}

	hasSuspiciousHost := false
	suspiciousHosts := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"metadata.azure.com",
		"amazonaws.com/latest/meta-data",
		"ifconfig.me",
		"ipinfo.io",
		"pastebin.com",
		"webhook.site",
		"requestbin",
		"discord.com/api/webhooks",
		"telegram.org",
	}
	for _, host := range suspiciousHosts {
		if strings.Contains(cmdLower, host) || strings.Contains(outLower, host) {
			hasSuspiciousHost = true
			break
		}
	}

	if strings.Contains(cmdLower, "169.254.169.254") || strings.Contains(outLower, "169.254.169.254") ||
		strings.Contains(cmdLower, "metadata.google.internal") || strings.Contains(outLower, "metadata.google.internal") ||
		strings.Contains(cmdLower, "metadata.azure.com") || strings.Contains(outLower, "metadata.azure.com") ||
		strings.Contains(cmdLower, "amazonaws.com/latest/meta-data") || strings.Contains(outLower, "amazonaws.com/latest/meta-data") {
		addFinding("cloud_metadata_access", "Lifecycle script attempted to access cloud metadata endpoint")
	}

	if hasNetworkCmd || hasSuspiciousHost {
		addFinding("network_call_from_lifecycle", "Lifecycle script made a network call")
	}

	if anyCanaryRead && (hasNetworkCmd || hasSuspiciousHost) {
		addFinding("credential_canary_exfiltration_attempt", "Script attempted to send canary-like content to remote endpoint")
	}

	if (strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "wget") || strings.Contains(cmdLower, "fetch")) &&
		(strings.Contains(cmdLower, "| sh") || strings.Contains(cmdLower, "| bash") || strings.Contains(cmdLower, "| cmd") || strings.Contains(cmdLower, "| powershell") || strings.Contains(cmdLower, "| pwsh") ||
			strings.Contains(cmdLower, "|sh") || strings.Contains(cmdLower, "|bash")) {
		addFinding("shell_download_execute", "Lifecycle script attempted to download and execute shell commands")
	}

	if strings.Contains(cmdLower, "base64") || strings.Contains(cmdLower, "eval") || strings.Contains(cmdLower, "function(") {
		addFinding("encoded_payload_execution", "Lifecycle script executed encoded payload")
	}

	if strings.Contains(cmdLower, "child_process") || strings.Contains(cmdLower, "exec(") || strings.Contains(cmdLower, "spawn(") || strings.Contains(cmdLower, "fork(") {
		addFinding("child_process_spawn", "Lifecycle script spawned a child process")
	}

	if strings.Contains(cmdLower, "ls ") && (strings.Contains(cmdLower, "~") || strings.Contains(cmdLower, "$home") || strings.Contains(cmdLower, "%userprofile%")) {
		addFinding("home_directory_enumeration", "Lifecycle script enumerated home directory content")
	}

	if strings.Contains(cmdLower, "printenv") || (strings.Contains(cmdLower, "env") && !strings.Contains(cmdLower, "dotenv")) || strings.Contains(cmdLower, "process.env") {
		addFinding("environment_variable_enumeration", "Lifecycle script enumerated environment variables")
	}

	if strings.Contains(cmdLower, "git config") || strings.Contains(cmdLower, ".gitconfig") {
		addFinding("git_config_access", "Lifecycle script accessed git configuration")
	}

	if strings.Contains(cmdLower, ".npmrc") || strings.Contains(cmdLower, ".pypirc") || strings.Contains(cmdLower, ".yarnrc") {
		addFinding("package_manager_config_access", "Lifecycle script accessed package manager configuration")
	}

	workspacePath := filepath.Join(sandboxRoot, "workspace")
	_ = filepath.Walk(workspacePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".exe" || ext == ".bin" || ext == ".node" || ext == ".so" || ext == ".dylib" || ext == ".dll" {
			addFinding("unexpected_binary_write", "Lifecycle script wrote an unexpected binary")
			return filepath.SkipDir
		}
		if ext == "" && (info.Mode()&0111) != 0 {
			addFinding("unexpected_binary_write", "Lifecycle script wrote an unexpected binary")
			return filepath.SkipDir
		}
		return nil
	})

	return dedupeFindings(findings)
}

func dedupeFindings(in []types.SandboxFinding) []types.SandboxFinding {
	seen := map[string]bool{}
	var out []types.SandboxFinding
	for _, f := range in {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			out = append(out, f)
		}
	}
	return out
}
