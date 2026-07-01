package pypi

import (
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func RiskyPatterns() []string {
	return []string{
		"os.system", "subprocess.run", "subprocess.Popen", "eval", "exec", "compile",
		"base64.b64decode", "marshal.loads", "pickle.loads", "requests.get", "requests.post",
		"urllib.request", "socket.socket", "http.client", "ftplib", "paramiko", "boto3",
		"botocore", "open(\"~/.aws/credentials\")", "open(\".env\")", "open(\"~/.ssh/id_rsa\")",
		"pathlib.Path.home()", "os.environ",
	}
}

func looksEncodedPayload(lower string) bool {
	return strings.Contains(lower, "base64.b64decode") || strings.Contains(lower, "marshal.loads") || strings.Contains(lower, "exec(")
}

func suspiciousBinaryName(base string) bool {
	lower := strings.ToLower(base)
	if !(strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".bin") || strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dll")) {
		return false
	}
	for _, token := range []string{"update", "helper", "install", "tmp", "payload"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func nativeExtensionName(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, suffix := range []string{".so", ".pyd", ".dll", ".dylib"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	for _, suffix := range []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func AnalyzePythonStaticPatterns(path, lower string) ([]types.Reason, []string) {
	var findings []types.Reason
	var suspicious []string
	add := func(id, description, evidence string) {
		findings = risk.AddReason(findings, id, description, path+": "+evidence)
		suspicious = append(suspicious, evidence)
	}
	if strings.Contains(lower, "eval(") || strings.Contains(lower, "exec(") || strings.Contains(lower, "compile(") {
		add("pypi_eval_exec_usage", "Python source uses dynamic evaluation or execution", "eval/exec/compile")
	}
	if (strings.Contains(lower, "base64.b64decode") || strings.Contains(lower, "b64decode(")) && strings.Contains(lower, "exec(") {
		add("pypi_base64_exec_payload", "Python source decodes base64 content and executes it", "base64 decode plus exec")
	}
	for _, pat := range []string{"requests.get", "requests.post", "urllib.request", "socket.socket", "http.client", "ftplib", "paramiko"} {
		if strings.Contains(lower, pat) {
			add("pypi_network_call", "Python source performs network calls", pat)
			break
		}
	}
	for _, pat := range []string{"~/.aws/credentials", "~/.ssh/id_rsa", "~/.npmrc", "~/.pypirc", ".env", "pathlib.path.home()", "expanduser(\"~", "expanduser('~"} {
		if strings.Contains(lower, pat) {
			add("pypi_credential_path_access", "Python source references credential paths or local secret files", pat)
			break
		}
	}
	for _, pat := range []string{"os.environ", "getenv(", "environ.get("} {
		if strings.Contains(lower, pat) {
			add("pypi_env_secret_access", "Python source reads environment variables that may contain secrets", pat)
			break
		}
	}
	for _, pat := range []string{"169.254.169.254", "metadata.google.internal", "metadata/instance", "latest/meta-data"} {
		if strings.Contains(lower, pat) {
			add("pypi_cloud_metadata_access", "Python source references cloud metadata endpoints", pat)
			break
		}
	}
	return findings, suspicious
}
