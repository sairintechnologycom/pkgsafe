package pypi

import (
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func AnalyzeSetupPy(path, lower string) ([]types.Reason, []string) {
	var findings []types.Reason
	var suspicious []string
	for _, pat := range []string{"os.system", "subprocess.run", "subprocess.popen", "popen(", "call(", "check_call", "check_output"} {
		if strings.Contains(lower, pat) {
			findings = risk.AddReason(findings, "pypi_setup_py_shell_execution", "setup.py executes shell commands", path+": "+pat)
			suspicious = append(suspicious, pat)
			break
		}
	}
	for _, pat := range []string{"requests.get", "requests.post", "urllib.request", "socket.socket", "http.client", "ftplib", "paramiko"} {
		if strings.Contains(lower, pat) {
			findings = risk.AddReason(findings, "pypi_setup_py_network_call", "setup.py performs network calls", path+": "+pat)
			suspicious = append(suspicious, pat)
			break
		}
	}
	for _, pat := range []string{"~/.aws/credentials", ".env", "~/.ssh/id_rsa", "os.environ", "pathlib.path.home()", "expanduser(\"~", "expanduser('~"} {
		if strings.Contains(lower, pat) {
			findings = risk.AddReason(findings, "pypi_setup_py_credential_access", "setup.py reads credentials or sensitive paths", path+": "+pat)
			suspicious = append(suspicious, pat)
			break
		}
	}
	return findings, suspicious
}
