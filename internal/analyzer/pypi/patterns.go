package pypi

import "strings"

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
