package sandbox

import (
	"os"
	"path/filepath"
)

var Canaries = map[string]string{
	"home/.aws/credentials": `[default]
aws_access_key_id = AKIAFAKEPKGSAFE000000
aws_secret_access_key = PKGSAFE_FAKE_SECRET
# PKGSAFE_CANARY_AWS_CREDENTIALS
`,
	"home/.aws/config": `[default]
region = us-east-1
output = json
# PKGSAFE_CANARY_AWS_CONFIG
`,
	"home/.ssh/id_rsa": `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtcn
NhAAAAAwEAAQAAAYEA01B...
# PKGSAFE_CANARY_SSH_KEY
-----END OPENSSH PRIVATE KEY-----
`,
	"home/.ssh/config": `Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_rsa
# PKGSAFE_CANARY_SSH_CONFIG
`,
	"home/.npmrc": `//registry.npmjs.org/:_authToken=npm_pkgsafe_fake_token
# PKGSAFE_CANARY_NPMRC
`,
	"home/.pypirc": `[pypi]
username = __token__
password = pypi-pkgsafe-fake-token
# PKGSAFE_CANARY_PYPIRC
`,
	"home/.kube/config": `apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: pkgsafe-fake-cluster
contexts:
- context:
    cluster: pkgsafe-fake-cluster
    user: pkgsafe-fake-user
  name: pkgsafe-fake-context
current-context: pkgsafe-fake-context
kind: Config
preferences: {}
users:
- name: pkgsafe-fake-user
  user:
    token: pkgsafe-fake-token
# PKGSAFE_CANARY_KUBECONFIG
`,
	"home/.docker/config.json": `{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "cGtnc2FmZTpmYWtlX3Rva2Vu"
    }
  }
}
# PKGSAFE_CANARY_DOCKER_CONFIG
`,
	"home/.azure/accessTokens.json": `[
  {
    "tokenType": "Bearer",
    "expiresOn": "2026-12-31T23:59:59.000Z",
    "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6InBrZ3NhZmUifQ.fake_token"
  }
]
# PKGSAFE_CANARY_AZURE_TOKENS
`,
	"home/.config/gcloud/application_default_credentials.json": `{
  "type": "authorized_user",
  "client_id": "pkgsafe-fake-client-id",
  "client_secret": "pkgsafe-fake-client-secret",
  "refresh_token": "pkgsafe-fake-refresh-token"
}
# PKGSAFE_CANARY_GCLOUD_CREDENTIALS
`,
	"home/.vault-token": `s.pkgsafe_fake_vault_token
# PKGSAFE_CANARY_VAULT_TOKEN
`,
	"workspace/.env": `DATABASE_URL=postgres://fake:fake@localhost:5432/fake
API_SECRET=pkgsafe_fake_api_secret
# PKGSAFE_CANARY_DOTENV
`,
	"workspace/.env.local": `DATABASE_URL=postgres://fake:fake@localhost:5432/fake
API_SECRET=pkgsafe_fake_api_secret_local
# PKGSAFE_CANARY_DOTENV_LOCAL
`,
}

func CreateFakeHome(sandboxRoot string) error {
	dirs := []string{
		"home",
		"home/.aws",
		"home/.ssh",
		"home/.config",
		"home/.config/gcloud",
		"home/.azure",
		"home/.kube",
		"home/.docker",
		"workspace",
		"tmp",
	}

	for _, d := range dirs {
		path := filepath.Join(sandboxRoot, d)
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}

	for relPath, content := range Canaries {
		path := filepath.Join(sandboxRoot, relPath)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return err
		}
	}

	return nil
}

func CopyDir(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
