package sandbox

import (
	"os"
	"path/filepath"
)

var Canaries = map[string]string{
	"home/.aws/credentials": `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
	"home/.aws/config": `[default]
region = us-east-1
output = json
`,
	"home/.ssh/id_rsa": `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtcn
NhAAAAAwEAAQAAAYEA01B...
-----END OPENSSH PRIVATE KEY-----
`,
	"home/.ssh/config": `Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_rsa
`,
	"home/.npmrc": `//registry.npmjs.org/:_authToken=npm_s7Y2Rz9F3Kj1Lm5Np9Qr2St8Uv4Wx1Yz
`,
	"home/.pypirc": `[pypi]
username = __token__
password = pypi-AgFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
`,
	"home/.kube/config": `apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: local-k8s-cluster
contexts:
- context:
    cluster: local-k8s-cluster
    user: admin-user
  name: admin-context
current-context: admin-context
kind: Config
preferences: {}
users:
- name: admin-user
  user:
    token: k8s-token-f8b2c4e6a8d0
`,
	"home/.docker/config.json": `{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "YWRtaW46c3VwZXJzZWNyZXRwYXNzd29yZA=="
    }
  }
}
`,
	"home/.azure/accessTokens.json": `[
  {
    "tokenType": "Bearer",
    "expiresOn": "2026-12-31T23:59:59.000Z",
    "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1NiJ9.fake_token_data"
  }
]
`,
	"home/.config/gcloud/application_default_credentials.json": `{
  "type": "authorized_user",
  "client_id": "1234567890-abcdef.apps.googleusercontent.com",
  "client_secret": "GOCSPX-fake-secret-key-12345",
  "refresh_token": "1//0fake-refresh-token-value"
}
`,
	"home/.vault-token": `hvs.CAESIEx1234567890abcdefghijklmnopqrstuvwxyz
`,
	"workspace/.env": `DATABASE_URL=postgres://dbuser:dbpass123@localhost:5432/production_db
API_SECRET=sec_9f3d8a1c6b5e4072f8a1
`,
	"workspace/.env.local": `DATABASE_URL=postgres://dbuser:dbpass123@localhost:5432/production_db
API_SECRET=sec_7a2b9c3d5e8f4160a2c5
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
