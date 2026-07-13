package intercept

import "testing"

func TestParsePnpmYarnUV(t *testing.T) {
	t.Run("pnpm add axios", func(t *testing.T) {
		cmd, err := ParseCommand("pnpm", []string{"add", "axios"})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.PackageManager != "pnpm" || cmd.Ecosystem != "npm" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "axios" {
			t.Fatalf("unexpected cmd: %+v", cmd)
		}
	})
	t.Run("yarn add lodash", func(t *testing.T) {
		cmd, err := ParseCommand("yarn", []string{"add", "lodash"})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.PackageManager != "yarn" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "lodash" {
			t.Fatalf("unexpected cmd: %+v", cmd)
		}
	})
	t.Run("bare yarn project install", func(t *testing.T) {
		cmd, err := ParseCommand("yarn", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !cmd.IsProjectInstall || cmd.PackageManager != "yarn" {
			t.Fatalf("unexpected cmd: %+v", cmd)
		}
	})
	t.Run("uv pip install requests", func(t *testing.T) {
		cmd, err := ParseCommand("uv", []string{"pip", "install", "requests"})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.PackageManager != "uv" || cmd.Ecosystem != "pypi" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "requests" {
			t.Fatalf("unexpected cmd: %+v", cmd)
		}
	})
	t.Run("uv add flask", func(t *testing.T) {
		cmd, err := ParseCommand("uv", []string{"add", "flask"})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.PackageManager != "uv" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "flask" {
			t.Fatalf("unexpected cmd: %+v", cmd)
		}
	})
	t.Run("pnpm run build passthrough", func(t *testing.T) {
		_, err := ParseCommand("pnpm", []string{"run", "build"})
		if err == nil {
			t.Fatal("expected unsupported command error")
		}
	})
}
