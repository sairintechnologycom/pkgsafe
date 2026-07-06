package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestCopyDirCopiesTree(t *testing.T) {
	src := t.TempDir()
	// Build a small nested tree.
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "copy")
	if err := CopyDir(src, dst); err != nil {
		t.Fatalf("CopyDir: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dst, "sub", "nested.txt"))
	if err != nil || string(got) != "nested" {
		t.Fatalf("nested file not copied: %q err=%v", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "top.txt")); err != nil || string(b) != "top" {
		t.Fatalf("top file not copied: %q err=%v", b, err)
	}
}

func TestCopyDirMissingSource(t *testing.T) {
	err := CopyDir(filepath.Join(t.TempDir(), "does-not-exist"), t.TempDir())
	if err == nil {
		t.Fatal("expected error copying a nonexistent source")
	}
}

func TestSelectRunnerHeuristic(t *testing.T) {
	sel := SelectRunner(context.Background(), types.BehaviorHeuristic)
	if _, ok := sel.Runner.(*ProcessRunner); !ok {
		t.Fatalf("heuristic mode should yield a *ProcessRunner, got %T", sel.Runner)
	}
	if sel.Meta.Name != "fake-home-process" {
		t.Errorf("Meta.Name = %q, want fake-home-process", sel.Meta.Name)
	}
	if sel.Meta.Isolated {
		t.Error("heuristic runner must not report Isolated")
	}
	if sel.Meta.Warning == "" {
		t.Error("heuristic runner must carry the not-a-sandbox warning")
	}
	if want := IsAvailable(context.Background()); sel.Meta.Available != want {
		t.Errorf("Meta.Available = %v, want %v", sel.Meta.Available, want)
	}
}

func TestSelectRunnerDisabledIsNoRunner(t *testing.T) {
	sel := SelectRunner(context.Background(), types.BehaviorDisabled)
	if sel.Runner != nil {
		t.Errorf("disabled mode should carry no runner, got %T", sel.Runner)
	}
	if sel.Meta.Name != "none" {
		t.Errorf("Meta.Name = %q, want none", sel.Meta.Name)
	}
}

func TestPrepareWorkspaceCopiesPackage(t *testing.T) {
	pkg := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	root, workspace, cleanup, err := prepareWorkspace(SandboxRequest{PackagePath: pkg})
	if err != nil {
		t.Fatalf("prepareWorkspace: %v", err)
	}
	defer cleanup()

	// The package file is copied into the workspace...
	if _, err := os.Stat(filepath.Join(workspace, "package.json")); err != nil {
		t.Errorf("package.json not copied into workspace: %v", err)
	}
	// ...and the fake HOME exists under the sandbox root.
	if _, err := os.Stat(filepath.Join(root, "home")); err != nil {
		t.Errorf("fake home not created under sandbox root: %v", err)
	}

	cleanup()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("cleanup should remove the sandbox root, stat err=%v", err)
	}
}
