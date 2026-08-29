package update

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Apply used to rename straight out of os.CreateTemp("") — i.e. /tmp, which
// is its own mount on most Linux installs, so every update failed with
// EXDEV. StagingDir keeps the download on the target's filesystem.
func TestStagingDirIsBesideTheTarget(t *testing.T) {
	target := filepath.Join("/opt", "f0", "f0-deception-agent")
	if got, want := StagingDir(target), filepath.Join("/opt", "f0"); got != want {
		t.Fatalf("StagingDir(%q) = %q, want %q", target, got, want)
	}
	if StagingDir(target) == os.TempDir() {
		t.Fatal("staging in the system temp dir reintroduces the EXDEV failure")
	}
}

func TestApplyReplacesTheBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(StagingDir(target), "f0-update-test")
	if err := os.WriteFile(staged, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Apply(target, staged); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("target holds %q, want %q", got, "new")
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Fatalf("target mode %v, want 0755", fi.Mode().Perm())
	}

	// On Windows the displaced binary is parked alongside; CleanupOld clears
	// it on the next start. Elsewhere there is nothing to clean.
	CleanupOld(target)
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Fatal("CleanupOld left the displaced binary behind")
	}
}

func TestCleanupOldIsSafeWhenAbsent(t *testing.T) {
	CleanupOld(filepath.Join(t.TempDir(), "nonexistent"))
}
