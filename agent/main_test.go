package main

import (
	"runtime"
	"strings"
	"testing"
)

// The Windows manifest key carries a .exe suffix. Omitting it meant the
// Windows entry was never requested and self-update was a silent no-op.
func TestReleaseArtifactNameMatchesTheManifestKey(t *testing.T) {
	name := releaseArtifactName()
	if !strings.HasPrefix(name, "f0-deception-agent-"+runtime.GOOS+"-"+runtime.GOARCH) {
		t.Fatalf("unexpected artifact name: %s", name)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(name, ".exe") {
		t.Fatalf("windows artifact name lacks .exe: %s", name)
	}
	if runtime.GOOS != "windows" && strings.HasSuffix(name, ".exe") {
		t.Fatalf("non-windows artifact name has .exe: %s", name)
	}
}
