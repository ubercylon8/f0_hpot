package sensors

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A planted credential exists to catch someone *reading* it. The signature
// previously covered only mtime, so `cat bait.txt` produced no incident.
func TestStatSignatureCoversAccessTime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("atimeOf is a stub on windows; signature degrades to mtime-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(path, []byte("vpn: admin / Summer2026!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Backdate atime/mtime the way the sensor does when planting, so the
	// first read is guaranteed to move atime even under relatime.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	before, err := statSignature(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	}

	after, err := statSignature(path)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatalf("read did not change the signature (%q); reads would go undetected", before)
	}
	// A read must not look like tampering: mtime is unchanged.
	if mtimePart(after) != mtimePart(before) {
		t.Fatalf("read changed the mtime half: %q -> %q", mtimePart(before), mtimePart(after))
	}
}

func TestStatSignatureDistinguishesWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bait.env")
	if err := os.WriteFile(path, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := statSignature(path)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	after, err := statSignature(path)
	if err != nil {
		t.Fatal(err)
	}
	if mtimePart(after) == mtimePart(before) {
		t.Fatal("write did not move the mtime half of the signature")
	}
}

func TestMtimePartHandlesMissingAtime(t *testing.T) {
	// Windows (and noatime mounts) yield an empty atime half.
	if got := mtimePart("2026-08-29T10:00:00Z|"); got != "2026-08-29T10:00:00Z" {
		t.Fatalf("got %q", got)
	}
	if got := mtimePart("2026-08-29T10:00:00Z"); got != "2026-08-29T10:00:00Z" {
		t.Fatalf("got %q", got)
	}
}
