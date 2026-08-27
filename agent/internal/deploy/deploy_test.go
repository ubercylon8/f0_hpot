package deploy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/f0rt1ka/f0-deception-agent/internal/api"
)

func strptr(s string) *string { return &s }

func TestExecuteFileDeployment(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plant")
	content := []byte("PK\x03\x04 docx bytes")
	d := api.Deployment{
		ID:        "dep1",
		Kind:      "file",
		TargetDir: target,
		Filename:  "quarterly_report.docx",
		Payload:   strptr(base64.StdEncoding.EncodeToString(content)),
	}
	results := Execute([]api.Deployment{d})
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("expected success, got %+v", results)
	}
	got, err := os.ReadFile(filepath.Join(target, "quarterly_report.docx"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: %q", got)
	}
}

func TestExecuteShortcutDeployment(t *testing.T) {
	dir := t.TempDir()
	d := api.Deployment{
		ID:        "dep2",
		Kind:      "shortcut",
		TargetDir: dir,
		Filename:  "abc123.url",
		URL:       strptr("http://gw.example.com/abc123/pixel.gif"),
	}
	results := Execute([]api.Deployment{d})
	if !results[0].OK {
		t.Fatalf("expected success, got %+v", results)
	}
	got, err := os.ReadFile(filepath.Join(dir, "abc123.url"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "URL=http://gw.example.com/abc123/pixel.gif") {
		t.Fatalf("shortcut content wrong: %q", got)
	}
}

func TestExecuteRejectsTraversalAndUnknownKind(t *testing.T) {
	dir := t.TempDir()
	results := Execute([]api.Deployment{
		{ID: "dep3", Kind: "file", TargetDir: dir, Filename: "../evil.txt", Payload: strptr("eA==")},
		{ID: "dep4", Kind: "teleport", TargetDir: dir, Filename: "x"},
	})
	if results[0].OK || !strings.Contains(results[0].Error, "unsafe filename") {
		t.Fatalf("traversal should fail: %+v", results[0])
	}
	if results[1].OK || !strings.Contains(results[1].Error, "unknown deployment kind") {
		t.Fatalf("unknown kind should fail: %+v", results[1])
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil.txt")); err == nil {
		t.Fatal("traversal file was written")
	}
}
