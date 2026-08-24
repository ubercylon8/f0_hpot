package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"testing"
)

// TestOpensslSignedManifest verifies a manifest signed by sign_release.sh
// (openssl ed25519) passes the agent's verifier. Requires the keypair used
// by sign_release.sh; skipped in CI (covered by TestVerifyManifest).
func TestOpensslSignedManifest(t *testing.T) {
	if _, err := os.Stat("../../bin/release-manifest.json"); err != nil {
		t.Skip("no signed manifest present")
	}
	pubB64 := os.Getenv("F0_RELEASE_PUB_B64")
	if pubB64 == "" {
		t.Skip("F0_RELEASE_PUB_B64 not set")
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad pub key: %v", err)
	}
	UpdatePublicKey = pubB64
	defer func() { UpdatePublicKey = "" }()

	raw, err := os.ReadFile("../../bin/release-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifyManifest(raw)
	if err != nil {
		t.Fatalf("openssl-signed manifest rejected: %v", err)
	}
	if m.Version == "" || len(m.Files) == 0 {
		t.Fatal("manifest empty")
	}
	_ = exec.Command
}
