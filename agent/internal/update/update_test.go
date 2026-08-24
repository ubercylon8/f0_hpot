package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sign(t *testing.T, priv ed25519.PrivateKey, m Manifest) []byte {
	t.Helper()
	m.Signature = ""
	canonical, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	UpdatePublicKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { UpdatePublicKey = "" }()

	good := Manifest{
		Version: "1.2.3",
		Files: map[string]struct {
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		}{
			"f0-deception-agent-linux-amd64": {SHA256: "abc", Size: 5},
		},
	}
	signed := sign(t, priv, good)

	if _, err := VerifyManifest(signed); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	// Tamper with version -> signature must fail.
	var tampered map[string]interface{}
	_ = json.Unmarshal(signed, &tampered)
	tampered["version"] = "9.9.9"
	bad, _ := json.Marshal(tampered)
	if _, err := VerifyManifest(bad); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestVerifyManifestWithoutEmbeddedKey(t *testing.T) {
	UpdatePublicKey = ""
	err := error(nil)
	_, err = VerifyManifest([]byte(`{}`))
	if err == nil || err.Error() != "update: no public key embedded in this build" {
		t.Fatalf("expected no-key error, got %v", err)
	}
}

func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.bin")
	payload := []byte("new-binary-bytes")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256Hex(payload)
	m := &Manifest{
		Version: "1.0.0",
		Files: map[string]struct {
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		}{
			"agent.bin": {SHA256: sum, Size: int64(len(payload))},
		},
	}
	if err := VerifyFile(m, "agent.bin", path); err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(m, "agent.bin", path); err == nil {
		t.Fatal("tampered file accepted")
	}
}
