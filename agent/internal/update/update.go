// Package update verifies and applies signed agent updates.
//
// Trust model: the operator signs a release manifest (see sign_release.sh)
// with an Ed25519 private key; the matching public key is embedded in the
// agent at build time (UpdatePublicKey). A manifest is only actionable when
// its signature verifies AND every file hash matches.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// UpdatePublicKey is injected via -ldflags -X update.UpdatePublicKey=<b64>.
var UpdatePublicKey = ""

type Manifest struct {
	Version string `json:"version"`
	Files   map[string]struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"files"`
	Signature string `json:"signature"`
}

var (
	errNoKey       = errors.New("update: no public key embedded in this build")
	errBadManifest = errors.New("update: malformed manifest")
)

func parsePublicKey() (ed25519.PublicKey, error) {
	if UpdatePublicKey == "" {
		return nil, errNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(UpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("update: bad public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("update: public key has wrong size")
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyManifest checks the Ed25519 signature over the manifest with the
// signature field removed (canonical re-encode), then returns it.
func VerifyManifest(manifestJSON []byte) (*Manifest, error) {
	pub, err := parsePublicKey()
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, errBadManifest
	}
	sig := m.Signature
	m.Signature = ""
	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, errBadManifest
	}
	sigRaw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, errBadManifest
	}
	if !ed25519.Verify(pub, canonical, sigRaw) {
		return nil, errors.New("update: manifest signature verification FAILED")
	}
	m.Signature = sig
	return &m, nil
}

// VerifyFile checks a downloaded artifact against the verified manifest.
func VerifyFile(m *Manifest, name string, path string) error {
	entry, ok := m.Files[name]
	if !ok {
		return fmt.Errorf("update: %s not in manifest", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != entry.SHA256 {
		return fmt.Errorf("update: %s hash mismatch", name)
	}
	if int64(len(data)) != entry.Size {
		return fmt.Errorf("update: %s size mismatch", name)
	}
	return nil
}

// Apply atomically replaces targetPath with the verified new binary.
func Apply(targetPath, newPath string) error {
	// Windows refuses to overwrite or delete a running executable, but it
	// will rename one. Move the current binary aside, install over the now
	// free name, and roll back if the second rename fails. CleanupOld
	// removes the leftover on the next start.
	if runtime.GOOS == "windows" {
		aside := targetPath + ".old"
		_ = os.Remove(aside)
		if err := os.Rename(targetPath, aside); err != nil {
			return fmt.Errorf("update: move running binary aside: %w", err)
		}
		if err := os.Rename(newPath, targetPath); err != nil {
			_ = os.Rename(aside, targetPath)
			return fmt.Errorf("update: install new binary: %w", err)
		}
		return os.Chmod(targetPath, 0o755)
	}

	if err := os.Rename(newPath, targetPath); err != nil {
		return fmt.Errorf("update: install new binary: %w", err)
	}
	return os.Chmod(targetPath, 0o755)
}

// CleanupOld removes the binary displaced by a previous Windows update.
// Safe (and a no-op) everywhere else.
func CleanupOld(targetPath string) {
	if runtime.GOOS == "windows" {
		_ = os.Remove(targetPath + ".old")
	}
}

// StagingDir is where a downloaded artifact must land before Apply renames
// it into place. It has to be the target's own directory: os.Rename cannot
// cross filesystems, and /tmp is a separate mount on most Linux installs,
// which made every update fail with EXDEV.
func StagingDir(targetPath string) string {
	return filepath.Dir(targetPath)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// version is overridden by main via SetVersion.
var agentVersion = "0.0.0"

func version() string { return agentVersion }

func SetVersion(v string) { agentVersion = v }
