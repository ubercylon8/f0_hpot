package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const httpClientTimeout = 30 * time.Second

// FetchAndApply downloads a signed manifest, verifies it, downloads the
// artifact named fileName, verifies its hash, and atomically swaps it in
// place of currentBinary. Caller decides whether to restart.
//
// No-op (nil, nil) when no public key is embedded.
func FetchAndApply(manifestURL, fileName, currentBinary string) (*Manifest, error) {
	if _, err := parsePublicKey(); err != nil {
		return nil, nil
	}
	client := &http.Client{Timeout: httpClientTimeout}

	mres, err := client.Get(manifestURL)
	if err != nil {
		return nil, fmt.Errorf("update: fetch manifest: %w", err)
	}
	defer mres.Body.Close()
	if mres.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: manifest HTTP %d", mres.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(mres.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	m, err := VerifyManifest(body)
	if err != nil {
		return nil, err
	}
	if m.Version == version() {
		return nil, nil // already current
	}

	bres, err := client.Get(artifactURL(manifestURL, fileName))
	if err != nil {
		return nil, fmt.Errorf("update: fetch artifact: %w", err)
	}
	defer bres.Body.Close()
	if bres.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: artifact HTTP %d", bres.StatusCode)
	}
	// Stage in the target's own directory: os.Rename cannot cross
	// filesystems, and /tmp is its own mount on most Linux installs.
	tmp, err := os.CreateTemp(StagingDir(currentBinary), "f0-update-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(bres.Body, 512<<20)); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	entry, ok := m.Files[fileName]
	if !ok || sum != entry.SHA256 {
		return nil, fmt.Errorf("update: artifact hash mismatch")
	}
	if err := Apply(currentBinary, tmp.Name()); err != nil {
		return nil, err
	}
	return m, nil
}

// artifactURL derives the artifact download URL from the manifest URL.
func artifactURL(manifestURL, name string) string {
	base := trimManifest(manifestURL)
	return base + name
}

func trimManifest(u string) string {
	for _, suffix := range []string{"release-manifest.json"} {
		if len(u) > len(suffix) && u[len(u)-len(suffix):] == suffix {
			return u[:len(u)-len(suffix)]
		}
	}
	if len(u) > 0 && u[len(u)-1] != '/' {
		return u + "/"
	}
	return u
}
