// Package deploy executes one-shot token deployments delivered via
// heartbeat: plant artifact files or URL shortcuts on this host.
package deploy

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/f0rt1ka/f0-deception-agent/internal/api"
)

// Execute plants every deployment and collects per-item results (reported
// to the console on a later heartbeat).
func Execute(deployments []api.Deployment) []api.DeploymentResult {
	results := make([]api.DeploymentResult, 0, len(deployments))
	for _, d := range deployments {
		results = append(results, executeOne(d))
	}
	return results
}

func executeOne(d api.Deployment) api.DeploymentResult {
	fail := func(err error) api.DeploymentResult {
		return api.DeploymentResult{ID: d.ID, OK: false, Error: err.Error()}
	}
	if d.ID == "" || d.Filename == "" || d.TargetDir == "" {
		return fail(fmt.Errorf("incomplete deployment descriptor"))
	}
	// Defense in depth: a filename must never escape the target dir, even
	// though the API sanitizes it too.
	if filepath.Base(d.Filename) != d.Filename {
		return fail(fmt.Errorf("unsafe filename %q", d.Filename))
	}
	if err := os.MkdirAll(d.TargetDir, 0o755); err != nil {
		return fail(fmt.Errorf("mkdir %s: %w", d.TargetDir, err))
	}
	dest := filepath.Join(d.TargetDir, d.Filename)

	switch d.Kind {
	case "file":
		if d.Payload == nil {
			return fail(fmt.Errorf("file deployment without payload"))
		}
		data, err := base64.StdEncoding.DecodeString(*d.Payload)
		if err != nil {
			return fail(fmt.Errorf("decode payload: %w", err))
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return fail(fmt.Errorf("write %s: %w", dest, err))
		}
	case "shortcut":
		if d.URL == nil {
			return fail(fmt.Errorf("shortcut deployment without url"))
		}
		content := "[InternetShortcut]\nURL=" + *d.URL + "\n"
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			return fail(fmt.Errorf("write %s: %w", dest, err))
		}
	default:
		return fail(fmt.Errorf("unknown deployment kind %q", d.Kind))
	}
	return api.DeploymentResult{ID: d.ID, OK: true}
}
