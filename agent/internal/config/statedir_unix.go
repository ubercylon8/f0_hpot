//go:build !windows

package config

import (
	"os"
	"path/filepath"
)

func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, StateDir), nil
}

// No migration needed on unix: the state path has not moved.
func legacyStateDir() (string, error) { return "", nil }
