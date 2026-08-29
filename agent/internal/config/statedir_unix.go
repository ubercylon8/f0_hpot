//go:build !windows

package config

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
)

// stateDir resolves the agent's state directory.
//
// os.UserHomeDir() fails outright when HOME is unset, which is exactly the
// case under systemd (services get no HOME unless the unit sets one). That
// used to abort startup with "load state: $HOME is not defined" and
// crash-loop the service, so fall back to the invoking user's passwd home
// — /root for the root-owned service.
func stateDir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, StateDir), nil
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, StateDir), nil
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/root", StateDir), nil
	}
	return "", errors.New("cannot resolve home directory for agent state (set HOME)")
}

// No migration needed on unix: the state path has not moved.
func legacyStateDir() (string, error) { return "", nil }
