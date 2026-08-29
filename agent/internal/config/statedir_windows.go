//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// On Windows the agent state must be machine-wide, not per-user: enrollment
// runs as the interactive administrator while the service runs as
// LocalSystem, whose profile is a different directory entirely. A per-user
// path would leave the service permanently "not enrolled".
//
// %PROGRAMDATA%\f0-deception matches stateDirPath() in the installer, so the
// unit's own paths and the state it loads agree.
func stateDir() (string, error) {
	progData := os.Getenv("PROGRAMDATA")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	return filepath.Join(progData, "f0-deception"), nil
}

// legacyStateDir is the pre-service per-user location. Load() migrates from
// it once so agents enrolled before the service existed keep their identity.
func legacyStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, StateDir), nil
}
