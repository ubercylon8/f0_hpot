// Package config manages agent state persisted outside the repo.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const StateDir = ".f0-deception"

// State is the agent's persisted identity. Hot-reloadable fields live in
// SensorConfig delivered by the server; enrollment-bound fields never change.
type State struct {
	ServerURL string `yaml:"server_url"`
	AgentID   string `yaml:"agent_id"`
	AgentKey  string `yaml:"agent_key"`
}

func statePath() (string, error) {
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent.yaml"), nil
}

// Load reads persisted state; returns zero State if absent.
func Load() (State, error) {
	p, err := statePath()
	if err != nil {
		return State{}, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		// One-time migration from the pre-service per-user location so an
		// agent enrolled before the state moved keeps its identity.
		if migrated, ok := loadLegacy(); ok {
			if err := Save(migrated); err != nil {
				return migrated, nil
			}
			return migrated, nil
		}
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := yaml.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("corrupt agent state: %w", err)
	}
	return s, nil
}

// Save atomically persists state with restrictive permissions.
func Save(s State) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Enrolled reports whether the agent has an identity.
func (s State) Enrolled() bool {
	return s.AgentID != "" && s.AgentKey != ""
}

// loadLegacy reads state from the previous location, if any.
func loadLegacy() (State, bool) {
	dir, err := legacyStateDir()
	if err != nil || dir == "" {
		return State{}, false
	}
	data, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if err != nil {
		return State{}, false
	}
	var s State
	if err := yaml.Unmarshal(data, &s); err != nil {
		return State{}, false
	}
	return s, s.Enrolled()
}
