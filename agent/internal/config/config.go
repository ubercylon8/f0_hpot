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
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, StateDir)
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
