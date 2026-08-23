//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const launchdLabel = "com.f0rt1ka.f0-deception-agent"

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	stateDir := stateDirPath()
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s/agent.log</string>
  <key>StandardErrorPath</key><string>%s/agent.log</string>
</dict></plist>`, launchdLabel, exe, stateDir, stateDir)
	path := filepath.Join(dir, launchdLabel+".plist")
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return err
	}
	return run("launchctl load -w " + path)
}

func uninstallService() error {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
	_ = run("launchctl unload -w " + path)
	return os.Remove(path)
}
