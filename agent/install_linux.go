//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const systemdUnit = `[Unit]
Description=f0_deception endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=10
# systemd starts services with no HOME. The agent resolves its state dir
# from the user's home, so without this the unit dies at startup with
# "load state: $HOME is not defined" and restarts forever.
Environment=HOME=%s
# Hardening: agent needs network + its state dir only.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s
PrivateTmp=yes
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
`

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	stateDir := stateDirPath()
	// The service runs as root, so its state lives under root's home. Pin it
	// explicitly rather than relying on an environment systemd doesn't set.
	home := filepath.Dir(stateDir)
	unit := fmt.Sprintf(systemdUnit, exe, home, stateDir)
	path := "/etc/systemd/system/f0-deception-agent.service"
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit (root required): %w", err)
	}
	return run("systemctl daemon-reload && systemctl enable --now f0-deception-agent")
}

func uninstallService() error {
	return run("systemctl disable --now f0-deception-agent && rm -f /etc/systemd/system/f0-deception-agent.service")
}
