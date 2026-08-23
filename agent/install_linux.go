//go:build linux

package main

import (
	"fmt"
	"os"
)

const systemdUnit = `[Unit]
Description=f0_deception endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=10
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
	unit := fmt.Sprintf(systemdUnit, exe, stateDir)
	path := "/etc/systemd/system/f0-deception-agent.service"
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit (root required): %w", err)
	}
	return run("systemctl daemon-reload && systemctl enable --now f0-deception-agent")
}

func uninstallService() error {
	return run("systemctl disable --now f0-deception-agent && rm -f /etc/systemd/system/f0-deception-agent.service")
}
