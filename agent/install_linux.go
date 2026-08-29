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
# Hardening, bounded by what the agent actually has to do.
#
# ProtectSystem=strict made the whole filesystem read-only except the state
# dir, which silently disabled the agent's file-based features: planted
# credentials could not be written or re-armed, and console token
# deployments could not land on disk. Both failed with no error an operator
# would ever see. "full" keeps /usr, /boot and /etc read-only — the part
# that matters, since the agent has no business editing system binaries or
# config — while leaving /opt, /srv, /var and homes writable for bait.
#
# ProtectHome and PrivateTmp are deliberately absent: ~/.aws/credentials and
# ~/.ssh are prime bait locations, and a private /tmp would hide deployed
# tokens from the very intruder they are meant to attract.
NoNewPrivileges=yes
ProtectSystem=full
ReadWritePaths=%s

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
