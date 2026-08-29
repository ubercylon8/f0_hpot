//go:build windows

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows service install. State lives machine-wide under %PROGRAMDATA%
// (see internal/config/statedir_windows.go), so the service running as
// LocalSystem loads the identity the installing administrator enrolled.

const (
	serviceDisplayName = "f0_hpot deception agent"
	serviceDescription = "Runs honeypot sensors and local canary detectors, managed by the f0_hpot console."
)

func installService() error {
	exe, err := osExecutable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()

	// Replace an existing installation rather than failing on re-run: the
	// install one-liner is expected to be idempotent.
	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		if err := removeService(m); err != nil {
			return fmt.Errorf("replace existing service: %w", err)
		}
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Restart on crash, the same posture as Restart=always on systemd.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400); err != nil {
		// Not fatal: the service is installed and will still run.
		fmt.Printf("warning: could not set recovery actions: %v\n", err)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	return removeService(m)
}

// removeService stops the service if running, then deletes it and waits for
// the SCM to drop the registration so a reinstall immediately afterwards
// doesn't fail with ERROR_SERVICE_MARKED_FOR_DELETE.
func removeService(m *mgr.Mgr) error {
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			status, err := s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}
