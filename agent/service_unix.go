//go:build !windows

package main

import "github.com/f0rt1ka/f0-deception-agent/internal/config"

// The Windows SCM has no equivalent here: systemd and launchd run the agent
// as an ordinary foreground process and signal it with SIGTERM, which
// signal.NotifyContext already handles.
func isWindowsService() bool { return false }

func runAsService(config.State) error { return nil }
