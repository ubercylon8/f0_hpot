//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
)

// Windows has no exec(2): syscall.Exec returns EWINDOWS, and the previous
// code discarded that error, so an updated agent kept running the old image
// forever. Under the SCM, exiting non-zero is the correct move — the
// service's recovery actions restart us on the new binary. In the
// foreground, spawn the replacement and let this process go.
func execSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if isWindowsService() {
		log.Println("self-update: exiting for service restart on the new binary")
		os.Exit(1)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Start(); err != nil {
		log.Printf("self-update: restart failed: %v", err)
		return
	}
	os.Exit(0)
}
