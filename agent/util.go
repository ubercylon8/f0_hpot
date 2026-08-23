package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

func osExecutable() (string, error) {
	return os.Executable()
}

func stateDirPath() string {
	switch runtime.GOOS {
	case "windows":
		progData := os.Getenv("PROGRAMDATA")
		if progData == "" {
			progData = `C:\ProgramData`
		}
		return filepath.Join(progData, "f0-deception")
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "/root/.f0-deception"
		}
		return filepath.Join(home, ".f0-deception")
	}
}

// run executes a shell script line (used by installers).
func run(script string) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := execCommand(shell, "-c", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
