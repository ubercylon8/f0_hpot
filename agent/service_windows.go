//go:build windows

package main

import (
	"context"
	"log"

	"golang.org/x/sys/windows/svc"

	"github.com/f0rt1ka/f0-deception-agent/internal/config"
)

// serviceName is shared by the installer, the dispatcher and the event log.
const serviceName = "f0-deception-agent"

// isWindowsService reports whether the process was started by the Service
// Control Manager rather than from a console.
func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return is
}

type agentService struct {
	state config.State
}

// Execute is the SCM callback. It starts the agent loop in a goroutine and
// translates Stop/Shutdown into context cancellation, so sensors get the same
// orderly shutdown they get from SIGTERM on unix.
func (s *agentService) Execute(
	_ []string,
	req <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runAgent(ctx, s.state)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case <-done:
			// The loop exited on its own (unrecoverable state).
			status <- svc.Status{State: svc.StopPending}
			return false, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			default:
				log.Printf("unexpected service control request: %d", c.Cmd)
			}
		}
	}
}

func runAsService(state config.State) error {
	return svc.Run(serviceName, &agentService{state: state})
}
