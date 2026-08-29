// f0-deception-agent: endpoint agent running honeypot sensors and local
// canary detectors, managed by the f0_deception console.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/f0rt1ka/f0-deception-agent/internal/api"
	"github.com/f0rt1ka/f0-deception-agent/internal/config"
	"github.com/f0rt1ka/f0-deception-agent/internal/deploy"
	"github.com/f0rt1ka/f0-deception-agent/internal/sensors"
	"github.com/f0rt1ka/f0-deception-agent/internal/update"
)

var version = "0.1.0-dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	serverURL := flag.String("server", "", "console API base URL (enrollment)")
	enrollToken := flag.String("enroll", "", "one-time enrollment token (enrollment)")
	install := flag.Bool("install", false, "install as a system service")
	uninstall := flag.Bool("uninstall", false, "remove the system service")
	flag.Parse()

	if *uninstall {
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
		log.Println("service removed")
		return
	}

	state, err := config.Load()
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	if *enrollToken != "" {
		if *serverURL == "" {
			log.Fatal("--enroll requires --server")
		}
		host, _ := os.Hostname()
		id, key, err := api.Enroll(*serverURL, *enrollToken, host, runtime.GOOS+"/"+runtime.GOARCH, version)
		if err != nil {
			log.Fatalf("enrollment failed: %v", err)
		}
		state.ServerURL = *serverURL
		state.AgentID = id
		state.AgentKey = key
		if err := config.Save(state); err != nil {
			log.Fatalf("persist state: %v", err)
		}
		log.Printf("enrolled as %s; state saved", id)
	}

	if *install {
		if !state.Enrolled() {
			log.Fatal("--install requires prior enrollment (--server/--enroll)")
		}
		if err := installService(); err != nil {
			log.Fatalf("install: %v", err)
		}
		log.Println("service installed and started")
		return
	}

	if !state.Enrolled() {
		log.Fatal("not enrolled; run with --server <url> --enroll <token>")
	}

	// Launched by the Windows SCM: run under the service control dispatcher
	// so stop and shutdown requests are answered. Always false elsewhere.
	if isWindowsService() {
		if err := runAsService(state); err != nil {
			log.Fatalf("service: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runAgent(ctx, state)
}

// runAgent is the heartbeat/sensor loop. It returns when ctx is cancelled, so
// the foreground process and the Windows service share one code path.
func runAgent(ctx context.Context, state config.State) {
	client := api.New(state.ServerURL, state.AgentID, state.AgentKey)

	report := func(t sensors.Trigger) {
		detail := t.Detail
		detail["sensor"] = t.Sensor
		sourceIP, _ := detail["source_ip"].(string)
		err := client.ReportIncident(api.Incident{
			TokenID:  t.TokenID,
			Severity: t.Severity,
			Event: map[string]interface{}{
				"kind":      "agent",
				"tokenHint": t.TokenID,
				"timestamp": t.SeenAt.Format(time.RFC3339),
				"sourceIp":  sourceIP,
				"detail":    detail,
			},
		})
		if err != nil {
			log.Printf("report incident: %v", err)
		}
	}

	sensors.Register(sensors.HTTPLoginSensor{})
	sensors.Register(sensors.SSHSensor{})
	sensors.Register(sensors.SMBSensor{})
	sensors.Register(sensors.RDPSensor{})
	sensors.Register(sensors.PlantedCredentialSensor{})
	sensors.Register(sensors.FileWatchSensor{})
	update.SetVersion(version)

	poll := 60 * time.Second
	var currentSpecs []api.SensorSpec
	var pendingResults []api.DeploymentResult
	for {
		if ctx.Err() != nil {
			log.Println("shutting down")
			return
		}
		interval, specs, deployments, err := client.Heartbeat(pendingResults)
		switch {
		case err == nil:
			// Results we just sent are acked by the server; clear them.
			pendingResults = nil
			if interval > 0 {
				poll = time.Duration(interval) * time.Second
			}
			if !specsEqual(currentSpecs, specs) {
				currentSpecs = specs
				sensors.StartAll(toSensors(specs), report)
			}
			// One-shot token deployments from the console: plant now,
			// report outcomes on a later heartbeat.
			if len(deployments) > 0 {
				pendingResults = deploy.Execute(deployments)
				ok := 0
				for _, r := range pendingResults {
					if r.OK {
						ok++
					}
				}
				log.Printf("executed %d deployment(s): %d ok, %d failed", len(deployments), ok, len(deployments)-ok)
			}
		default:
			log.Printf("heartbeat failed, retrying in %s: %v", poll, err)
		}
		// Signed self-update check (no-op without embedded public key).
		if updateURL := os.Getenv("F0_UPDATE_MANIFEST_URL"); updateURL != "" {
			if m, err := update.FetchAndApply(updateURL, "f0-deception-agent-"+runtime.GOOS+"-"+runtime.GOARCH, os.Args[0]); err != nil {
				log.Printf("self-update: %v", err)
			} else if m != nil {
				log.Printf("updated to %s; restarting", m.Version)
				execSelf()
			}
		}
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-time.After(poll):
		}
	}
}

func execSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	_ = syscall.Exec(exe, os.Args, os.Environ())
}

func toSensors(in []api.SensorSpec) []sensors.SensorSpec {
	out := make([]sensors.SensorSpec, 0, len(in))
	for _, s := range in {
		out = append(out, sensors.SensorSpec{Kind: s.Kind, Enabled: s.Enabled, Config: s.Config})
	}
	return out
}

func specsEqual(a, b []api.SensorSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].Enabled != b[i].Enabled {
			return false
		}
	}
	return true
}
