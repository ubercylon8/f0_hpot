// f0-deception-agent: endpoint agent running honeypot sensors and local
// canary detectors, managed by the f0_deception console.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	client.Version = version

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
	defer sensors.StopAll()
	update.SetVersion(version)

	// os.Args[0] is whatever the caller typed; resolve the real path so the
	// updater stages next to (and replaces) the actual binary.
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	update.CleanupOld(self)

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
				hostname, _ := os.Hostname()
				sensors.StartAll(toSensors(specs, state.AgentID, hostname), report)
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
		case errors.Is(err, api.ErrRevoked):
			// Retired from the console. Shut the honeypots down: leaving
			// them listening would mean a host that looks defended while
			// every detection is silently rejected.
			//
			// Deliberately not self-uninstalling. A console compromise
			// would otherwise be able to wipe the fleet and destroy
			// evidence, and an API restored from an older backup would
			// tell healthy agents they are unknown. Going dormant is
			// recoverable; deleting yourself is not.
			sensors.StopAll()
			log.Printf("this agent was retired from the console: %v", err)
			log.Printf("sensors stopped. To remove the service from this host, run: %s --uninstall", self)
			log.Printf("to put it back to work, re-enroll: %s --server <url> --enroll <token>", self)
			// Stay alive and idle rather than exiting: the service manager
			// would only restart us into the same state, and a crash loop
			// buries the message above.
			<-ctx.Done()
			return
		default:
			log.Printf("heartbeat failed, retrying in %s: %v", poll, err)
		}
		// Signed self-update check (no-op without embedded public key).
		if updateURL := os.Getenv("F0_UPDATE_MANIFEST_URL"); updateURL != "" {
			if m, err := update.FetchAndApply(updateURL, releaseArtifactName(), self); err != nil {
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

// releaseArtifactName is the manifest key for this platform's binary. It
// must match what the release build produces — including the .exe suffix on
// Windows, whose absence meant the Windows manifest entry was never
// requested and self-update silently did nothing.
func releaseArtifactName() string {
	name := "f0-deception-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// toSensors converts server-delivered specs into runnable ones, injecting
// the agent's own identity. These two keys are agent-supplied: they
// overwrite any operator value of the same name, because a sensor must not
// be able to claim another agent's id.
func toSensors(in []api.SensorSpec, agentID, hostname string) []sensors.SensorSpec {
	out := make([]sensors.SensorSpec, 0, len(in))
	for _, s := range in {
		cfg := make(map[string]interface{}, len(s.Config)+2)
		for k, v := range s.Config {
			cfg[k] = v
		}
		cfg["agent_id"] = agentID
		cfg["agent_hostname"] = hostname
		out = append(out, sensors.SensorSpec{Kind: s.Kind, Enabled: s.Enabled, Config: cfg})
	}
	return out
}

// specsEqual decides whether the delivered sensor set differs from what is
// running. Config must be part of the comparison: a port/path/token_id edit
// in the console changes neither kind nor enabled, and comparing only those
// left the agent running the old config indefinitely while the console
// showed the new one as deployed.
func specsEqual(a, b []api.SensorSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].Enabled != b[i].Enabled {
			return false
		}
		// JSON-encode for a stable deep compare: config comes off the wire as
		// map[string]interface{}, and Go's map iteration order is randomised,
		// so encoding/json's sorted keys give a canonical form.
		ja, errA := json.Marshal(a[i].Config)
		jb, errB := json.Marshal(b[i].Config)
		if errA != nil || errB != nil || !bytes.Equal(ja, jb) {
			return false
		}
	}
	return true
}
