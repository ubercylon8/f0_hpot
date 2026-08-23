// f0-deception-agent: endpoint agent running honeypot sensors and local
// canary detectors, managed by the f0_deception console.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/f0rt1ka/f0-deception-agent/internal/api"
	"github.com/f0rt1ka/f0-deception-agent/internal/config"
	"github.com/f0rt1ka/f0-deception-agent/internal/sensors"
)

var version = "0.1.0-dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	serverURL := flag.String("server", "", "console API base URL (enrollment)")
	enrollToken := flag.String("enroll", "", "one-time enrollment token (enrollment)")
	flag.Parse()

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
		return
	}

	if !state.Enrolled() {
		log.Fatal("not enrolled; run with --server <url> --enroll <token>")
	}

	client := api.New(state.ServerURL, state.AgentID, state.AgentKey)

	report := func(t sensors.Trigger) {
		detail := t.Detail
		detail["sensor"] = t.Sensor
		err := client.ReportIncident(api.Incident{
			TokenID:  t.TokenID,
			Severity: t.Severity,
			Event: map[string]interface{}{
				"kind":      "http", // v1 detail channel; dedicated agent kind lands later
				"tokenHint": t.TokenID,
				"timestamp": t.SeenAt.Format(time.RFC3339),
				"detail":    detail,
			},
		})
		if err != nil {
			log.Printf("report incident: %v", err)
		}
	}

	sensors.Register(sensors.HTTPLoginSensor{})
	sensors.Register(sensors.SSHSensor{})
	sensors.Register(sensors.PlantedCredentialSensor{})
	sensors.Register(sensors.FileWatchSensor{})

	poll := 60 * time.Second
	var currentSpecs []api.SensorSpec
	for {
		interval, specs, err := client.Heartbeat()
		switch {
		case err == nil:
			if interval > 0 {
				poll = time.Duration(interval) * time.Second
			}
			if !specsEqual(currentSpecs, specs) {
				currentSpecs = specs
				sensors.StartAll(toSensors(specs), report)
			}
		default:
			log.Printf("heartbeat failed, retrying in %s: %v", poll, err)
		}
		time.Sleep(poll)
	}
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

var _ = fmt.Sprintf // keep fmt until install/uninstall subcommands land
