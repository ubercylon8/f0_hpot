// Package sensors implements honeypot services and local canary sensors.
// Each sensor reports trigger events through a shared callback.
package sensors

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Trigger is what a sensor emits when someone touches the honeypot.
type Trigger struct {
	Sensor   string
	TokenID  string
	Severity string // low | medium | high
	Detail   map[string]interface{}
	SeenAt   time.Time
}

// Reporter delivers triggers to the console pipeline.
type Reporter func(Trigger)

// Sensor is one runnable deception component.
type Sensor interface {
	Name() string
	// Start runs the sensor and blocks until it fails or ctx is cancelled.
	// It must release its listeners/tickers before returning, so the next
	// generation can bind the same ports.
	Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error
}

var (
	mu       sync.Mutex
	registry = map[string]Sensor{}
)

func Register(s Sensor) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[s.Name()]; dup {
		panic(fmt.Sprintf("sensor %q registered twice", s.Name()))
	}
	registry[s.Name()] = s
}

func Lookup(name string) (Sensor, bool) {
	mu.Lock()
	defer mu.Unlock()
	s, ok := registry[name]
	return s, ok
}

// SensorSpec mirrors the server-delivered sensor configuration.
type SensorSpec struct {
	Kind    string                 `json:"kind"`
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// Generation bookkeeping: StartAll replaces the running set wholesale, so the
// previous generation must be stopped and *waited for* before the new one
// binds. Without the wait, the old listeners keep their ports and every
// re-deploy leaves the new sensors dying with "address already in use".
var (
	runMu     sync.Mutex
	runCancel context.CancelFunc
	runWG     *sync.WaitGroup
)

// shutdownGrace bounds how long we wait for a generation to release its
// ports. A wedged sensor must not stall the heartbeat loop forever.
const shutdownGrace = 10 * time.Second

// StartAll stops the currently running sensors, waits for them to release
// their resources, then launches every enabled spec. Failures are logged,
// not fatal.
func StartAll(specs []SensorSpec, report Reporter) {
	runMu.Lock()
	defer runMu.Unlock()

	stopCurrentLocked()

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	runCancel, runWG = cancel, wg

	for _, spec := range specs {
		if !spec.Enabled {
			continue
		}
		sensor, ok := Lookup(spec.Kind)
		if !ok {
			log.Printf("sensor %q not available in this build", spec.Kind)
			continue
		}
		wg.Add(1)
		go func(sensor Sensor, cfg map[string]interface{}) {
			defer wg.Done()
			if err := sensor.Start(ctx, cfg, report); err != nil {
				log.Printf("sensor %s stopped: %v", sensor.Name(), err)
			}
		}(sensor, spec.Config)
	}
}

// StopAll shuts the running sensors down and waits for them.
func StopAll() {
	runMu.Lock()
	defer runMu.Unlock()
	stopCurrentLocked()
}

func stopCurrentLocked() {
	if runCancel == nil {
		return
	}
	runCancel()
	done := make(chan struct{})
	go func() {
		runWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownGrace):
		log.Printf("sensors: shutdown timed out after %s; ports may still be held", shutdownGrace)
	}
	runCancel, runWG = nil, nil
}
