// Package sensors implements honeypot services and local canary sensors.
// Each sensor reports trigger events through a shared callback.
package sensors

import (
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
	// Start runs the sensor; it must return promptly on ctx cancellation.
	Start(cfg map[string]interface{}, report Reporter) error
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

// StartAll launches every enabled spec; failures are logged, not fatal.
func StartAll(specs []SensorSpec, report Reporter) {
	for _, spec := range specs {
		if !spec.Enabled {
			continue
		}
		sensor, ok := Lookup(spec.Kind)
		if !ok {
			log.Printf("sensor %q not available in this build", spec.Kind)
			continue
		}
		go func(sensor Sensor, cfg map[string]interface{}) {
			if err := sensor.Start(cfg, report); err != nil {
				log.Printf("sensor %s stopped: %v", sensor.Name(), err)
			}
		}(sensor, spec.Config)
	}
}
