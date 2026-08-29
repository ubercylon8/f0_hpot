package sensors

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// portSensor binds a TCP port so a leaked listener from a previous
// generation is directly observable: the second Start would fail with
// "address already in use".
type portSensor struct {
	name    string
	started *atomic.Int32
}

func (p portSensor) Name() string { return p.name }

func (p portSensor) Start(ctx context.Context, cfg map[string]interface{}, _ Reporter) error {
	port, _ := cfg["port"].(int)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()
	p.started.Add(1)
	<-ctx.Done()
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// StartAll must stop and *wait for* the previous generation. Without the
// wait, redeploying a sensor set left the old listener holding the port and
// the replacement died with "address already in use".
func TestStartAllReleasesPortsBeforeRestart(t *testing.T) {
	var started atomic.Int32
	name := "test_port_sensor"
	Register(portSensor{name: name, started: &started})
	t.Cleanup(StopAll)

	port := freePort(t)
	spec := []SensorSpec{{Kind: name, Enabled: true, Config: map[string]interface{}{"port": port}}}

	for i := 1; i <= 3; i++ {
		StartAll(spec, func(Trigger) {})
		deadline := time.Now().Add(2 * time.Second)
		for started.Load() < int32(i) && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if got := started.Load(); got != int32(i) {
			t.Fatalf("generation %d: sensor did not rebind the port (started=%d)", i, got)
		}
	}

	StopAll()
	// The port must be free once StopAll returns.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port still held after StopAll: %v", err)
	}
	ln.Close()
}

func TestStopAllIsSafeWhenNothingRunning(t *testing.T) {
	StopAll()
	StopAll()
}
