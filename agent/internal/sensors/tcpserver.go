package sensors

import (
	"context"
	"fmt"
	"log"
	"net"
)

// serveTCPSensor is the shared listener harness for banner/handshake
// honeypots: accepts connections, applies sane limits, and hands each one
// to a protocol handler.
// It blocks until ctx is cancelled or the listener fails, so the caller can
// wait for the port to be released before starting a new generation.
func serveTCPSensor(
	ctx context.Context,
	name string,
	port int,
	tokenID string,
	handle func(conn net.Conn, tokenID string, report Reporter),
	report Reporter,
) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("[%s] listening on :%d", name, port)

	// Unblock Accept on cancellation.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("[%s] stopped", name)
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go handle(conn, tokenID, report)
	}
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
