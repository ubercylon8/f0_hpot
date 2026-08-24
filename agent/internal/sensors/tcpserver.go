package sensors

import (
	"fmt"
	"log"
	"net"
)

// serveTCPSensor is the shared listener harness for banner/handshake
// honeypots: accepts connections, applies sane limits, and hands each one
// to a protocol handler.
func serveTCPSensor(
	name string,
	port int,
	tokenID string,
	handle func(conn net.Conn, tokenID string, report Reporter),
	report Reporter,
) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	log.Printf("[%s] listening on :%d", name, port)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("[%s] accept: %v", name, err)
				return
			}
			go handle(conn, tokenID, report)
		}
	}()
	return nil
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
