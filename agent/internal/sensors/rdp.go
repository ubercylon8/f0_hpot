package sensors

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

// RDPSensor: low-interaction RDP honeypot on :3389. Parses the X.224
// connection request (which leaks client version/requested protocols and,
// in some clients, the username via cookie routing tokens), replies with
// connection confirm, then records the attempt. Full TLS/NLA credential
// capture is future work.
type RDPSensor struct{}

func (RDPSensor) Name() string { return "rdp" }

func (RDPSensor) Start(cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 3389)
	tokenID := str(cfg, "token_id", "")
	return serveTCPSensor("rdp", port, tokenID, handleRDPConn, report)
}

func handleRDPConn(conn net.Conn, tokenID string, report Reporter) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// TPKT header: version(1)=3, reserved(1), length(2 BE)
	tpkt := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpkt); err != nil || tpkt[0] != 3 {
		return
	}
	length := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if length < 11 || length > 1024 {
		return
	}
	x224 := make([]byte, 0, length-4)
	tmp := make([]byte, length-4)
	for len(x224) < length-4 {
		n, err := conn.Read(tmp)
		if n > 0 {
			x224 = append(x224, tmp[:n]...)
		}
		if err != nil {
			// Short read (scanner closed early) — still report what we have.
			break
		}
	}
	if x224[0] != 0xe0 { // Connection Request PDU type
		return
	}

	detail := map[string]interface{}{
		"event":     "connection_request",
		"source_ip": remoteIP(conn),
	}
	// Requested protocols at fixed offset in CRPDU: negReq fields.
	if len(x224) >= 12 && x224[11] == 0x01 { // TYPE_RDP_NEG_REQ follows cookie
		proto := x224[15] // requestedProtocols (low byte) when present
		if len(x224) > 15 {
			switch proto & 0x03 {
			case 0x01:
				detail["requested_security"] = "tls"
			case 0x02:
				detail["requested_security"] = "credssp(nla)"
			case 0x03:
				detail["requested_security"] = "tls+credssp"
			}
		}
	}
	// Cookie/routing token often contains the *username*: "Cookie: mstshash=USER"
	for i := 0; i+8 <= len(x224); i++ {
		if string(x224[i:i+6]) == "mstsha" {
			end := i + 100
			if end > len(x224) {
				end = len(x224)
			}
			detail["cookie_hint"] = string(x224[i:end])
			break
		}
	}

	log.Printf("[rdp] conn request from %s (%v)", detail["source_ip"], detail["requested_security"])

	// X.224 Connection Confirm: minimal, no negotiation payload.
	ccf := []byte{3, 0, 0, 11, 0xd0, 0, 0, 0, 0, 0, 0}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(ccf)
	time.Sleep(200 * time.Millisecond)

	report(Trigger{
		Sensor:   "rdp",
		TokenID:  tokenID,
		Severity: "high",
		Detail:   detail,
		SeenAt:   time.Now().UTC(),
	})
}
