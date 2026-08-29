package sensors

import (
	"context"
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

func (RDPSensor) Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 3389)
	tokenID := str(cfg, "token_id", "")
	return serveTCPSensor(ctx, "rdp", port, tokenID, handleRDPConn, report)
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
	// Requested-protocols NEG_REQ: scan for the [0x01,0x00,0x08,proto,4×rsvd]
	// sequence anywhere in the payload (position varies when a cookie or
	// routing token precedes it).
	for i := 0; i+8 <= len(x224); i++ {
		if x224[i] == 0x01 && x224[i+1] == 0x00 && x224[i+2] == 0x08 {
			switch x224[i+3] & 0x03 {
			case 0x01:
				detail["requested_security"] = "tls"
			case 0x02:
				detail["requested_security"] = "credssp(nla)"
			case 0x03:
				detail["requested_security"] = "tls+credssp"
			}
			break
		}
	}
	// Cookie/routing token often contains the *username*: "Cookie: mstshash=USER"
	if idx := indexOf(x224, []byte("mstsha")); idx >= 0 {
		end := idx + 64
		if end > len(x224) {
			end = len(x224)
		}
		detail["cookie_hint"] = string(x224[idx:end])
	}

	log.Printf("[rdp] conn request from %s (%v)", detail["source_ip"], detail["requested_security"])

	// X.224 Connection Confirm. When the client requested CredSSP/NLA we
	// must answer with an RDP_NEG_RSP selecting PROTOCOL_HYBRID (2) —
	// real mstsc aborts if the server doesn't echo a protocol selection.
	// Clients that requested plain TLS get a bare CC (they'll start TLS
	// without NLA and we won't capture creds there).
	requested, _ := detail["requested_security"].(string)
	var ccf []byte
	switch requested {
	case "credssp(nla)":
		// TPKT(4) LI(1) type d0 dst(2) src(2) class(1) + RDP_NEG_RSP(8):
		// type 02 flags 00 length 0008 selectedProtocol PROTOCOL_HYBRID
		ccf = []byte{3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0,
			0x02, 0x00, 0x08, 0x00, 0x02, 0, 0, 0}
	case "tls":
		ccf = []byte{3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0,
			0x02, 0x00, 0x08, 0x00, 0x01, 0, 0, 0} // PROTOCOL_TLS
	default:
		ccf = []byte{3, 0, 0, 11, 0xd0, 0, 0, 0, 0, 0, 0}
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(ccf)
	time.Sleep(200 * time.Millisecond)

	report(Trigger{
		Sensor:   "rdp",
		TokenID:  tokenID,
		Severity: "medium",
		Detail:   detail,
		SeenAt:   time.Now().UTC(),
	})

	// NLA/CredSSP: upgrade to TLS and capture the NTLM exchange.
	if requested == "credssp(nla)" || requested == "tls+credssp" {
		tlsConn := upgradeRDPToTLS(conn)
		if tlsConn != nil {
			handleRDPCredSSP(tlsConn, tokenID, report)
			return
		}
	}

	report(Trigger{
		Sensor:   "rdp",
		TokenID:  tokenID,
		Severity: "high",
		Detail:   detail,
		SeenAt:   time.Now().UTC(),
	})
}
