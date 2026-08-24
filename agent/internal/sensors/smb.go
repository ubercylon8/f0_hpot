package sensors

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// SMBSensor: protocol-aware low-interaction SMB honeypot on :445.
// Parses the NetBIOS session header + SMB negotiate request, replies with a
// minimal SMB2 negotiate response advertising NTLM so scanners proceed to
// session setup, then closes. Full NTLM credential capture is future work.
type SMBSensor struct{}

func (SMBSensor) Name() string { return "smb" }

func (SMBSensor) Start(cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 445)
	tokenID := str(cfg, "token_id", "")
	return serveTCPSensor("smb", port, tokenID, handleSMBConn, report)
}

func handleSMBConn(conn net.Conn, tokenID string, report Reporter) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// NetBIOS session service header: 4 bytes; type 0x00 = session message.
	nb := make([]byte, 4)
	if _, err := io.ReadFull(conn, nb); err != nil {
		return
	}
	if nb[0] != 0x00 {
		return
	}
	length := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if length <= 0 || length > 16*1024 {
		return
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	detail := map[string]interface{}{
		"source_ip": remoteIP(conn),
		"bytes":     length,
	}
	if len(buf) < 4 || string(buf[0:4]) != "\xffSMB" && string(buf[0:4]) != "\xfeSMB" {
		log.Printf("[smb] non-SMB payload from %s (%d bytes)", detail["source_ip"], length)
		detail["event"] = "probe"
		report(Trigger{
			Sensor:   "smb",
			TokenID:  tokenID,
			Severity: "medium",
			Detail:   detail,
			SeenAt:   time.Now().UTC(),
		})
		return
	}

	if len(buf) >= 36 && binary.LittleEndian.Uint16(buf[4:6]) == 0x24 {
		detail["protocol"] = "SMB2"
	} else {
		detail["protocol"] = "SMB1"
	}
	detail["event"] = "negotiate"
	log.Printf("[smb] %s negotiate from %s", detail["protocol"], detail["source_ip"])

	resp := buildSMB2NegotiateResponse()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	totalLen := len(resp)
	hdr := []byte{0x00, byte(totalLen >> 16), byte(totalLen >> 8), byte(totalLen)}
	if _, err := conn.Write(append(hdr, resp...)); err != nil {
		return
	}

	report(Trigger{
		Sensor:   "smb",
		TokenID:  tokenID,
		Severity: "high",
		Detail:   detail,
		SeenAt:   time.Now().UTC(),
	})

	smbSessionLoop(conn, tokenID, report)
}

// smbSessionLoop handles SESSION_SETUP exchanges after negotiation,
// running one NTLM challenge round and capturing whatever credentials
// the client volunteers.
func smbSessionLoop(conn net.Conn, tokenID string, report Reporter) {
	log.Printf("[smb-debug] loop entered")
	for i := 0; i < 4; i++ { // bounded: at most a few round trips
		buf, err := readNetBIOSMessage(conn)
		if err != nil {
			log.Printf("[smb-debug] read err: %v", err)
			return
		}
		if len(buf) < 64 {
			return
		}
		command := binary.LittleEndian.Uint16(buf[12:14])
		sessionID := binary.LittleEndian.Uint64(buf[40:48])
		log.Printf("[smb-debug] session setup cmd=%d len=%d", command, len(buf))
		if command != 0x01 { // SMB2 SESSION_SETUP only
			return
		}
		if len(buf) < 88 {
			return
		}
		blobOff := int(binary.LittleEndian.Uint16(buf[78:80]))
		blobLen := int(binary.LittleEndian.Uint16(buf[80:82]))
		if blobOff <= 0 || blobOff+blobLen > len(buf) {
			return
		}
		secBlob := buf[blobOff : blobOff+blobLen]

		switch {
		case IsNegotiate(secBlob):
			challengeMsg, _, err := BuildChallenge("FORTIKA")
			if err != nil {
				return
			}
			reply := buildSMB2StatusReply(0xC0000016, sessionID|1, challengeMsg) // MORE_PROCESSING_REQUIRED
			writeNetBIOS(conn, reply)

		case IsAuthenticate(secBlob):
			msg := findNTLMBlob(secBlob)
			auth, err := ParseAuthenticate(msg)
			if err != nil {
				log.Printf("[smb] auth parse failed from %s: %v", remoteIP(conn), err)
				return
			}
			line := HashcatLine(auth)
			log.Printf("[smb] captured credentials user=%q domain=%q host=%q from %s",
				auth.Username, auth.Domain, auth.Host, remoteIP(conn))
			report(Trigger{
				Sensor:   "smb",
				TokenID:  tokenID,
				Severity: "high",
				Detail: map[string]interface{}{
					"event":     "ntlm_credentials",
					"source_ip": remoteIP(conn),
					"username":  auth.Username,
					"domain":    auth.Domain,
					"host":      auth.Host,
					"hashcat":   line,
				},
				SeenAt: time.Now().UTC(),
			})
			fail := buildSMB2StatusReply(0xC000006D, sessionID|1, nil) // LOGON_FAILURE
			writeNetBIOS(conn, fail)
			return
		default:
			return
		}
	}
}

// readNetBIOSMessage reads one NetBIOS-framed SMB message.
func readNetBIOSMessage(conn net.Conn) ([]byte, error) {
	nb := make([]byte, 4)
	if _, err := io.ReadFull(conn, nb); err != nil {
		return nil, err
	}
	length := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if length <= 0 || length > 16*1024 {
		return nil, fmt.Errorf("bad NetBIOS length %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeNetBIOS(conn net.Conn, msg []byte) error {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	totalLen := len(msg)
	hdr := []byte{0x00, byte(totalLen >> 16), byte(totalLen >> 8), byte(totalLen)}
	_, err := conn.Write(append(hdr, msg...))
	return err
}

// buildSMB2StatusReply constructs a bare SMB2 reply with a status and an
// optional security blob (used for session setup flows).
func buildSMB2StatusReply(status uint32, sessionID uint64, blob []byte) []byte {
	const secOffset = 72
	out := make([]byte, 64)
	copy(out[0:4], "\xfeSMB")
	binary.LittleEndian.PutUint16(out[4:6], 64)
	binary.LittleEndian.PutUint32(out[8:12], status)
	binary.LittleEndian.PutUint16(out[12:14], 0x01) // SESSION_SETUP

	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	if blob != nil {
		binary.LittleEndian.PutUint16(body[4:6], secOffset)
		binary.LittleEndian.PutUint16(body[6:8], uint16(len(blob)))
	}
	out = append(out, body...)
	binary.LittleEndian.PutUint64(out[40:48], sessionID)
	out = append(out, blob...)
	return out
}

// buildSMB2NegotiateResponse returns header(64) + fixed body(64) + SPNEGO/NTLM
// token, per MS-SMB2 2.2.4. Enough for scanners to attempt session setup.
func buildSMB2NegotiateResponse() []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], "\xfeSMB")
	hdr[4] = 64   // StructureSize
	hdr[6] = 0x01 // Flags: SERVER_TO_REDIR

	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)           // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0x02)         // SecurityMode: signing disabled
	binary.LittleEndian.PutUint16(body[4:6], 0x0202)       // Dialect 2.0.2
	binary.LittleEndian.PutUint32(body[24:28], 0x00000001) // Capabilities: DFS
	binary.LittleEndian.PutUint32(body[28:32], 8192)       // MaxTransactionSize
	binary.LittleEndian.PutUint32(body[32:36], 65536)      // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 65536)      // MaxWriteSize
	now := uint64(time.Now().UnixNano()) + 116444736000000000
	binary.LittleEndian.PutUint64(body[40:48], now)
	binary.LittleEndian.PutUint16(body[48:50], 128) // SecurityBufferOffset

	token := ntlmSpnegoPlaceholder()
	binary.LittleEndian.PutUint16(body[50:52], uint16(len(token)))

	out := append(hdr, body...)
	return append(out, token...)
}

// ntlmSpnegoPlaceholder: minimal SPNEGO response advertising NTLMSSP.
func ntlmSpnegoPlaceholder() []byte {
	inner := []byte{
		0xa0, 0x03, 0x02, 0x01, 0x00, // negResult: accept-completed
		0xa1, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, // NTLM OID
		0xa2, 0x06, 0x04, 0x04, 'N', 'T', 'L', 'M', // mech token
	}
	body := append([]byte{0x30, byte(len(inner))}, inner...)
	return append([]byte{0xa1, byte(len(body))}, body...)
}

var _ = fmt.Sprintf
