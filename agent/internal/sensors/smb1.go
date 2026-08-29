package sensors

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"
)

// SMB1 support via EXTENDED SECURITY (SPNEGO/NTLMSSP), which reuses the
// same capture helpers as SMB2:
//
//	negotiate (0x72) -> response advertising extended security + NTLM OID
//	session setup AndX (0x73) with NEGOTIATE -> MORE_PROCESSING + CHALLENGE
//	session setup AndX (0x73) with AUTHENTICATE -> capture + LOGON_FAILURE

const (
	smb1CmdNegotiate     = 0x72
	smb1CmdSessionSetup  = 0x73
	statusMoreProcessing = 0xC0000016
	statusLogonFailure   = 0xC000006D
)

// spnegoInitNTLM is a minimal SPNEGO NegTokenInit offering only NTLMSSP.
func spnegoInitNTLM() []byte {
	oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // NTLMSSP OID
	mechTypes := append([]byte{0x30, byte(len(oid))}, oid...)
	negTokenInit := append([]byte{0xa0, byte(len(mechTypes))}, mechTypes...)
	return append([]byte{0x60, byte(len(negTokenInit))}, negTokenInit...)
}

// buildSMB1NegotiateResponse answers a core/NTLM negotiate with extended
// security so clients send SPNEGO blobs we already understand.
func buildSMB1NegotiateResponse(req []byte) []byte {
	blob := spnegoInitNTLM()
	dialectIdx := selectDialectIndex(req)

	hdr := make([]byte, 32)
	copy(hdr[0:4], "\xffSMB")
	hdr[4] = smb1CmdNegotiate
	// status = 0
	hdr[9] = req[9]                                                    // flags
	flags2 := binary.LittleEndian.Uint16(req[10:12]) | 0x8000 | 0x0400 // STATUS32 | LONG_NAMES
	binary.LittleEndian.PutUint16(hdr[10:12], flags2)
	copy(hdr[12:32], req[12:32]) // PIDHigh, signature, reserved, TID, PID, UID, MID

	words := make([]byte, 0, 35)
	words = append(words, 17) // WordCount
	w := func(v uint16) { words = append(words, byte(v), byte(v>>8)) }
	w32 := func(v uint32) { words = append(words, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	// WordCount 17 = 34 bytes matching SMBNTLMDialect_Parameters:
	// DialectIndex(2) SecurityMode(1) MaxMpx(2) MaxVCs(2) MaxBufferSize(4)
	// MaxRawSize(4) SessionKey(4) Capabilities(4) SysTimeLow(4) SysTimeHigh(4)
	// ServerTimeZone(2) ChallengeLength(1)
	w(uint16(dialectIdx))       // DialectIndex
	words = append(words, 0x03) // SecurityMode: user + encrypted passwords
	w(50)                       // MaxMpxCount
	w(1)                        // MaxNumberVCs
	w32(65535)                  // MaxBufferSize
	w32(65535)                  // MaxRawSize
	w32(0)                      // SessionKey
	w32(0x800002D0)             // Capabilities: EXT_SECURITY|NT_FIND|LEVEL2_OPLOCKS|STATUS32|NT_SMBS
	// SystemTime: fixed plausible value (Low + High)
	words = append(words, 0x20, 0xC4, 0x9A, 0x0D, 0xD5, 0x35, 0xD9, 0x01)
	w(0) // ServerTimeZone
	// ChallengeLength = security blob length (extended security carries the
	// SPNEGO blob where a raw challenge would be)
	words = append(words, byte(len(blob)))

	// Data section: ServerGUID(16) + security blob; ByteCount covers both.
	data := append(make([]byte, 16), blob...)
	out := append(hdr, words...)
	out = append(out, byte(len(data)), byte(len(data)>>8))
	return append(out, data...)
}

// selectDialectIndex picks "NT LM 0.12" from the client's dialect list
// (SMB1 negotiate request: WordCount=0, ByteCount, null-terminated strings).
func selectDialectIndex(req []byte) int {
	if len(req) < 37 {
		return 0
	}
	count := int(binary.LittleEndian.Uint16(req[33:35]))
	pos := 35
	end := pos + count
	if end > len(req) {
		end = len(req)
	}
	cur := 0
	for pos < end {
		start := pos
		for pos < end && req[pos] != 0 {
			pos++
		}
		name := string(req[start:pos])
		pos++ // skip null
		// Dialect entries are prefixed with a 0x02 format byte.
		if name == "\x02NT LM 0.12" {
			return cur
		}
		cur++
	}
	return cur - 1 // last offered dialect as fallback
}

// buildSMB1SessionSetupReply answers a Session Setup AndX with a status
// and optional security blob, echoing the client's PID/UID/MID.
func buildSMB1SessionSetupReply(req []byte, status uint32, uid uint16, blob []byte) []byte {
	hdr := make([]byte, 32)
	copy(hdr[0:4], "\xffSMB")
	hdr[4] = smb1CmdSessionSetup
	binary.LittleEndian.PutUint32(hdr[5:9], status)
	hdr[9] = req[9]
	flags2 := binary.LittleEndian.Uint16(req[10:12]) | 0x8000
	binary.LittleEndian.PutUint16(hdr[10:12], flags2)
	copy(hdr[12:32], req[12:32])
	binary.LittleEndian.PutUint16(hdr[28:30], uid)

	// Session Setup AndX response: WordCount 4
	//   AndXCommand(1) Reserved(1) AndXOffset(2) | Action(2) | SecBlobLen(2)
	words := []byte{4, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, byte(len(blob)), 0x00}
	// Data = blob + NativeOS + NativeLanMan (z-strings); ByteCount covers all
	// Unicode z-strings: utf16le + double-null terminator
	native := utf16Encode("Unix")
	native = append(native, 0, 0)
	native = append(native, utf16Encode("Samba")...)
	native = append(native, 0, 0)
	byteCount := len(blob) + len(native)
	out := append(hdr, words...)
	out = append(out, byte(byteCount), byte(byteCount>>8))
	out = append(out, blob...)
	return append(out, native...)
}

// buildSMB1LegacyNegotiateResponse: for clients that did NOT request
// extended security (flags2 EXTENDED_SECURITY clear). Same 34-byte
// parameter layout, but capabilities WITHOUT CAP_EXTENDED_SECURITY and
// the raw 8-byte challenge as Data (clients hash against it directly).
func buildSMB1LegacyNegotiateResponse(req []byte) ([]byte, [8]byte, error) {
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, challenge, err
	}

	hdr := make([]byte, 32)
	copy(hdr[0:4], "\xffSMB")
	hdr[4] = smb1CmdNegotiate
	hdr[9] = req[9]
	// LONG_NAMES only — no STATUS32/EXT bits in legacy mode
	flags2 := binary.LittleEndian.Uint16(req[10:12]) &^ 0x8800
	flags2 |= 0x0400
	binary.LittleEndian.PutUint16(hdr[10:12], flags2)
	copy(hdr[12:32], req[12:32])

	words := make([]byte, 0, 35)
	words = append(words, 17) // WordCount
	w := func(v uint16) { words = append(words, byte(v), byte(v>>8)) }
	w32 := func(v uint32) { words = append(words, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	w(5)                        // DialectIndex: NT LM 0.12
	words = append(words, 0x03) // SecurityMode
	words = append(words, 0x00) // Reserved
	w(50)                       // MaxMpxCount
	w(1)                        // MaxNumberVCs
	w32(65535)                  // MaxBufferSize
	w32(65535)                  // MaxRawSize
	w32(0)                      // SessionKey
	w32(0x000002D0)             // Capabilities: NO extended security
	words = append(words, 0x20, 0xC4, 0x9A, 0x0D)
	words = append(words, 0xD5, 0x35, 0xD9, 0x01)
	w(0)                     // ServerTimeZone
	words = append(words, 8) // ChallengeLength

	out := append(hdr, words...)
	out = append(out, 0x08, 0x00) // ByteCount = 8
	return append(out, challenge[:]...), challenge, nil
}

// clientRequestedExtendedSecurity: flags2 EXTENDED_SECURITY_NEGOTIATE bit.
func clientRequestedExtendedSecurity(req []byte) bool {
	if len(req) < 12 {
		return false
	}
	return binary.LittleEndian.Uint16(req[10:12])&0x0800 != 0
}

// handleSMB1LegacySetup captures credentials from a legacy (non-SPNEGO)
// Session Setup AndX: ANSI/Unicode password fields + account + domain.
// Request layout (WordCount 13): AndX(3) MaxBuffer(2) MaxMpx(2) VC(2)
// SessionKey(4) AnsiPwdLen(2) UniPwdLen(2) Reserved(4) Capabilities(4),
// ByteCount(2), then data: ansiPwd, uniPwd, account, domain, nativeOS...
// Field offsets are absolute from the start of the SMB message.
func handleSMB1LegacySetup(t *smbTransport, buf []byte, challenge [8]byte, uid uint16, tokenID string, report Reporter) {
	if len(buf) < 61 {
		return
	}
	ansiPwdLen := int(binary.LittleEndian.Uint16(buf[47:49]))
	uniPwdLen := int(binary.LittleEndian.Uint16(buf[49:51]))
	accountLen := int(binary.LittleEndian.Uint16(buf[51:53]))

	// Data layout: ansiPwd, uniPwd, account ("DOMAIN\user" or "user"),
	// nativeOS, lanMan... starting after ByteCount: 32 hdr + 1 wc + wc*2
	// params + 2 bc. No separate domain-length field in legacy setups.
	dataStart := 35 + int(buf[32])*2
	if dataStart+ansiPwdLen+uniPwdLen+accountLen > len(buf) {
		return
	}

	unicode := binary.LittleEndian.Uint16(buf[10:12])&0x8000 != 0
	decode := func(b []byte) string {
		if unicode {
			return utf16ToString(b)
		}
		return string(b)
	}

	pos := dataStart
	ansiPwd := buf[pos : pos+ansiPwdLen]
	pos += ansiPwdLen
	uniPwd := buf[pos : pos+uniPwdLen]
	pos += uniPwdLen
	account := strings.TrimRight(decode(buf[pos:pos+accountLen]), "\x00")

	// Account is often "DOMAIN\user".
	domain := ""
	if slash := strings.LastIndex(account, "\\"); slash >= 0 {
		domain = account[:slash]
		account = account[slash+1:]
	}

	line := fmt.Sprintf("%s::%s:%s:%s:%s",
		account, domain, hexLower(challenge[:]),
		hexLower(ansiPwd), hexLower(uniPwd))
	log.Printf("[smb1] captured legacy credentials user=%q domain=%q from %s",
		account, domain, remoteIP(t.conn))
	report(Trigger{
		Sensor:   "smb",
		TokenID:  tokenID,
		Severity: "high",
		Detail: map[string]interface{}{
			"event":     "legacy_credentials",
			"protocol":  "SMB1-legacy",
			"source_ip": remoteIP(t.conn),
			"username":  account,
			"domain":    domain,
			"hashcat":   line,
		},
		SeenAt: time.Now().UTC(),
	})
	_ = t.writeMsg(buildSMB1SessionSetupReply(buf, statusLogonFailure, uid, nil))
}

// handleSMB1 runs the SMB1 state machine after the negotiate frame.
func handleSMB1(t *smbTransport, firstMsg []byte, tokenID string, report Reporter) {
	// Negotiate: extended (SPNEGO) vs legacy (raw challenge) by flags2.
	if len(firstMsg) < 35 || firstMsg[4] != smb1CmdNegotiate {
		return
	}
	var challenge [8]byte
	if clientRequestedExtendedSecurity(firstMsg) {
		if err := t.writeMsg(buildSMB1NegotiateResponse(firstMsg)); err != nil {
			return
		}
	} else {
		resp, chal, err := buildSMB1LegacyNegotiateResponse(firstMsg)
		if err != nil {
			return
		}
		challenge = chal
		if err := t.writeMsg(resp); err != nil {
			return
		}
	}

	uid := uint16(0x1000)
	// Held across round trips so the AUTHENTICATE can be scored against
	// the challenge we actually issued (extended-security path).
	var serverChallenge [8]byte
	for i := 0; i < 4; i++ {
		buf, err := t.readMsg()
		if err != nil || len(buf) < 35 {
			return
		}
		if buf[4] != smb1CmdSessionSetup {
			return
		}
		if !clientRequestedExtendedSecurity(firstMsg) {
			handleSMB1LegacySetup(t, buf, challenge, uid, tokenID, report)
			return
		}
		blob := findNTLMBlob(buf)
		if blob == nil {
			return
		}
		switch {
		case IsNegotiate(blob):
			chalMsg, chal, err := BuildChallenge("FORTIKA")
			if err != nil {
				return
			}
			serverChallenge = chal
			// Wrap challenge in SPNEGO negTokenResp (accept-completed):
			// a1 { 30 { a0 negState, a2 responseToken } }
			respTok := append([]byte{0x04, byte(len(chalMsg))}, chalMsg...)
			inner := append([]byte{0xa0, 0x03, 0x0a, 0x01, 0x00},
				append([]byte{0xa2, byte(len(respTok))}, respTok...)...)
			body := append([]byte{0x30, byte(len(inner))}, inner...)
			resp := append([]byte{0xa1, byte(len(body))}, body...)
			uid += 0x10
			if err := t.writeMsg(buildSMB1SessionSetupReply(buf, statusMoreProcessing, uid, resp)); err != nil {
				return
			}

		case IsAuthenticate(blob):
			auth, err := ParseAuthenticate(blob)
			if err != nil {
				log.Printf("[smb1] auth parse failed from %s: %v", remoteIP(t.conn), err)
				return
			}
			auth.Challenge = serverChallenge
			line := HashcatLine(auth)
			log.Printf("[smb1] captured credentials user=%q domain=%q host=%q from %s",
				auth.Username, auth.Domain, auth.Host, remoteIP(t.conn))
			report(Trigger{
				Sensor:   "smb",
				TokenID:  tokenID,
				Severity: "high",
				Detail: map[string]interface{}{
					"event":     "ntlm_credentials",
					"protocol":  "SMB1",
					"source_ip": remoteIP(t.conn),
					"username":  auth.Username,
					"domain":    auth.Domain,
					"host":      auth.Host,
					"hashcat":   line,
				},
				SeenAt: time.Now().UTC(),
			})
			_ = t.writeMsg(buildSMB1SessionSetupReply(buf, statusLogonFailure, uid, nil))
			return

		default:

			return
		}
	}
}

var _ = fmt.Sprintf
