package sensors

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
)

// Minimal NTLMSSP message handling for credential capture.
//
// Flow: client sends NEGOTIATE (type 1), we reply with a CHALLENGE
// (type 2, random 8-byte server challenge), client responds with an
// AUTHENTICATE (type 3) carrying username/domain and LM/NTLM responses
// that are crackable offline. This mirrors Responder-style capture.

var ntlmMagic = []byte("NTLMSSP\x00")

const (
	ntlmTypeNegotiate    = 1
	ntlmTypeChallenge    = 2
	ntlmTypeAuthenticate = 3
)

// ntlmFlags we advertise on the challenge. Deliberately NOT advertising
// key exchange or strong crypto so clients fall back to crackable
// NTLMv1/v2 responses over our challenge.
const ntlmChallengeFlags = 0x00008201 | // NEGOTIATE_NTLM | REQUEST_TARGET | NEGOTIATE_UNICODE
	0x02000000 // NEGOTIATE_VERSION

// findNTLMBlob locates the NTLMSSP signature inside a security blob,
// which may be raw or SPNEGO-wrapped.
func findNTLMBlob(blob []byte) []byte {
	idx := indexOf(blob, ntlmMagic)
	if idx < 0 {
		return nil
	}
	return blob[idx:]
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+8 <= len(haystack); i++ {
		if haystack[i] == needle[0] && string(haystack[i:i+8]) == string(needle) {
			return i
		}
	}
	return -1
}

type ntlmAuth struct {
	Username     string
	Domain       string
	Host         string
	LmResponse   []byte
	NtlmResponse []byte // first 16 bytes = NTProofStr; rest = blob
	Challenge    [8]byte
}

// IsAuthenticate returns true if the blob is an NTLM AUTHENTICATE message.
func IsAuthenticate(blob []byte) bool {
	msg := findNTLMBlob(blob)
	if msg == nil || len(msg) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(msg[8:12]) == ntlmTypeAuthenticate
}

// IsNegotiate returns true if the blob is an NTLM NEGOTIATE message.
func IsNegotiate(blob []byte) bool {
	msg := findNTLMBlob(blob)
	if msg == nil || len(msg) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(msg[8:12]) == ntlmTypeNegotiate
}

// ParseAuthenticate extracts identity + response fields from an
// AUTHENTICATE message.
func ParseAuthenticate(msg []byte) (*ntlmAuth, error) {
	if len(msg) < 56 {
		return nil, fmt.Errorf("authenticate message too short: %d", len(msg))
	}
	u16 := func(off int) int { return int(binary.LittleEndian.Uint16(msg[off : off+2])) }
	u32off := func(off int) int { return int(binary.LittleEndian.Uint32(msg[off : off+4])) }

	lmLen, lmOff := u16(12), u32off(16)
	ntlLen, ntlOff := u16(20), u32off(24)
	domLen, domOff := u16(28), u32off(32)
	userLen, userOff := u16(36), u32off(40)
	hostLen, hostOff := u16(44), u32off(48)

	safe := func(off, l int) ([]byte, error) {
		// Honeypot-tolerant: clients (and our own emulators) sometimes lie
		// by a couple of bytes. Clamp rather than reject.
		if off < 0 || l < 0 || off >= len(msg) {
			return nil, fmt.Errorf("field out of bounds: off=%d len=%d msg=%d", off, l, len(msg))
		}
		end := off + l
		if end > len(msg) {
			end = len(msg)
		}
		return msg[off:end], nil
	}

	auth := &ntlmAuth{}
	var err error
	if auth.LmResponse, err = safe(lmOff, lmLen); err != nil {
		return nil, err
	}
	if auth.NtlmResponse, err = safe(ntlOff, ntlLen); err != nil {
		return nil, err
	}
	domain, err := safe(domOff, domLen)
	if err != nil {
		return nil, err
	}
	user, err := safe(userOff, userLen)
	if err != nil {
		return nil, err
	}
	host, err := safe(hostOff, hostLen)
	if err != nil {
		return nil, err
	}
	auth.Username = utf16ToString(user)
	auth.Domain = utf16ToString(domain)
	auth.Host = utf16ToString(host)
	return auth, nil
}

// utf16ToString decodes little-endian UTF-16 without allocations gymnastics.
func utf16ToString(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		sb.WriteRune(r)
	}
	return sb.String()
}

// NTLM AV pair IDs (MS-NLMP 2.2.2.1)
const (
	avEOL         = 0x0000
	avNbDomain    = 0x0001
	avNbComputer  = 0x0003
	avDnsDomain   = 0x0004
	avDnsServer   = 0x0005
	avDnsHostname = 0x0006
)

func avPair(id uint16, value string) []byte {
	v := utf16Encode(value)
	out := le16(nil, int(id))
	out = le16(out, len(v))
	return append(out, v...)
}

// buildTargetInfo constructs AV pairs the way real servers do (impacket
// and other clients parse them eagerly; an empty list trips some parsers).
func buildTargetInfo(domain string) []byte {
	ti := avPair(avNbDomain, domain)
	ti = append(ti, avPair(avNbComputer, domain)...)
	ti = append(ti, avPair(avDnsDomain, domain+".local")...)
	ti = append(ti, avPair(avDnsHostname, domain)...)
	ti = append(ti, avPair(avEOL, "")...) // 4-byte EOL: type + zero length
	return ti
}

// BuildChallenge constructs an NTLM CHALLENGE (type 2) message with a
// fresh random server challenge and a decoy domain name.
func BuildChallenge(targetName string) (msg []byte, challenge [8]byte, err error) {
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, challenge, err
	}
	target := utf16Encode(targetName)
	ti := buildTargetInfo(targetName)

	flags := uint32(ntlmChallengeFlags)
	m := make([]byte, 0, 64+len(target)+len(ti))
	m = append(m, ntlmMagic...)
	m = le32(m, ntlmTypeChallenge)
	// TargetName: len, alloc, offset
	m = le16(m, len(target))
	m = le16(m, len(target))
	m = le32(m, 56) // offset after fixed part incl. version block
	// User flags
	m = le32(m, int(flags))
	// Server challenge
	m = append(m, challenge[:]...)
	// Reserved (8 zero bytes)
	m = append(m, make([]byte, 8)...)
	// TargetInfo: len, alloc, offset
	m = le16(m, len(ti))
	m = le16(m, len(ti))
	m = le32(m, 56+len(target))
	// Version block (pretend Windows 10 18362)
	version := []byte{10, 0, 7, 183, 0, 0, 0, 15}
	m = append(m, version...)
	// Payloads
	m = append(m, target...)
	m = append(m, ti...)
	return m, challenge, nil
}

func utf16Encode(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			continue // surrogate pairs unnecessary for decoy names
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func le16(dst []byte, v int) []byte { return append(dst, byte(v), byte(v>>8)) }
func le32(dst []byte, v int) []byte {
	return append(dst, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// HashcatLine renders the captured material in hashcat NTLMv2 format
// (mode 5600): user::domain:challenge:NTproofstr:blob — or NTLMv1
// (mode 5500) style when the response is 24 bytes.
func HashcatLine(auth *ntlmAuth) string {
	user := auth.Username
	if auth.Domain != "" {
		user = auth.Domain + "\\" + auth.Username
	}
	chal := hexLower(auth.Challenge[:])
	if len(auth.NtlmResponse) == 24 {
		// NTLMv1: user::domain:challenge:lm:ntlm
		return fmt.Sprintf("%s::%s:%s:%s:%s",
			user, auth.Domain, chal,
			hexLower(auth.LmResponse), hexLower(auth.NtlmResponse))
	}
	if len(auth.NtlmResponse) >= 16 {
		return fmt.Sprintf("%s::%s:%s:%s:%s",
			user, auth.Domain, chal,
			hexLower(auth.NtlmResponse[:16]), hexLower(auth.NtlmResponse[16:]))
	}
	return fmt.Sprintf("%s::%s:%s:::", user, auth.Domain, chal)
}

func hexLower(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexdigits[x>>4], hexdigits[x&0xf])
	}
	return string(out)
}
