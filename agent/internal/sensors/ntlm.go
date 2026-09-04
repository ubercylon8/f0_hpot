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

// NTLM negotiate flags (MS-NLMP 2.2.2.5). Named so the constant below
// cannot drift from its own comment, as it did: the value was 0x00008201
// while the comment claimed REQUEST_TARGET, which is not among those bits.
const (
	ntlmNegotiateUnicode    = 0x00000001
	ntlmRequestTarget       = 0x00000004
	ntlmNegotiateSign       = 0x00000010
	ntlmNegotiateSeal       = 0x00000020
	ntlmNegotiateNTLM       = 0x00000200
	ntlmNegotiateAlwaysSign = 0x00008000
	// ntlmNegotiateVersion is the only flag a persona controls; it is set
	// with the VERSION structure and cleared without it. Real Samba sends
	// neither.
	ntlmNegotiateVersion = 0x02000000
	ntlmNegotiateKeyExch = 0x40000000
)

// ntlmChallengeFlags we advertise on the challenge. Deliberately NOT
// advertising key exchange or strong crypto (sign/seal) so clients fall
// back to crackable NTLMv1/v2 responses over our challenge.
const ntlmChallengeFlags = ntlmNegotiateUnicode | ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign

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

// encodeVersion renders the VERSION structure (MS-NLMP 2.2.2.10). The build is
// a little-endian uint16; writing those two bytes by hand is how this file
// came to advertise build 46855.
func encodeVersion(major, minor uint8, build uint16) []byte {
	return []byte{major, minor, byte(build), byte(build >> 8), 0, 0, 0, 15}
}

func decodeVersion(b []byte) (major, minor uint8, build uint16, ok bool) {
	if len(b) < 8 {
		return 0, 0, 0, false
	}
	return b[0], b[1], uint16(b[2]) | uint16(b[3])<<8, true
}

// buildTargetInfo constructs AV pairs the way real servers do (impacket
// and other clients parse them eagerly; an empty list trips some parsers).
// The domain and the computer are separate names: a server whose NetBIOS
// domain equals its own hostname is a tell.
func buildTargetInfo(id Identity) []byte {
	ti := avPair(avNbDomain, id.NBDomain)
	ti = append(ti, avPair(avNbComputer, id.NBComputer)...)
	if id.DNSDomain != "" {
		ti = append(ti, avPair(avDnsDomain, id.DNSDomain)...)
	}
	ti = append(ti, avPair(avDnsHostname, id.DNSHostname)...)
	ti = append(ti, avPair(avEOL, "")...) // 4-byte EOL: type + zero length
	return ti
}

// ntlmChallengeFixedLen is the CHALLENGE header up to but excluding the
// optional VERSION structure (MS-NLMP 2.2.1.2): signature 8 + message type 4
// + TargetName fields 8 + flags 4 + server challenge 8 + reserved 8 +
// TargetInfo fields 8. The payload starts here, or 8 bytes later when a
// version block is emitted — never at a fixed 56.
const ntlmChallengeFixedLen = 48

// BuildChallenge constructs an NTLM CHALLENGE (type 2) message with a
// fresh random server challenge, naming the identity's NetBIOS domain.
func BuildChallenge(id Identity) (msg []byte, challenge [8]byte, err error) {
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, challenge, err
	}
	target := utf16Encode(id.NBDomain)
	ti := buildTargetInfo(id)

	flags := uint32(ntlmChallengeFlags)
	var version []byte
	if id.Persona.HasVersion {
		flags |= ntlmNegotiateVersion
		version = encodeVersion(id.Persona.VerMajor, id.Persona.VerMinor, id.Persona.VerBuild)
	}
	// Derived, not hardcoded: a persona that sends no version block puts its
	// payload 8 bytes earlier, and a stale 56 would still parse while
	// pointing the client at the wrong bytes.
	targetOff := ntlmChallengeFixedLen + len(version)

	m := make([]byte, 0, targetOff+len(target)+len(ti))
	m = append(m, ntlmMagic...)
	m = le32(m, ntlmTypeChallenge)
	// TargetName: len, alloc, offset
	m = le16(m, len(target))
	m = le16(m, len(target))
	m = le32(m, targetOff)
	// User flags
	m = le32(m, int(flags))
	// Server challenge
	m = append(m, challenge[:]...)
	// Reserved (8 zero bytes)
	m = append(m, make([]byte, 8)...)
	// TargetInfo: len, alloc, offset
	m = le16(m, len(ti))
	m = le16(m, len(ti))
	m = le32(m, targetOff+len(target))
	// Version block, only when NEGOTIATE_VERSION is set
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
