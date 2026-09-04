package sensors

import (
	"bytes"
	"strings"
	"testing"
)

// The server challenge is issued with the CHALLENGE message and must be
// carried to the AUTHENTICATE a round trip later. Every capture path used to
// discard it (`chalMsg, _, err := BuildChallenge(...)`), leaving a hashcat
// line with an all-zero challenge that cannot be cracked or correlated.
func TestBuildChallengeReturnsUsableChallenge(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_hostname": "testhost"}, "smb")
	msg, chal, err := BuildChallenge(id)
	if err != nil {
		t.Fatal(err)
	}
	if chal == ([8]byte{}) {
		t.Fatal("BuildChallenge returned a zero challenge")
	}
	// The challenge the caller keeps must be the one actually on the wire,
	// or the captured hash is scored against the wrong value.
	if !bytes.Contains(msg, chal[:]) {
		t.Fatal("challenge message does not carry the returned challenge")
	}

	second := func() [8]byte {
		_, c, err := BuildChallenge(id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}()
	if chal == second {
		t.Fatal("challenge is not random across connections")
	}
}

func TestHashcatLineCarriesTheServerChallenge(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_hostname": "testhost"}, "smb")
	_, chal, err := BuildChallenge(id)
	if err != nil {
		t.Fatal(err)
	}
	auth := &ntlmAuth{
		Username:     "svc_backup",
		Domain:       "CORP",
		NtlmResponse: bytes.Repeat([]byte{0xab}, 32),
	}

	// Regression: without threading, the line carries 16 zeros.
	zeroed := HashcatLine(auth)
	if !strings.Contains(zeroed, "0000000000000000") {
		t.Fatal("expected an unset challenge to render as zeros (test premise)")
	}

	auth.Challenge = chal
	line := HashcatLine(auth)
	if strings.Contains(line, "0000000000000000") {
		t.Fatalf("hashcat line still carries a zero challenge: %s", line)
	}
	if !strings.Contains(line, hexLower(chal[:])) {
		t.Fatalf("hashcat line does not carry the server challenge: %s", line)
	}
	if !strings.HasPrefix(line, `CORP\svc_backup::CORP:`) {
		t.Fatalf("unexpected hashcat line shape: %s", line)
	}
}

// The version block shipped as hand-written bytes {10,0,7,183,...}, which
// decodes to build 46855 — no such Windows build exists. The comment above
// it claimed 18362. Round-tripping the encoder retires that class of bug.
func TestVersionEncodingRoundTrips(t *testing.T) {
	for _, p := range Personas() {
		if !p.HasVersion {
			continue
		}
		maj, min, build, ok := decodeVersion(encodeVersion(p.VerMajor, p.VerMinor, p.VerBuild))
		if !ok {
			t.Fatalf("persona %s: version block did not decode", p.ID)
		}
		if maj != p.VerMajor || min != p.VerMinor || build != p.VerBuild {
			t.Errorf("persona %s: round-trip gave %d.%d.%d, want %d.%d.%d",
				p.ID, maj, min, build, p.VerMajor, p.VerMinor, p.VerBuild)
		}
	}
}

// The old encoding is what this test would have caught.
func TestVersionEncodingRejectsTheOldBytes(t *testing.T) {
	_, _, build, ok := decodeVersion([]byte{10, 0, 7, 183, 0, 0, 0, 15})
	if !ok {
		t.Fatal("decodeVersion could not read a well-formed block")
	}
	if build == 17763 {
		t.Fatal("the old bytes decode to 17763, so this test proves nothing")
	}
	t.Logf("the shipped bytes decoded to build %d, which is not a real release", build)
}

func TestChallengeCarriesPersonaVersionOnlyWhenItHasOne(t *testing.T) {
	win := Resolve(map[string]interface{}{"persona": "windows-server-2019", "agent_hostname": "h"}, "smb")
	msg, _, err := BuildChallenge(win)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(msg, encodeVersion(10, 0, 17763)) {
		t.Error("Windows persona did not emit its version block")
	}

	samba := Resolve(map[string]interface{}{"persona": "samba-ubuntu-2204", "agent_hostname": "h"}, "smb")
	msg, _, err = BuildChallenge(samba)
	if err != nil {
		t.Fatal(err)
	}
	// NEGOTIATE_VERSION is bit 0x02000000 of the flags field at offset 20.
	flags := uint32(msg[20]) | uint32(msg[21])<<8 | uint32(msg[22])<<16 | uint32(msg[23])<<24
	if flags&0x02000000 != 0 {
		t.Error("Samba persona set NEGOTIATE_VERSION; real Samba does not")
	}
}

// A payload offset of 56 is right only while a version block is emitted. The
// Samba persona emits none, so its payload begins at 48. Get this wrong and
// the message is still well-formed — every length field agrees — but it
// points the client at the wrong bytes, which no other test here notices.
func TestChallengePayloadOffsetsFollowTheVersionBlock(t *testing.T) {
	for _, p := range Personas() {
		t.Run(p.ID, func(t *testing.T) {
			id := Resolve(map[string]interface{}{
				"persona": p.ID, "agent_hostname": "fs-win-02", "domain": "CORP",
			}, "smb")
			msg, _, err := BuildChallenge(id)
			if err != nil {
				t.Fatal(err)
			}
			// signature 8 + type 4 + TargetName fields 8 + flags 4 +
			// challenge 8 + reserved 8 + TargetInfo fields 8 = 48.
			wantFixed := 48
			if p.HasVersion {
				wantFixed = 56
			}
			if len(msg) < wantFixed {
				t.Fatalf("message is %d bytes, shorter than its own fixed part (%d)", len(msg), wantFixed)
			}
			u16 := func(off int) int { return int(msg[off]) | int(msg[off+1])<<8 }
			u32 := func(off int) int {
				return int(msg[off]) | int(msg[off+1])<<8 |
					int(msg[off+2])<<16 | int(msg[off+3])<<24
			}
			tnLen, tnMax, tnOff := u16(12), u16(14), u32(16)
			tiLen, tiMax, tiOff := u16(40), u16(42), u32(44)

			if tnLen != tnMax || tiLen != tiMax {
				t.Errorf("len/maxlen disagree: TargetName %d/%d, TargetInfo %d/%d",
					tnLen, tnMax, tiLen, tiMax)
			}
			if tnOff != wantFixed {
				t.Errorf("TargetName offset = %d, want %d (persona HasVersion=%v)",
					tnOff, wantFixed, p.HasVersion)
			}
			if tiOff != wantFixed+tnLen {
				t.Errorf("TargetInfo offset = %d, want %d", tiOff, wantFixed+tnLen)
			}
			if len(msg) != wantFixed+tnLen+tiLen {
				t.Fatalf("message is %d bytes, want %d — a trailing or missing version block",
					len(msg), wantFixed+tnLen+tiLen)
			}
			if tnOff+tnLen > len(msg) || tiOff+tiLen > len(msg) {
				t.Fatalf("payload fields point past the end of a %d-byte message", len(msg))
			}
			if got := utf16ToString(msg[tnOff : tnOff+tnLen]); got != id.NBDomain {
				t.Errorf("TargetName offset points at %q, want the NetBIOS domain %q", got, id.NBDomain)
			}
			if !bytes.Equal(msg[tiOff:tiOff+tiLen], buildTargetInfo(id)) {
				t.Error("TargetInfo offset does not point at the AV pair list")
			}
			if p.HasVersion && !bytes.Equal(msg[48:56], encodeVersion(p.VerMajor, p.VerMinor, p.VerBuild)) {
				t.Error("the 8 bytes before the payload are not this persona's version block")
			}
		})
	}
}

// The weak-crypto flags are deliberate: they make clients fall back to
// crackable NTLMv1/v2 responses, which is the sensor's purpose.
func TestChallengePreservesTheDeliberatelyWeakFlags(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_hostname": "h"}, "smb")
	msg, _, err := BuildChallenge(id)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(msg[20]) | uint32(msg[21])<<8 | uint32(msg[22])<<16 | uint32(msg[23])<<24
	const wantBase = ntlmNegotiateUnicode | ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign
	if flags&wantBase != wantBase {
		t.Errorf("base flags = 0x%08X, want 0x%08X set", flags, wantBase)
	}
	if flags&ntlmNegotiateSign != 0 || flags&ntlmNegotiateSeal != 0 || flags&ntlmNegotiateKeyExch != 0 {
		t.Error("challenge advertised sign/seal/key-exchange; clients would stop sending crackable responses")
	}
}

func TestTargetInfoNamesDifferForDomainAndComputer(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_hostname": "fs-win-02"}, "smb")
	ti := buildTargetInfo(id)
	if !bytes.Contains(ti, utf16Encode("WORKGROUP")) {
		t.Error("target info is missing the NetBIOS domain")
	}
	if !bytes.Contains(ti, utf16Encode("FS-WIN-02")) {
		t.Error("target info is missing the NetBIOS computer name")
	}
}
