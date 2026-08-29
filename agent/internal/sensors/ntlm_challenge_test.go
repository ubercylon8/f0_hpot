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
	msg, chal, err := BuildChallenge("FORTIKA")
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
		_, c, err := BuildChallenge("FORTIKA")
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
	_, chal, err := BuildChallenge("FORTIKA")
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
