package sensors

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// Every shipped persona must be internally consistent. The defect this
// replaces was a Samba server advertising a Windows build number that has
// never existed, so these assertions are about realism, not well-formedness.
func TestPersonasAreInternallyConsistent(t *testing.T) {
	for _, p := range Personas() {
		if p.ID == "" || p.NativeOS == "" || p.NativeLanMan == "" {
			t.Errorf("persona %q has an empty required field", p.ID)
		}
		if p.HasVersion && p.VerBuild == 0 {
			t.Errorf("persona %q claims a version but has build 0", p.ID)
		}
		if !p.HasVersion && p.VerBuild != 0 {
			t.Errorf("persona %q omits its version block but still carries build %d", p.ID, p.VerBuild)
		}
		if p.DNSSuffix == "" {
			t.Errorf("persona %q has no DNS suffix", p.ID)
		}
	}
}

// Real Samba does not set NEGOTIATE_VERSION and sends no version structure.
func TestSambaPersonaOmitsWindowsVersion(t *testing.T) {
	p, ok := LookupPersona("samba-ubuntu-2204")
	if !ok {
		t.Fatal("samba-ubuntu-2204 is not registered")
	}
	if p.HasVersion {
		t.Error("the Samba persona must not advertise a Windows version block")
	}
}

// A domain and a computer name are never the same string on a real host;
// they were identical before this change.
func TestDefaultsArePlausible(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_hostname": "fs-win-02"}, "smb")
	if id.NBDomain == id.NBComputer {
		t.Errorf("domain and computer name are both %q", id.NBDomain)
	}
	if id.NBDomain != "WORKGROUP" {
		t.Errorf("default domain = %q, want WORKGROUP", id.NBDomain)
	}
	if id.NBComputer != "FS-WIN-02" {
		t.Errorf("computer name = %q, want FS-WIN-02", id.NBComputer)
	}
	// A standalone machine has no DNS domain; emitting workgroup.local
	// would be its own tell.
	if id.DNSDomain != "" {
		t.Errorf("workgroup host has DNS domain %q, want empty", id.DNSDomain)
	}
	if id.DNSHostname != "fs-win-02" {
		t.Errorf("DNS hostname = %q, want fs-win-02", id.DNSHostname)
	}
}

func TestDomainJoinedDerivesDNSNames(t *testing.T) {
	id := Resolve(map[string]interface{}{
		"agent_hostname": "fs-win-02",
		"domain":         "CONTOSO",
		"hostname":       "FS-04",
	}, "smb")
	if id.NBDomain != "CONTOSO" || id.NBComputer != "FS-04" {
		t.Fatalf("overrides ignored: domain=%q computer=%q", id.NBDomain, id.NBComputer)
	}
	if id.DNSDomain != "contoso.local" {
		t.Errorf("DNS domain = %q, want contoso.local", id.DNSDomain)
	}
	if id.DNSHostname != "fs-04.contoso.local" {
		t.Errorf("DNS hostname = %q, want fs-04.contoso.local", id.DNSHostname)
	}
}

// A NetBIOS name may not contain a dot. os.Hostname() returns an FQDN on
// routine cloud images ("ip-10-0-1-23.ec2.internal"), and deriving the
// NetBIOS computer name from the full string advertised a dotted name
// truncated mid-label — a worse tell than the constant this work replaced.
func TestFQDNHostnameYieldsShortNetBIOSName(t *testing.T) {
	id := Resolve(map[string]interface{}{"hostname": "fs-01.corp.contoso.com"}, "smb")
	if strings.Contains(id.NBComputer, ".") {
		t.Errorf("NetBIOS name %q contains a dot", id.NBComputer)
	}
	if id.NBComputer != "FS-01" {
		t.Errorf("NetBIOS name = %q, want FS-01", id.NBComputer)
	}
}

// " CONTOSO " used to derive " contoso .local"; hostname was already
// trimmed on the DNS path, domain was not.
func TestDomainIsTrimmedBeforeDNSDerivation(t *testing.T) {
	id := Resolve(map[string]interface{}{"hostname": " fs-04 ", "domain": " CONTOSO "}, "smb")
	if id.NBDomain != "CONTOSO" {
		t.Errorf("NetBIOS domain = %q, want CONTOSO", id.NBDomain)
	}
	if id.DNSDomain != "contoso.local" {
		t.Errorf("DNS domain = %q, want contoso.local", id.DNSDomain)
	}
	if id.DNSHostname != "fs-04.contoso.local" {
		t.Errorf("DNS hostname = %q, want fs-04.contoso.local", id.DNSHostname)
	}
}

// NetBIOS names are at most 15 characters and uppercase.
func TestNetBIOSNamesAreTruncatedAndUppercased(t *testing.T) {
	id := Resolve(map[string]interface{}{"hostname": "a-very-long-hostname-indeed"}, "smb")
	if len(id.NBComputer) > 15 {
		t.Errorf("NetBIOS name %q is %d chars, max 15", id.NBComputer, len(id.NBComputer))
	}
	if id.NBComputer != "A-VERY-LONG-HOS" {
		t.Errorf("NetBIOS name = %q, want A-VERY-LONG-HOS", id.NBComputer)
	}
}

// An unknown persona must not kill the sensor; it falls back and is logged.
func TestUnknownPersonaFallsBackToDefault(t *testing.T) {
	id := Resolve(map[string]interface{}{"persona": "no-such-persona"}, "smb")
	if id.Persona.ID != "windows-server-2019" {
		t.Errorf("fallback persona = %q, want windows-server-2019", id.Persona.ID)
	}
}

// The GUID must be stable for a given agent and sensor, differ between
// sensors, and never be all-zero — it shipped as 16 zero bytes.
func TestServerGUIDIsStableUniqueAndNonZero(t *testing.T) {
	cfg := map[string]interface{}{"agent_id": "agt_1234567890abcdef"}
	a := Resolve(cfg, "smb")
	b := Resolve(cfg, "smb")
	c := Resolve(cfg, "rdp")
	if a.GUID == ([16]byte{}) {
		t.Fatal("GUID is all zero")
	}
	if a.GUID != b.GUID {
		t.Error("GUID is not stable across resolutions")
	}
	if a.GUID == c.GUID {
		t.Error("smb and rdp produced the same GUID")
	}
	d := Resolve(map[string]interface{}{"agent_id": "agt_différent"}, "smb")
	if a.GUID == d.GUID {
		t.Error("different agents produced the same GUID")
	}
}

// The SMB1 response builders copy fields out of the request without
// checking its length — req[9], req[10:12] and req[12:32] are read
// unconditionally — so a nil request panics. Tests pass a minimal buffer.
func smb1TestRequest() []byte { return make([]byte, 40) }

// Both negotiate responses shipped a 16-byte all-zero ServerGuid. No real
// server sends one, so it was a hard fingerprint on every deployment.
func TestNegotiateResponsesCarryANonZeroServerGUID(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_id": "agt_test", "agent_hostname": "h"}, "smb")
	if id.GUID == ([16]byte{}) {
		t.Fatal("resolved identity has a zero GUID")
	}

	smb2 := buildSMB2NegotiateResponse(id)
	// MS-SMB2 2.2.4: ServerGuid occupies body bytes 8..24, and the body
	// begins after the 64-byte header.
	if got := smb2[64+8 : 64+24]; bytes.Equal(got, make([]byte, 16)) {
		t.Error("SMB2 negotiate response still carries an all-zero ServerGuid")
	}
	if !bytes.Equal(smb2[64+8:64+24], id.GUID[:]) {
		t.Error("SMB2 ServerGuid does not match the resolved identity")
	}

	// SMB1's GUID lives in the data section; assert the identity's bytes
	// appear somewhere in the response rather than re-deriving offsets.
	smb1 := buildSMB1NegotiateResponse(smb1TestRequest(), id)
	if !bytes.Contains(smb1, id.GUID[:]) {
		t.Error("SMB1 negotiate response does not carry the identity's GUID")
	}
}

// The SMB2 negotiate response used to compute SystemTime by adding raw
// nanoseconds to the FILETIME epoch offset instead of 100ns ticks, which
// decodes to the year 7635. Every response this honeypot ever sent carried
// that fingerprint.
func TestNegotiateResponseSystemTimeIsPlausible(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_id": "agt_test", "agent_hostname": "h"}, "smb")
	smb2 := buildSMB2NegotiateResponse(id)
	// MS-SMB2 2.2.4: SystemTime occupies body bytes 40..48, and the body
	// begins after the 64-byte header.
	ticks := binary.LittleEndian.Uint64(smb2[64+40 : 64+48])
	const filetimeUnixOffsetTicks = 116444736000000000
	got := time.Unix(0, int64(ticks-filetimeUnixOffsetTicks)*100).UTC()
	if diff := time.Since(got); diff < -5*time.Minute || diff > 5*time.Minute {
		t.Errorf("SystemTime decoded to %s, want within a few minutes of now", got)
	}
}

// The session setup hardcoded Unix/Samba regardless of persona, which
// contradicted the Windows version block on the same connection.
func TestSessionSetupUsesThePersonaNativeStrings(t *testing.T) {
	id := Resolve(map[string]interface{}{"persona": "windows-server-2019", "agent_hostname": "h"}, "smb")
	reply := buildSMB1SessionSetupReply(smb1TestRequest(), 0, 1, []byte{0x01}, id)
	if !bytes.Contains(reply, utf16Encode(id.Persona.NativeOS)) {
		t.Errorf("reply does not advertise NativeOS %q", id.Persona.NativeOS)
	}
	if bytes.Contains(reply, utf16Encode("Samba")) {
		t.Error("a Windows persona still advertised Samba")
	}
}

// The certificate CommonName was a constant, so every RDP honeypot
// presented an identical certificate. It must now match what the NTLM
// layer claims the machine is called — a cert that disagrees with the
// computer name is its own tell.
func TestRDPCertificateCommonNameMatchesTheIdentity(t *testing.T) {
	id := Resolve(map[string]interface{}{
		"agent_hostname": "fs-win-02", "domain": "CONTOSO", "persona": "windows-server-2019",
	}, "rdp")
	cert := selfSignedCert(id)
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("selfSignedCert returned nothing")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject.CommonName != id.DNSHostname {
		t.Errorf("CommonName = %q, want %q", parsed.Subject.CommonName, id.DNSHostname)
	}
	if strings.Contains(strings.ToUpper(parsed.Subject.CommonName), "FORT") {
		t.Error("certificate still carries the old constant")
	}
}
