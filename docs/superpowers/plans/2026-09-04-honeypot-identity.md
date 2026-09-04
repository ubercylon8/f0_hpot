# Honeypot Server Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `FORTIKA` constants with a persona-driven server identity, so every layer of the SMB and RDP honeypots advertises values that are mutually consistent and vary per deployment.

**Architecture:** A `Persona` is a coherent bundle of everything a server advertises. A sensor's config supplies at most three inputs — `persona`, `domain`, `hostname` — and an `Identity` derives every wire value from them. The SMB, SMB1 and RDP handlers consume an `Identity` instead of string literals, which makes a Samba server reporting a Windows build unrepresentable rather than merely absent.

**Tech Stack:** Go 1.26.5 (agent), TypeScript/React (console), vitest, `go test`.

**Spec:** `docs/superpowers/specs/2026-09-03-honeypot-identity-design.md`

## Global Constraints

- **Go 1.26.5** (`agent/go.mod:3`). Node ≥22, pnpm 11.23.0 for the console task.
- **Apache-2.0 SPDX headers on new source files** (`.go`, `.ts`, `.mjs`). Markdown carries none.
- **The weak NTLM negotiation flags are deliberate and must survive.** `agent/internal/sensors/ntlm.go:25-27` withholds key exchange and strong crypto so clients fall back to crackable NTLMv1/v2 responses. That is the sensor's purpose. Only `NEGOTIATE_VERSION` (`0x02000000`) becomes persona-controlled; every other bit in `ntlmChallengeFlags` stays exactly as it is.
- **No real operational identifiers in any tracked file.** `./scripts/ci/check-identifiers.sh` must exit 0 before every commit.
- **`pnpm build` precedes `pnpm typecheck`/`pnpm test`** (turbo `dependsOn: ["^build"]`).
- Every commit message ends with exactly:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M
  ```
- Do not push. Do not create tags.

## File structure

| File | Responsibility |
|---|---|
| `agent/internal/sensors/persona.go` *(new)* | `Persona` table, `Identity` struct, `Resolve()`, `serverGUID()` |
| `agent/internal/sensors/persona_test.go` *(new)* | Realism-property tests for personas and resolution |
| `agent/internal/sensors/ntlm.go` | `encodeVersion`/`decodeVersion`; `BuildChallenge` and `buildTargetInfo` take an `Identity` |
| `agent/internal/sensors/ntlm_challenge_test.go` | Existing assertions kept, updated to the new signature |
| `agent/internal/sensors/smb.go` | Resolve identity in `Start`; thread to handlers; fill the SMB2 `ServerGuid` |
| `agent/internal/sensors/smb1.go` | `ServerGuid`, `NativeOS`/`NativeLanMan`, SystemTime, challenge target |
| `agent/internal/sensors/rdp.go`, `rdp_credssp.go` | Thread identity; certificate `CommonName` |
| `agent/main.go` | Inject `agent_id` and `agent_hostname` into every sensor config |
| `apps/web/src/pages/agents.tsx` | `persona`/`domain`/`hostname` fields on `smb` and `rdp` rows |
| `docs/AGENT-GUIDE.md`, `scripts/ci/check-identifiers.sh` | Document personas; delete the now-unneeded exemption |

## A spec gap this plan closes

Spec §3.1 lists `ServerGUID` under SMB1 only. **SMB2 has the same field and the same defect:** `buildSMB2NegotiateResponse` (`agent/internal/sensors/smb.go:213`) allocates `body := make([]byte, 64)` and never writes bytes 8–24, which is where MS-SMB2 places `ServerGuid`. It ships as 16 zero bytes exactly like the SMB1 one. Task 4 fills both.

## An observation to verify, not a task

While mapping `buildSMB2NegotiateResponse`, the field offsets did not obviously match MS-SMB2's NEGOTIATE Response layout: the code writes `SecurityBufferOffset` at `body[48:50]` and its length at `body[50:52]`, whereas MS-SMB2 §2.2.4 places `ServerStartTime` at offset 48 and `SecurityBufferOffset` at 56. This may be a real off-by-eight, or the reader may have mis-mapped it. **It is out of scope for this plan** — it is a protocol-correctness question, not an identity one, and the sensor demonstrably captures credentials today. Task 4's implementer should note what they observe while writing `ServerGuid` at `body[8:24]`, and report it rather than fixing it.

---

## Task 1: The persona table and identity resolution

Pure data and pure functions, testable with no network and no sensor. Everything later consumes this.

**Files:**
- Create: `agent/internal/sensors/persona.go`
- Create: `agent/internal/sensors/persona_test.go`

**Interfaces:**
- Produces:
  ```go
  type Persona struct {
      ID           string
      NativeOS     string   // SMB1 NativeOS z-string
      NativeLanMan string   // SMB1 NativeLanMan z-string
      HasVersion   bool     // false ⇒ omit the NTLM version block AND clear NEGOTIATE_VERSION
      VerMajor     uint8
      VerMinor     uint8
      VerBuild     uint16
      DNSSuffix    string   // e.g. "local"
  }

  type Identity struct {
      Persona      Persona
      NBDomain     string // uppercase, ≤15 chars
      NBComputer   string // uppercase, ≤15 chars
      DNSDomain    string // "" when the host is not domain-joined
      DNSHostname  string // lowercase; bare hostname when DNSDomain is ""
      GUID         [16]byte
  }

  func Personas() []Persona                                        // shipped list, stable order
  func LookupPersona(id string) (Persona, bool)
  func Resolve(cfg map[string]interface{}, kind string) Identity   // never fails; unknown persona ⇒ default + log
  ```

- [ ] **Step 1: Write the failing tests**

Create `agent/internal/sensors/persona_test.go`:

```go
package sensors

import "testing"

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd agent && go test ./internal/sensors/ -run 'Persona|Identity|Default|Domain|NetBIOS|ServerGUID' -v`
Expected: compilation failure — `undefined: Personas`, `undefined: Resolve`, `undefined: LookupPersona`.

- [ ] **Step 3: Write `persona.go`**

Create `agent/internal/sensors/persona.go` with the Apache-2.0 header used by the other files in this package, then:

```go
package sensors

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"strings"
)

// A Persona is everything a server says about itself, bundled so the parts
// cannot contradict each other. The values this replaces were five
// independent constants: a Samba server reporting an impossible Windows
// build, with its NetBIOS domain equal to its own computer name.
type Persona struct {
	ID           string
	NativeOS     string
	NativeLanMan string
	HasVersion   bool
	VerMajor     uint8
	VerMinor     uint8
	VerBuild     uint16
	DNSSuffix    string
}

const defaultPersonaID = "windows-server-2019"

// Build numbers are real releases. NativeOS/NativeLanMan follow the shape
// Windows actually sends ("<product> <build>" / "<product> 6.3").
var personas = []Persona{
	{
		ID: "windows-server-2019",
		NativeOS: "Windows Server 2019 Standard 17763", NativeLanMan: "Windows Server 2019 Standard 6.3",
		HasVersion: true, VerMajor: 10, VerMinor: 0, VerBuild: 17763, DNSSuffix: "local",
	},
	{
		ID: "windows-server-2022",
		NativeOS: "Windows Server 2022 Standard 20348", NativeLanMan: "Windows Server 2022 Standard 6.3",
		HasVersion: true, VerMajor: 10, VerMinor: 0, VerBuild: 20348, DNSSuffix: "local",
	},
	{
		ID: "windows-11",
		NativeOS: "Windows 11 Pro 22631", NativeLanMan: "Windows 11 Pro 6.3",
		HasVersion: true, VerMajor: 10, VerMinor: 0, VerBuild: 22631, DNSSuffix: "local",
	},
	{
		// Real Samba sets no NTLMSSP_NEGOTIATE_VERSION and sends no
		// version structure. HasVersion false controls both.
		ID: "samba-ubuntu-2204",
		NativeOS: "Unix", NativeLanMan: "Samba 4.15.13-Ubuntu",
		HasVersion: false, DNSSuffix: "lan",
	},
}

func Personas() []Persona { return personas }

func LookupPersona(id string) (Persona, bool) {
	for _, p := range personas {
		if p.ID == id {
			return p, true
		}
	}
	return Persona{}, false
}

// Identity is the resolved, per-sensor view every wire layer reads from.
type Identity struct {
	Persona     Persona
	NBDomain    string
	NBComputer  string
	DNSDomain   string
	DNSHostname string
	GUID        [16]byte
}

func netbios(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) > 15 {
		s = s[:15]
	}
	return s
}

// Resolve never fails: a sensor that cannot name itself is worse than one
// that names itself plausibly. agent_id and agent_hostname are injected by
// the agent, not supplied by the operator.
func Resolve(cfg map[string]interface{}, kind string) Identity {
	p, _ := LookupPersona(defaultPersonaID)
	if want := str(cfg, "persona", ""); want != "" {
		if got, ok := LookupPersona(want); ok {
			p = got
		} else {
			log.Printf("[%s] unknown persona %q; falling back to %s", kind, want, defaultPersonaID)
		}
	}

	host := str(cfg, "hostname", "")
	if host == "" {
		host = str(cfg, "agent_hostname", "honeypot")
	}
	domain := str(cfg, "domain", "WORKGROUP")

	id := Identity{
		Persona:    p,
		NBDomain:   netbios(domain),
		NBComputer: netbios(host),
	}
	short := strings.ToLower(strings.SplitN(strings.TrimSpace(host), ".", 2)[0])
	if id.NBDomain != "WORKGROUP" {
		id.DNSDomain = strings.ToLower(domain) + "." + p.DNSSuffix
		id.DNSHostname = short + "." + id.DNSDomain
	} else {
		// A standalone machine has no DNS domain. Emitting
		// "workgroup.local" would be a tell of its own.
		id.DNSHostname = short
	}

	mac := hmac.New(sha256.New, []byte(str(cfg, "agent_id", "unenrolled")))
	mac.Write([]byte(kind))
	copy(id.GUID[:], mac.Sum(nil))
	return id
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd agent && go test ./internal/sensors/ -run 'Persona|Identity|Default|Domain|NetBIOS|ServerGUID' -v`
Expected: PASS, all seven tests.

- [ ] **Step 5: Vet and format**

```bash
cd agent && go vet ./... && gofmt -l .
```
Expected: no output from either.

- [ ] **Step 6: Commit**

```bash
git add agent/internal/sensors/persona.go agent/internal/sensors/persona_test.go
git commit -m "feat(agent): add server personas and identity resolution

A Persona bundles everything a server advertises so the parts cannot
contradict each other. The values this replaces were five independent
constants that did: a Samba server reporting a Windows build that has
never existed, with its NetBIOS domain equal to its own computer name.

Resolve() never fails — an unknown persona logs and falls back, because a
sensor that cannot name itself is worse than one that names itself
plausibly. Tests assert realism properties rather than well-formedness,
which is why the previous defects survived: the old assertions hold for
any target name and any build number.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Task 2: Version encoding and an identity-driven NTLM challenge

**Files:**
- Modify: `agent/internal/sensors/ntlm.go:28-31` (flags), `:163-171` (`buildTargetInfo`), `:174-206` (`BuildChallenge`)
- Modify: `agent/internal/sensors/ntlm_challenge_test.go`

**Interfaces:**
- Consumes: `Identity`, `Resolve` from Task 1.
- Produces:
  ```go
  func encodeVersion(major, minor uint8, build uint16) []byte  // 8 bytes, MS-NLMP 2.2.2.10
  func decodeVersion(b []byte) (major, minor uint8, build uint16, ok bool)
  func BuildChallenge(id Identity) (msg []byte, challenge [8]byte, err error)
  func buildTargetInfo(id Identity) []byte
  ```

- [ ] **Step 1: Write the failing tests**

Append to `agent/internal/sensors/ntlm_challenge_test.go`:

```go
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

// The weak-crypto flags are deliberate: they make clients fall back to
// crackable NTLMv1/v2 responses, which is the sensor's purpose.
func TestChallengePreservesTheDeliberatelyWeakFlags(t *testing.T) {
	id := Resolve(map[string]interface{}{"agent_hostname": "h"}, "smb")
	msg, _, err := BuildChallenge(id)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(msg[20]) | uint32(msg[21])<<8 | uint32(msg[22])<<16 | uint32(msg[23])<<24
	const wantBase = 0x00008201 // NEGOTIATE_NTLM | REQUEST_TARGET | NEGOTIATE_UNICODE
	if flags&wantBase != wantBase {
		t.Errorf("base flags = 0x%08X, want 0x%08X set", flags, wantBase)
	}
	if flags&0x40000000 != 0 || flags&0x00000040 != 0 {
		t.Error("challenge advertised sign/seal; clients would stop sending crackable responses")
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
```

Update the three existing `BuildChallenge("FORTIKA")` call sites in this file to:

```go
	id := Resolve(map[string]interface{}{"agent_hostname": "testhost"}, "smb")
	msg, chal, err := BuildChallenge(id)
```

- [ ] **Step 2: Run to verify failure**

Run: `cd agent && go test ./internal/sensors/ -run 'Version|Challenge|TargetInfo' -v`
Expected: compilation failure — `undefined: encodeVersion`, and `BuildChallenge` still wants a string.

- [ ] **Step 3: Implement**

In `ntlm.go`, replace the package-level flag constant's use with a per-identity computation. Keep the constant and its comment as the base:

```go
// ntlmChallengeFlags we advertise on the challenge. Deliberately NOT
// advertising key exchange or strong crypto so clients fall back to
// crackable NTLMv1/v2 responses over our challenge.
const ntlmChallengeFlags = 0x00008201 // NEGOTIATE_NTLM | REQUEST_TARGET | NEGOTIATE_UNICODE

const ntlmNegotiateVersion = 0x02000000

// encodeVersion renders MS-NLMP 2.2.2.10 VERSION. The build is a
// little-endian uint16; writing those two bytes by hand is how this file
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
```

Then in `BuildChallenge`, take `id Identity`, use `id.NBDomain` as the TargetName, compute `flags := uint32(ntlmChallengeFlags)` plus `ntlmNegotiateVersion` only when `id.Persona.HasVersion`, and append `encodeVersion(...)` only in that case. **The payload offsets must account for the version block's presence:** the fixed part is 56 bytes with a version block and 48 without, so compute the TargetName offset from whether one is emitted rather than hardcoding 56.

- [ ] **Step 4: Run to verify passing**

Run: `cd agent && go test ./internal/sensors/ -v`
Expected: PASS, including the pre-existing challenge and hashcat tests.

- [ ] **Step 5: Commit**

```bash
git add agent/internal/sensors/ntlm.go agent/internal/sensors/ntlm_challenge_test.go
git commit -m "feat(agent): derive the NTLM challenge from a persona

The version block was eight hand-written bytes decoding to Windows build
46855, which does not exist; the comment above them claimed 18362.
encodeVersion/decodeVersion round-trip in a test, so that cannot recur.

The Samba persona now clears NEGOTIATE_VERSION and emits no version
structure, because real Samba sends neither — a Samba server reporting a
Windows build was the contradiction this work exists to remove. The
deliberately weak sign/seal flags are unchanged and now asserted by a
test, so a later tidy-up cannot silently strengthen them and stop
clients sending crackable responses.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Task 3: Give sensors the agent's id and hostname

`Resolve` reads `agent_id` and `agent_hostname` from the config map, but nothing puts them there yet. The agent injects them alongside the operator's keys, which keeps `Sensor.Start`'s signature unchanged and avoids a second channel or a package global.

**Files:**
- Modify: `agent/main.go:222-229` (`toSensors`) and its call site at `agent/main.go:156`

**Interfaces:**
- Consumes: `Resolve` from Task 1, which reads `cfg["agent_id"]` and `cfg["agent_hostname"]`.
- Produces: every sensor config map carries those two keys.

- [ ] **Step 1: Read the current function and its caller**

```bash
sed -n '215,232p' agent/main.go
sed -n '150,160p' agent/main.go
```

Note that `specsEqual` (`agent/main.go:235`) compares `[]api.SensorSpec` — the *server-supplied* specs, before this conversion. Injection therefore happens downstream of the change-detection and cannot cause spurious sensor restarts. Confirm that ordering before editing; if injection were upstream, the two constant keys would still compare equal, but the reasoning should be checked rather than assumed.

- [ ] **Step 2: Change `toSensors` to inject both values**

```go
// toSensors converts server-delivered specs into runnable ones, injecting
// the agent's own identity. These two keys are agent-supplied: they
// overwrite any operator value of the same name, because a sensor must not
// be able to claim another agent's id.
func toSensors(in []api.SensorSpec, agentID, hostname string) []sensors.SensorSpec {
	out := make([]sensors.SensorSpec, 0, len(in))
	for _, s := range in {
		cfg := make(map[string]interface{}, len(s.Config)+2)
		for k, v := range s.Config {
			cfg[k] = v
		}
		cfg["agent_id"] = agentID
		cfg["agent_hostname"] = hostname
		out = append(out, sensors.SensorSpec{Kind: s.Kind, Enabled: s.Enabled, Config: cfg})
	}
	return out
}
```

Copying the map rather than mutating `s.Config` matters: the spec slice is retained for the next `specsEqual` comparison, and mutating it would compare an injected map against a fresh server one and restart every sensor on every heartbeat.

- [ ] **Step 3: Update the call site**

At `agent/main.go:156`, pass the values the agent already holds:

```go
	sensors.StartAll(toSensors(specs, state.AgentID, hostname), report)
```

Read the surrounding function to find the in-scope hostname variable — `agent/main.go:52` obtains one via `os.Hostname()`. If it is not in scope at line 156, call `os.Hostname()` there and ignore the error the same way line 52 does; an empty hostname falls back to `"honeypot"` inside `Resolve`.

- [ ] **Step 4: Verify it builds and the suite still passes**

```bash
cd agent && go build ./... && go test ./... && go vet ./... && gofmt -l .
```
Expected: all clean, no output from `gofmt -l .`.

- [ ] **Step 5: Commit**

```bash
git add agent/main.go
git commit -m "feat(agent): inject agent id and hostname into sensor configs

Identity resolution needs both to derive a stable per-deployment server
GUID and a plausible computer name. Injecting them into the config map
keeps Sensor.Start's signature unchanged and avoids a package global.

The map is copied rather than mutated: the server-supplied specs are
retained for the next specsEqual comparison, and mutating them in place
would compare an injected map against a fresh server one and restart
every sensor on every heartbeat.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Task 4: Thread the identity through SMB and SMB1

The largest task. Both the SMB2 and SMB1 negotiate responses ship a 16-byte all-zero `ServerGuid`; the SMB1 session-setup hardcodes `Unix`/`Samba`; and the SMB1 challenge names `FORTIKA`.

**Files:**
- Modify: `agent/internal/sensors/smb.go` — `Start:21`, `handleSMBConn:27`, `smbSessionLoop:93`, `buildSMB2NegotiateResponse:213`
- Modify: `agent/internal/sensors/smb1.go` — `buildSMB1NegotiateResponse:36`, `buildSMB1SessionSetupReply:110`, `buildSMB1LegacyNegotiateResponse:141`, `handleSMB1LegacySetup:194`, `handleSMB1:255`, and the `BuildChallenge` call at `:298`

**Interfaces:**
- Consumes: `Identity`, `Resolve` (Task 1); `BuildChallenge(Identity)` (Task 2).
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

Append to `agent/internal/sensors/persona_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cd agent && go test ./internal/sensors/ -run 'ServerGUID|SessionSetup' -v`
Expected: compilation failure — those builders do not yet take an `Identity`.

- [ ] **Step 3: Thread the identity through `smb.go`**

`Start` resolves once and closes over the result, so `serveTCPSensor`'s shared handler type is unchanged:

```go
func (SMBSensor) Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 445)
	tokenID := str(cfg, "token_id", "")
	id := Resolve(cfg, "smb")
	log.Printf("[smb] identity: persona=%s domain=%s computer=%s", id.Persona.ID, id.NBDomain, id.NBComputer)
	handle := func(conn net.Conn, tokenID string, report Reporter) {
		handleSMBConn(conn, tokenID, id, report)
	}
	return serveTCPSensor(ctx, "smb", port, tokenID, handle, report)
}
```

Add an `id Identity` parameter to `handleSMBConn`, `smbSessionLoop` and `buildSMB2NegotiateResponse`, and pass it to `handleSMB1` at `smb.go:70`. In `buildSMB2NegotiateResponse`, write the GUID:

```go
	copy(body[8:24], id.GUID[:]) // ServerGuid — shipped as 16 zero bytes
```

**While you are in that function, note but do not change** the field offsets: the code writes `SecurityBufferOffset` at `body[48:50]`, whereas MS-SMB2 2.2.4 places `ServerStartTime` at 48 and `SecurityBufferOffset` at 56. Record what you observe in your report. It is a protocol-correctness question, out of scope here, and the sensor captures credentials today.

- [ ] **Step 4: Thread the identity through `smb1.go`**

Add `id Identity` to `buildSMB1NegotiateResponse`, `buildSMB1SessionSetupReply`, `buildSMB1LegacyNegotiateResponse`, `handleSMB1LegacySetup` and `handleSMB1`. Then:

- `buildSMB1NegotiateResponse` — replace `data := append(make([]byte, 16), blob...)` with a copy of `id.GUID[:]`, and replace the fixed FILETIME literal at `:66` with a value derived from the current time.
- `buildSMB1SessionSetupReply` — replace the hardcoded strings:
  ```go
  native := utf16Encode(id.Persona.NativeOS)
  native = append(native, 0, 0)
  native = append(native, utf16Encode(id.Persona.NativeLanMan)...)
  native = append(native, 0, 0)
  ```
- The `BuildChallenge("FORTIKA")` call at `:298` becomes `BuildChallenge(id)`.

- [ ] **Step 5: Run the full agent suite**

```bash
cd agent && go test ./... -v 2>&1 | tail -30
go vet ./... && gofmt -l .
```
Expected: PASS throughout, no vet or format output. The pre-existing SMB1 and NTLM tests must still pass — if `smb1_test.go` asserts on the old `Samba` string, update the assertion to read from the persona rather than deleting the test.

- [ ] **Step 6: Commit**

```bash
git add agent/internal/sensors/smb.go agent/internal/sensors/smb1.go agent/internal/sensors/persona_test.go
git commit -m "feat(agent): derive SMB and SMB1 server identity from the persona

Both negotiate responses shipped a 16-byte all-zero ServerGuid — the SMB2
one because bytes 8..24 of the body were never written. No real server
sends that, so it fingerprinted every deployment. The SMB1 session setup
hardcoded Unix/Samba regardless of persona, contradicting the Windows
version block on the same connection, and the SMB1 challenge named a
constant.

Start resolves the identity once and closes over it, so serveTCPSensor's
shared handler type is unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Task 5: Thread the identity through RDP

**Files:**
- Modify: `agent/internal/sensors/rdp.go` — `Start:21`, `handleRDPConn:27`, the `handleRDPCredSSP` call at `:123`
- Modify: `agent/internal/sensors/rdp_credssp.go` — `handleRDPCredSSP:25`, `selfSignedCert:87`, `upgradeRDPToTLS:113`, the `BuildChallenge` call at `:45`

**Interfaces:**
- Consumes: `Identity`, `Resolve` (Task 1); `BuildChallenge(Identity)` (Task 2).

- [ ] **Step 1: Write the failing test**

Append to `agent/internal/sensors/persona_test.go`:

```go
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
```

Add `"crypto/x509"` and `"strings"` to that file's imports if absent.

- [ ] **Step 2: Run to verify failure**

Run: `cd agent && go test ./internal/sensors/ -run 'RDPCertificate' -v`
Expected: compilation failure — `selfSignedCert` takes no arguments.

- [ ] **Step 3: Implement**

`Start` mirrors Task 4's closure pattern:

```go
func (RDPSensor) Start(ctx context.Context, cfg map[string]interface{}, report Reporter) error {
	port := intVal(cfg, "port", 3389)
	tokenID := str(cfg, "token_id", "")
	id := Resolve(cfg, "rdp")
	log.Printf("[rdp] identity: persona=%s computer=%s cn=%s", id.Persona.ID, id.NBComputer, id.DNSHostname)
	handle := func(conn net.Conn, tokenID string, report Reporter) {
		handleRDPConn(conn, tokenID, id, report)
	}
	return serveTCPSensor(ctx, "rdp", port, tokenID, handle, report)
}
```

Add `id Identity` to `handleRDPConn`, `handleRDPCredSSP` and `upgradeRDPToTLS`. In `selfSignedCert(id Identity)`, set `Subject: pkix.Name{CommonName: id.DNSHostname}` and add `DNSNames: []string{id.DNSHostname}` so the SAN agrees with the subject — a certificate with a CN and no matching SAN is itself unusual on modern hosts. Replace `BuildChallenge("FORTIKA-RDP")` with `BuildChallenge(id)`.

If `selfSignedCert` currently caches its result in a package variable, the cache must key on the identity or be removed; a shared cache would hand every sensor the first identity's certificate.

- [ ] **Step 4: Run to verify passing**

```bash
cd agent && go test ./... && go vet ./... && gofmt -l .
```
Expected: PASS, clean vet, no format output.

- [ ] **Step 5: Verify no constant survives in the agent**

```bash
git grep -In 'FORTIKA' -- agent/ || echo "no FORTIKA literal remains under agent/"
```
Expected: the "no FORTIKA literal remains" line. If any hit remains, it belongs to this task.

- [ ] **Step 6: Commit**

```bash
git add agent/internal/sensors/rdp.go agent/internal/sensors/rdp_credssp.go agent/internal/sensors/persona_test.go
git commit -m "feat(agent): derive the RDP certificate and challenge from the persona

Every RDP honeypot presented a certificate with the same CommonName, and
named the same constant in its CredSSP challenge. The certificate now
matches what the NTLM layer says the machine is called, with a SAN that
agrees with the subject — a cert disagreeing with the computer name is
its own tell.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Task 6: Expose persona, domain and hostname in the console

**Files:**
- Modify: `apps/web/src/pages/agents.tsx` — `SENSOR_KINDS` (~line 903), `SensorRowState` (~line 918), `SensorEditor`'s row state initialiser, `save()`, and the per-row advanced disclosure

**Interfaces:**
- Consumes: the config keys `Resolve` reads — `persona`, `domain`, `hostname` (Task 1).
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Read the current editor**

```bash
sed -n '900,935p' apps/web/src/pages/agents.tsx
sed -n '955,1050p' apps/web/src/pages/agents.tsx
```

Note the existing shape: `token_id` is deliberately absent from `SENSOR_KINDS`' `fields` arrays and lives behind a per-row `advanced` disclosure, because the API provisions it when omitted. The three identity fields follow that pattern — the common case stays a port.

- [ ] **Step 2: Add the persona list and extend the row state**

Near `SENSOR_KINDS`, add the list the agent ships. A comment must record that the agent is the authority, so a reader knows a stale option is harmless:

```tsx
// Server personas the agent ships (agent/internal/sensors/persona.go is the
// authority). An id the agent does not know falls back to its default and is
// logged, so a stale entry here costs a missing menu option, never a dead
// sensor. Deliberately not shared via packages/shared: a list that degrades
// when it drifts beats one that lies.
const SENSOR_PERSONAS = [
  "windows-server-2019",
  "windows-server-2022",
  "windows-11",
  "samba-ubuntu-2204",
] as const;

/** Sensor kinds whose advertised server identity is configurable. */
const IDENTITY_KINDS = new Set(["smb", "rdp"]);
```

Extend `SensorRowState` with three fields:

```tsx
interface SensorRowState {
  kind: string;
  enabled: boolean;
  port: string;
  path: string;
  label: string;
  token_id: string;
  persona: string;
  domain: string;
  hostname: string;
  /** UI-only: whether this row's advanced disclosure is expanded. */
  advanced: boolean;
}
```

- [ ] **Step 3: Initialise, send and default the new fields**

In the `useState` initialiser that maps `initial`, add:

```tsx
      persona: String(s.config["persona"] ?? ""),
      domain: String(s.config["domain"] ?? ""),
      hostname: String(s.config["hostname"] ?? ""),
```

In `save()`, alongside the existing `token_id: r.token_id || undefined`:

```tsx
            persona: r.persona || undefined,
            domain: r.domain || undefined,
            hostname: r.hostname || undefined,
```

Empty strings become `undefined` and are omitted, which is what yields the agent's defaults. Add the same three keys with `""` to the `+ add sensor` button's new-row object so the shape stays uniform.

- [ ] **Step 4: Render the fields inside the advanced disclosure**

Within the existing `{r.advanced && (...)}` block, after the token input, add a section shown only for identity-bearing kinds:

```tsx
          {IDENTITY_KINDS.has(r.kind) && (
            <div className="flex flex-wrap items-center gap-2 pl-2 text-xs text-faint">
              <span>advertises as</span>
              <select
                value={r.persona}
                onChange={(e) => update(i, { persona: e.target.value })}
                className={`${selectClass} h-7 w-48 text-xs`}
              >
                <option value="">windows-server-2019 (default)</option>
                {SENSOR_PERSONAS.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
              <Input
                placeholder="WORKGROUP"
                value={r.domain}
                onChange={(e) => update(i, { domain: e.target.value })}
                className="h-7 w-32 font-mono text-xs"
              />
              <Input
                placeholder="(agent hostname)"
                value={r.hostname}
                onChange={(e) => update(i, { hostname: e.target.value })}
                className="h-7 w-40 font-mono text-xs"
              />
              <span>set the domain to blend into a real AD estate</span>
            </div>
          )}
```

- [ ] **Step 5: Typecheck and test**

```bash
pnpm build && pnpm typecheck && pnpm test
```
Expected: all pass. `pnpm build` must run first — turbo declares `dependsOn: ["^build"]` for both other tasks.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/pages/agents.tsx
git commit -m "feat(console): configure SMB and RDP server identity per sensor

Persona, domain and hostname join token_id behind the per-row advanced
disclosure, so the common case stays a port. Empty fields are omitted
from the saved config, which yields the agent's defaults.

The persona list is duplicated here rather than shared: the agent is the
authority and an unknown id falls back with a log line, so a stale entry
costs a missing menu option rather than a dead sensor.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Task 7: Document personas and retire the identifier-gate exemption

**Files:**
- Modify: `docs/AGENT-GUIDE.md` — the SMB and RDP sensor sections
- Modify: `scripts/ci/check-identifiers.sh` — remove the `FORT[I]KA` exemption

**Interfaces:**
- Consumes: the persona table (Task 1) and the fact that Task 5 removed the last literal from `agent/`.

- [ ] **Step 1: Confirm the exemption is genuinely unnecessary**

```bash
git grep -In 'FORTIKA' -- agent/ || echo "clean"
F0_IDENTIFIER_DENYLIST='FORTIKA fortika' ./scripts/ci/check-identifiers.sh; echo "exit=$?"
```

Expected: `clean`, then exit 0. **If the gate exits 0 only because the exemption is still there, that proves nothing** — comment the exemption out, re-run, and confirm it still exits 0 before deleting it.

- [ ] **Step 2: Delete the exemption**

Remove the `FORT[I]KA` skip added to the denylist branch, along with its explanatory comment about being a deferral pending a rename. Leave the `198[.]18[.]7[.]7` fixture exemption and the case-insensitivity (`-i`) alone — both are still needed.

- [ ] **Step 3: Prove the gate still fires**

```bash
printf 'a fortika reference\n' > docs/gate-control.md && git add docs/gate-control.md
F0_IDENTIFIER_DENYLIST='FORTIKA' ./scripts/ci/check-identifiers.sh; echo "exit=$?"
git rm -f docs/gate-control.md
./scripts/ci/check-identifiers.sh; echo "exit=$?"
git status --short
```

Expected: exit 1 naming `docs/gate-control.md` (proving case-insensitive matching still works with the exemption gone), then exit 0, then a clean tree.

- [ ] **Step 4: Document personas in the agent guide**

In `docs/AGENT-GUIDE.md`'s sensor section, add a short subsection covering: what a persona is; the three config keys and their defaults (`persona` → `windows-server-2019`, `domain` → `WORKGROUP`, `hostname` → the agent's own hostname); the four shipped ids; that an unknown persona falls back and logs rather than failing the sensor; and that setting `domain` to a real AD domain name is what makes these honeypots convincing inside an enterprise.

State the limitation the spec records in §7.1 rather than omitting it: Windows has shipped with SMB1 disabled by default since 2017, so a host answering SMB1 while claiming a modern Windows persona is mildly implausible. The SMB1 path exists because it captures NTLMv1 from legacy clients. Do not editorialise; one short paragraph.

**Do not claim more than the code does.** Eight documents in the previous release asserted something stronger than the source supported. Every statement here must be checkable in `agent/internal/sensors/persona.go`.

- [ ] **Step 5: Full verification**

```bash
./scripts/ci/check-identifiers.sh; echo "exit=$?"
cd agent && go test ./... && go vet ./... && gofmt -l . && cd ..
pnpm build && pnpm typecheck && pnpm test
semgrep scan --config .semgrep.yml
```
Expected: everything passes, semgrep reports 0 findings.

- [ ] **Step 6: Commit**

```bash
git add docs/AGENT-GUIDE.md scripts/ci/check-identifiers.sh
git commit -m "docs: document server personas; retire the gate exemption

The identifier gate carried a path-and-value exemption for the hardcoded
constants, commented as a deferral pending a rename rather than a
judgement that the strings were harmless. The rename has happened, so the
exemption goes and the gate covers the agent tree unconditionally again.

The agent guide gains the three config keys with their defaults, the four
shipped personas, and the SMB1 limitation the design records: Windows has
shipped with SMB1 off by default since 2017, so answering it while
claiming a modern Windows persona is mildly implausible. The path exists
because it captures NTLMv1 from legacy clients.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Lu7VJWLy1AETmnLjdaGi6M"
```

---

## Self-review

**Spec coverage** — every requirement maps to a task:

| Spec section | Task |
|---|---|
| §3.1 resolution and derived fields | 1 |
| §3.2 persona table; Samba omits the version block | 1, 2 |
| §3.3 reaching the agent id | 3 |
| §4 `ntlm.go` changes; weak flags preserved | 2 |
| §4 `smb.go`/`smb1.go` threading | 4 |
| §4 `rdp_credssp.go` threading | 5 |
| §5 tests 1–2 (round-trip, persona consistency) | 2 |
| §5 tests 3–5 (defaults, GUID, precedence) | 1 |
| §5 test 6 (no literal; exemption removed) | 5, 7 |
| §6 console | 6 |
| §7 migration — additive, no DB change | inherent; verified in 3 |
| §7.1 SMB1 limitation documented | 7 |
| §9 success criteria 1–6 | 5 (1), 1 (2, 4), 2 (3, 5), 7 (6) |

**Beyond the spec, deliberately:** the SMB2 `ServerGuid` (spec §3.1 names SMB1 only; the same defect exists in `buildSMB2NegotiateResponse` and Task 4 fills both), and the RDP certificate SAN (a CN with no matching SAN is unusual on modern hosts).

**Placeholder scan:** no TBD/TODO; every code step carries real code; no step says "similar to Task N".

**Type consistency:** `Identity`, `Persona`, `Resolve(cfg, kind)`, `BuildChallenge(id)`, `buildTargetInfo(id)`, `encodeVersion`/`decodeVersion`, `selfSignedCert(id)`, `buildSMB2NegotiateResponse(id)`, `buildSMB1NegotiateResponse(req, id)`, `buildSMB1SessionSetupReply(req, status, uid, blob, id)` — each is defined once and used with the same signature everywhere it appears.

**Ordering:** Task 1 before all others. Task 2 before 4 and 5 (both call `BuildChallenge(Identity)`). Task 3 before any runtime verification of GUID uniqueness, though not before compilation. Task 5 before Task 7 (the exemption cannot go until the last literal does).
