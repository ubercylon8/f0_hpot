# Design — configurable honeypot server identity

**Date:** 2026-09-03
**Status:** approved, pending implementation plan
**Scope:** `agent/internal/sensors/` (SMB, SMB1, RDP), the console sensor editor, and the
agent guide. No changes to the token pipeline, the gateway, or the alerting path.

---

## 1. Problem

The SMB and RDP honeypots advertise a server identity assembled from five independent
hardcoded values that contradict one another. On a single connection, the honeypot claims to
be a Samba server on Unix that reports a Windows build number which has never existed, whose
NetBIOS domain and computer name are the same word, with an all-zero server GUID and a frozen
system clock.

| Layer | Current value | Defect |
|---|---|---|
| NTLM `TargetInfo` (`ntlm.go:163-169`) | `nbDomain`, `nbComputer`, `dnsHostname` all `FORTIKA`; `dnsDomain` `FORTIKA.local` | A domain and a computer name are never the same string on a real host |
| NTLM version block (`ntlm.go:200`) | `{10,0,7,183,0,0,0,15}` → build **46855** | **Bug.** No such Windows build exists. The comment says 18362, whose little-endian bytes are `{186,71}` |
| SMB1 `NativeOS`/`NativeLanMan` (`smb1.go:126-129`) | `Unix` / `Samba` | Contradicts the Windows version block on the same connection |
| SMB1 `ServerGUID` (`smb1.go:73`) | `make([]byte, 16)` — 16 zero bytes | **Bug.** No real server sends an all-zero GUID |
| SMB1 SystemTime (`smb1.go:66`) | fixed FILETIME literal | Every deployment reports an identical system time |
| RDP certificate (`rdp_credssp.go:97`) | `CommonName: "FORTIKA-RDP"` | Constant across every deployment |

Two consequences, in order of severity:

1. **The deception fails on its own terms.** An intruder inside a real Active Directory
   domain who reaches this share sees a server claiming membership of a domain that is not
   theirs, named after itself. They do not need to have seen the source to discount it.
2. **Publishing the source makes it greppable.** `FORTIKA` is a stable cross-deployment
   fingerprint that also names the maintainer's company. Anyone can read the repository and
   then identify any deployment with a single connection.

**Why no test caught this.** `ntlm_challenge_test.go` asserts the challenge is non-zero and
the message parses. Both hold for any target name and any build number, including impossible
ones. The existing tests verify protocol *well-formedness*; every defect above is a
*realism* property, and nothing tests realism.

## 2. Decisions taken

| Decision | Choice | Rationale |
|---|---|---|
| Configuration shape | **Persona presets with per-sensor overrides** | The defect class is inconsistency between layers. Independent fields would let an operator reassemble the exact contradiction being removed. |
| Default when unconfigured | **Fixed persona, varying hostname** | The identity varies per deployment through the hostname and GUID. A shared OS string reads as "this estate standardised on Server 2019", which is unremarkable. |
| Persona list location | **`agent/internal/sensors/persona.go`, Go is the authority** | Not `packages/shared`: this repository has a dead, drifted schema there, and a list that degrades safely when it drifts beats one that lies. |
| Unknown persona | **Log, fall back to default, report in heartbeat** | The console's dropdown is a convenience. If it lags the agent, the cost is a missing menu option, not a dead sensor. |

## 3. The identity model

### 3.1 Resolution

Three inputs per sensor, everything else derived:

```
persona   ← cfg["persona"],  default "windows-server-2019"
domain    ← cfg["domain"],   default "WORKGROUP"
hostname  ← cfg["hostname"], default the agent's own hostname
```

`hostname` is uppercased and truncated to 15 characters for NetBIOS fields, and used
lowercased for DNS fields. Derived, never configurable:

| Field | Derivation |
|---|---|
| NTLM `avNbDomain` | `domain` |
| NTLM `avNbComputer` | `hostname` (NetBIOS form) |
| NTLM `avDnsDomain` | `domain` lowercased + the persona's DNS suffix (`CONTOSO` → `contoso.local`). When `domain` is the default `WORKGROUP`, the pair is **omitted entirely** — a standalone machine has no DNS domain, and emitting `workgroup.local` would be its own tell |
| NTLM `avDnsHostname` | `hostname.dnsDomain` lowercased when a DNS domain exists, otherwise the bare lowercased `hostname` |
| NTLM version block | the persona's real build triple |
| SMB1 `NativeOS` / `NativeLanMan` | the persona's strings |
| SMB1 `ServerGUID` | HMAC-SHA256(agent id ‖ sensor kind), first 16 bytes |
| SMB1 SystemTime | current time minus the process uptime |
| RDP certificate `CommonName` | `hostname.dnsDomain` |

### 3.2 Shipped personas

Four. Enough to cover file server, workstation and Linux share without becoming a catalogue
nobody maintains. Build numbers are real releases and must be verified against Microsoft's published build list
during implementation, not copied from this table on trust. The `NativeOS` and `NativeLanMan`
strings should likewise be checked against a real capture or a documented example rather than
invented — a plausible-looking string that no Windows release actually sends is the same class
of defect as build 46855.

| Id | `NativeOS` | `NativeLanMan` | Version block | DNS suffix |
|---|---|---|---|---|
| `windows-server-2019` *(default)* | `Windows Server 2019 Standard` | `Windows Server 2019 Standard 6.3` | 10.0.17763 | `.local` |
| `windows-server-2022` | `Windows Server 2022 Standard` | `Windows Server 2022 Standard 6.3` | 10.0.20348 | `.local` |
| `windows-11` | `Windows 11 Pro` | `Windows 11 Pro 6.3` | 10.0.22631 | `.local` |
| `samba-ubuntu-2204` | `Unix` | `Samba 4.15.13-Ubuntu` | **none — see below** | `.lan` |

**The Samba persona must not advertise a Windows version block.** Real Samba does not set
`NTLMSSP_NEGOTIATE_VERSION` and sends no version structure. Today `ntlmChallengeFlags`
(`ntlm.go:28-29`) sets `0x02000000` unconditionally and `BuildChallenge` appends the block
unconditionally. The persona therefore controls both: Windows personas set the flag and emit
the block; the Samba persona clears the flag and omits it. A Samba server that reports a
Windows build is exactly the contradiction this design exists to remove, so it must be
structurally impossible rather than merely avoided.

### 3.3 Reaching the agent id

`ServerGUID` derivation needs the agent id, which lives in `config.State.AgentID`
(`agent/internal/config/config.go:18`). Sensors currently receive only
`cfg map[string]interface{}`, so the id is not reachable from `smb1.go`.

The agent injects `agent_id` and `agent_hostname` into each sensor's config map before
`StartAll`, alongside the operator-supplied keys. This follows the existing shape rather than
introducing a second channel or a package-level global, and it keeps `Sensor.Start`'s
signature unchanged. These two keys are agent-supplied and must be ignored if they appear in
operator config; the injection overwrites them.

## 4. Per-layer changes

- **`ntlm.go`** — `BuildChallenge(targetName string)` becomes `BuildChallenge(id Identity)`.
  `buildTargetInfo` takes the four derived names rather than one string. The version block is
  emitted only when the identity carries one, and the flags are computed per identity rather
  than from a package constant. Add `encodeVersion(major, minor, build uint16) []byte` and its
  inverse so the encoding is exercised rather than hand-written.
- **`smb.go`, `smb1.go`, `rdp_credssp.go`** — resolve an `Identity` in `Start` and thread it
  through their handlers. `smb1.go` additionally uses it for `NativeOS`/`NativeLanMan`,
  `ServerGUID` and SystemTime.
- **`persona.go`** *(new)* — the persona table, the `Identity` struct, and
  `Resolve(cfg map[string]interface{}) Identity`.

**Not changed:** the deliberately weak NTLM negotiation flags. `ntlm.go:25-27` documents that
key exchange and strong crypto are withheld so clients fall back to crackable NTLMv1/v2
responses. That is a designed trade-off central to the honeypot's purpose, and the persona
work must preserve it exactly. Only `NEGOTIATE_VERSION` becomes persona-controlled.

## 5. Testing

The existing tests pass with `FORTIKA` and build 46855, so new tests must assert realism
properties, not well-formedness:

1. **Version round-trip** — `decodeVersion(encodeVersion(10, 0, 17763)) == (10, 0, 17763)`.
   Retires the hand-encoded-bytes bug class permanently.
2. **Every shipped persona is internally consistent** — table test: the emitted version block
   decodes to the build the persona declares; `NativeOS` matches the OS family; the Samba
   persona emits no version block and does not set `NEGOTIATE_VERSION`.
3. **Defaults are plausible** — `nbDomain != nbComputer`; `dnsHostname` ends with `dnsDomain`.
4. **GUID is stable and unique** — the same agent id and sensor kind produce the same GUID
   twice; different sensor kinds produce different GUIDs; no GUID is all-zero.
5. **Override precedence** — operator `domain`/`hostname` win over the defaults; an unknown
   persona falls back to the default and is reported rather than failing the sensor.
6. **No literal `FORTIKA` remains under `agent/`** — which also permits deleting the exemption
   added to `scripts/ci/check-identifiers.sh`.

The existing `ntlm_challenge_test.go` assertions stay; they are correct as far as they go.

## 6. Console

The sensor editor (`apps/web/src/pages/agents.tsx`) gains three fields on `smb` and `rdp`
rows: `persona` as a `<select>`, `domain` and `hostname` as text inputs. They live behind the
existing per-row advanced disclosure, alongside the token override, so the common case remains
a port. Empty fields are omitted from the saved config, which yields the defaults.

`apps/api/src/routes/agents.ts` already accepts `config` as `z.record(z.string(), z.unknown())`
and needs no schema change; confirm this during implementation rather than assuming it.

## 7. Migration

Sensors already deployed carry no `persona`, `domain` or `hostname` keys, so they take the
defaults on the next heartbeat: `WORKGROUP`, the agent's real hostname, and the
`windows-server-2019` persona. `FORTIKA` stops being advertised without operator action. No
database migration and no config rewrite is required; the change is additive in the config map.

### 7.1 A limitation this design does not remove

Windows has shipped with SMB1 disabled by default since 2017, so a host answering SMB1 *and*
claiming to be Windows Server 2019 is mildly implausible on its own. The SMB1 path exists
deliberately: it is what captures NTLMv1 responses from legacy clients, which is a stated
purpose of the sensor. This design makes the identity self-consistent; it does not resolve the
tension between offering SMB1 and claiming a modern Windows persona.

Recorded here so it is understood as a known trade-off rather than an oversight. Two later
options, both out of scope: default the SMB sensor to a persona for which SMB1 is plausible,
or advertise SMB1 only after a client explicitly negotiates down to it.

## 8. Non-goals

- Passing a determined protocol fingerprinting tool. The aim is to stop advertising an
  identity that is self-contradictory and constant across deployments, not to be
  indistinguishable from Windows under `nmap --script smb-os-discovery`.
- Changing the weak-crypto negotiation flags (§4).
- Personas beyond the four in §3.2.
- Any change to the SSH, HTTP-login, planted-credential or file-watch sensors.
- Renaming the `f0_hpot` project or its Go module path.

## 9. Success criteria

1. `git grep FORTIKA -- agent/` returns nothing, and the identifier gate's exemption is removed.
2. Every shipped persona passes the internal-consistency table test.
3. `decodeVersion(encodeVersion(...))` round-trips for all four personas.
4. Two agents running the default configuration advertise different `ServerGUID`s and
   different computer names.
5. The Samba persona sends no NTLM version block and does not set `NEGOTIATE_VERSION`.
6. `go test ./... && go vet ./... && gofmt -l .` clean; `pnpm build && pnpm typecheck && pnpm test` clean.
