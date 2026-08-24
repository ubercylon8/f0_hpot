# RDP honeypot — mstsc validation guide

Validate the f0_deception RDP honeypot against a **real Windows mstsc
client** (stricter than scripted clients) and confirm credential capture.

## Topology

```
Windows 11 VM (ssh win)                f0_deception agent host
172.30.0.2                ──RDP──►     <agent-host>:13389
mstsc /v:...                           RDP honeypot sensor
```

## 1. Prerequisites (agent host)

```sh
# agent running with an rdp sensor on :13389 — check the console Agents
# tab, or the process log for: "[rdp] listening on :13389"
ss -tln | grep 13389
```

## 2. Connectivity from the Windows VM

```powershell
# via ssh win:
Test-NetConnection <agent-host-ip> -Port 13389
```

`<agent-host-ip>` is the address the VM can route to (the host's bridge or
LAN IP — try the gateway address first, e.g. `172.30.0.1`).
`TcpTestSucceeded: True` → proceed.

## 3. Automated CredSSP check (no GUI)

Copy the test script to the VM and run it — validates the full NLA flow:

```powershell
scp agent/scripts/rdp_credssp_test.py win:C:/temp/
ssh win "python C:/temp/rdp_credssp_test.py <agent-host-ip> 13389 svc_test 'P@ss1' CORP"
```

Expected: `[3] NTLM challenge received (type 2)` and a
**credssp_credentials** incident in the console showing `CORP\svc_test`.

## 4. Real mstsc run

On the VM (GUI session or via `ssh win` + `mstsc`):

```
mstsc /v:<agent-host-ip>:13389
```

Expected behavior, step by step:

| Step | What you see | What it proves |
|---|---|---|
| 1 | Certificate warning (unknown publisher / name mismatch) | our self-signed cert is served — click **Yes** to continue |
| 2 | Windows security prompt asking for credentials | NLA/CredSSP handshake reached — enter any test credentials |
| 3 | Connection fails / black screen after auth | expected: honeypot captured and dropped you |

Then check the console: an incident with
`rdp: CAPTURED credentials <DOMAIN>\<user>` and a hashcat line.

## 5. If mstsc aborts early

The scripted client is more forgiving than mstsc. Known strictness points,
in the order mstsc hits them:

1. **X.224 CC must echo RDP_NEG_RSP with PROTOCOL_HYBRID** — verified ✓
2. **TLS cipher suites** — we accept the Go defaults; mstsc requires
   TLS 1.2+ ✓
3. **TSRequest version field** must be 5 ✓
4. **NTLM challenge AV pairs** must parse — verified ✓
5. If mstsc shows "An authentication error has occurred" *before* asking
   for credentials, capture the exchange:

```powershell
# on the VM, with a packet capture on the agent host:
sudo tcpdump -i any port 13389 -w /tmp/rdp.pcap
```

and file the trace against `agent/internal/sensors/rdp_credssp.go`.

## 6. Cleanup

Incidents are expected — acknowledge them in the console. The honeypot
accepts every credential by design.
