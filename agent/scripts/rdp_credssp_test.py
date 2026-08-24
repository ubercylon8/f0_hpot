#!/usr/bin/env python3
"""CredSSP/NLA test client for the f0_deception RDP honeypot.

Performs the same flow as mstsc's NLA handshake (minus the real Kerberos/
NTLM crypto): X.224 CR with PROTOCOL_HYBRID -> TLS (cert validation
disabled) -> TSRequest NTLM NEGOTIATE -> challenge -> AUTHENTICATE.

Usage:
  python rdp_credssp_test.py <host> <port> [username] [password] [domain]

If credentials are supplied they are sent in the AUTHENTICATE message —
verify they appear in the console incident. Defaults to random junk.
"""
import socket
import struct
import ssl
import sys


def tsrequest(blob: bytes) -> bytes:
    inner = (b"\xa1" + bytes([len(blob) + 4])
             + b"\x30" + bytes([len(blob) + 2])
             + b"\x04" + bytes([len(blob)]) + blob)
    return (b"\x30" + bytes([len(inner) + 7])
            + b"\xa0\x03\x02\x01\x05"
            + b"\xa1" + bytes([len(inner)]) + inner)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 13389
    user = sys.argv[3] if len(sys.argv) > 3 else "rdp_tester"
    password = sys.argv[4] if len(sys.argv) > 4 else "CredSSP-Test-1!"
    domain = sys.argv[5] if len(sys.argv) > 5 else "TESTDOMAIN"

    # 1) X.224 connection request requesting PROTOCOL_HYBRID (NLA)
    x224 = (b"\xe0" + b"\x00\x00" * 2 + b"\x00"
            + b"Cookie: mstshash=f0test\r\n"
            + b"\x01\x00\x08\x02\x00\x00\x00\x00")
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(bytes([3, 0]) + struct.pack(">H", len(x224) + 4) + x224)
    cc = s.recv(64)
    neg = cc[11:19] if len(cc) >= 19 else b""
    print(f"[1] connection confirm: {len(cc)} bytes, "
          f"NEG_RSP type={neg[0] if neg else '-'}, proto={neg[7] if len(neg) > 7 else '-'}")
    time.sleep(0.3)

    # 2) TLS with cert validation disabled (like clicking through mstsc's warning)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(s)
    print(f"[2] TLS established: {tls.version()}")

    # 3) TSRequest with NTLM NEGOTIATE
    negotiate = b"NTLMSSP\x00" + (1).to_bytes(4, "little") + b"\x00" * 16
    tls.sendall(tsrequest(negotiate))
    r = tls.recv(8192)
    i = r.find(b"NTLMSSP\x00")
    if i < 0:
        print("[3] FAIL: no NTLM challenge in response")
        return
    challenge_type = int.from_bytes(r[i + 8:i + 12], "little")
    print(f"[3] NTLM challenge received (type {challenge_type})")

    # 4) AUTHENTICATE with the test credentials
    lm = b"T" * 24
    ntlm = b"U" * 16 + b"V" * 48
    u, d, h = (x.encode("utf-16-le") for x in (user, domain, "TESTMACHINE"))
    a = bytearray(b"NTLMSSP\x00" + (3).to_bytes(4, "little"))
    off = 64
    for f in (lm, ntlm, d, u, h):
        a += struct.pack("<HHI", len(f), len(f), off)
        off += len(f)
    a += b"\x00" * 8 + b"\x06\x82\xa8\xe2"
    a += lm + ntlm + d + u + h
    tls.sendall(tsrequest(bytes(a)))
    try:
        tls.recv(1024)
    except Exception:
        pass
    tls.close()
    print(f"[4] AUTHENTICATE sent: user={domain}\\{user} — "
          "check the f0_deception console for a credssp_credentials incident")


if __name__ == "__main__":
    import time  # noqa: F401 (kept for parity with dev client)
    main()
