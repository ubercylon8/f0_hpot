#!/usr/bin/env bash
# Signs the agent release manifest with an Ed25519 private key.
#
# Usage:
#   ./sign_release.sh <private_key_file> <binary>...
#
# Produces bin/release-manifest.json:
#   { "version", "files": {name: {sha256,size}}, "signature" }
set -euo pipefail

PRIVKEY_FILE=$1
shift
BINARIES=("$@")

cd "$(dirname "$0")"
VERSION=$(git describe --tags --always 2>/dev/null || echo dev)

# 1. Assemble the exact canonical bytes the agent verifies.
SIGN_INPUT=$(mktemp)
python3 - "$VERSION" "${BINARIES[@]}" > "$SIGN_INPUT" <<'PYEOF'
import json, hashlib, os, sys
version = sys.argv[1]
files = {}
for b in sys.argv[2:]:
    h = hashlib.sha256(open(b, "rb").read()).hexdigest()
    files[os.path.basename(b)] = {"sha256": h, "size": os.path.getsize(b)}

def go_str(s):
    # Go's json.Marshal string escaping (HTML chars are escaped by default).
    return (json.dumps(s, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))

# Canonical form MUST match the agent's verifier byte-for-byte: Go
# json.Marshal emits struct fields in DECLARATION order (version, files,
# signature — NOT sorted), map keys sorted, compact separators, and the
# signature field present but EMPTY. Locked by golden tests on both sides
# (agent/internal/update + apps/api/src/release-signing).
inner = ",".join(
    '%s:{"sha256":%s,"size":%d}' % (go_str(n), go_str(f["sha256"]), f["size"])
    for n, f in sorted(files.items()))
canonical = ('{"version":%s,"files":{%s},"signature":""}'
             % (go_str(version), inner))
sys.stdout.write(canonical)
PYEOF

# 2. Sign the exact manifest bytes with Ed25519.
openssl pkeyutl -sign -inkey "$PRIVKEY_FILE" -rawin -in "$SIGN_INPUT" \
  -out /tmp/f0-release.sig

# 3. Embed the signature.
python3 - "$SIGN_INPUT" /tmp/f0-release.sig bin/release-manifest.json <<'PYEOF'
import base64, json, sys
data = open(sys.argv[1], "rb").read()
sig = base64.b64encode(open(sys.argv[2], "rb").read()).decode()
m = json.loads(data)
m["signature"] = sig
json.dump(m, open(sys.argv[3], "w"), indent=2)
print(f"signed bin/release-manifest.json (version {m['version']}, {len(m['files'])} files)")
PYEOF
rm -f "$SIGN_INPUT" /tmp/f0-release.sig

echo "Public key (embed via -ldflags '-X update.UpdatePublicKey=<b64>'):"
echo "  openssl pkey -in $PRIVKEY_FILE -pubout -outform DER | tail -c 32 | base64 -w0"
