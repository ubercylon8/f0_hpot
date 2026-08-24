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

# 1. Assemble the unsigned manifest JSON.
MANIFEST=$(mktemp)
SIGN_INPUT=$(mktemp)
python3 - "$VERSION" "${BINARIES[@]}" > "$SIGN_INPUT" <<'PYEOF'
import json, hashlib, os, sys
version = sys.argv[1]
files = {}
for b in sys.argv[2:]:
    h = hashlib.sha256(open(b, "rb").read()).hexdigest()
    files[os.path.basename(b)] = {"sha256": h, "size": os.path.getsize(b)}
# Canonical form MUST match the agent's verifier: Go json.Marshal encodes
# maps with sorted keys and compact separators.
json.dump({"files": files, "version": version},
          open(sys.stdout.fileno(), "w"),
          sort_keys=True, separators=(",", ":"))
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
rm -f "$MANIFEST" "$SIGN_INPUT" /tmp/f0-release.sig

echo "Public key (embed via -ldflags '-X update.UpdatePublicKey=<b64>'):"
echo "  openssl pkey -in $PRIVKEY_FILE -pubout | grep -v '---' | tr -d '\n' | base64 -w0"
