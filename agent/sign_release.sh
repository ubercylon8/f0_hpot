#!/usr/bin/env bash
# Signs the agent release manifest with an Ed25519 private key.
#
# Usage:
#   ./sign_release.sh <private_key_file> <binary>...
#
# Produces bin/release-manifest.json:
#   { "version": "...", "files": { "<name>": { "sha256": "...", "size": n } }, "signature": "..." }
#
# The public key is distributed embedded in the agent; updates are trusted
# only when the manifest signature verifies (see internal/update).
set -euo pipefail

PRIVKEY_FILE=$1
shift
BINARIES=("$@")

cd "$(dirname "$0")"
VERSION=$(git describe --tags --always 2>/dev/null || echo dev)

MANIFEST=$(mktemp)
{
  echo '{'
  echo "  \"version\": \"$VERSION\","
  echo '  "files": {'
  first=1
  for b in "${BINARIES[@]}"; do
    name=$(basename "$b")
    hash=$(sha256sum "$b" | cut -d' ' -f1)
    size=$(stat -c%s "$b" 2>/dev/null || stat -f%z "$b")
    [ $first -eq 1 ] && first=0 || echo ','
    printf '    "%s": {"sha256": "%s", "size": %s}' "$name" "$hash" "$size"
  done
  echo
  echo '  }'
} > "$MANIFEST"

# Sign SHA-256 digest of the manifest body (without signature field) using
# openssl pkeyutl with Ed25519.
openssl pkeyutl -sign -inkey "$PRIVKEY_FILE" -rawin -in "$MANIFEST" \
  -out /tmp/f0-release.sig 2>/dev/null

SIG_B64=$(base64 -w0 /tmp/f0-release.sig)
python3 - "$MANIFEST" "$SIG_B64" <<'EOF'
import json, sys
path, sig = sys.argv[1], sys.argv[2]
data = json.load(open(path))
data["signature"] = sig
json.dump(data, open("bin/release-manifest.json", "w"), indent=2)
print("signed bin/release-manifest.json (version %s)" % data["version"])
EOF
rm -f "$MANIFEST" /tmp/f0-release.sig

echo "Public key (embed in agent):"
echo "  openssl pkey -in $PRIVKEY_FILE -pubout"
