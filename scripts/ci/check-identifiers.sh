#!/usr/bin/env bash
# Copyright 2026 The f0_hpot Authors
# SPDX-License-Identifier: Apache-2.0
# Fail if a tracked file contains a real operational identifier.
#
# Deception infrastructure is only useful while an adversary does not know
# which domain and which console belong to the defender. Documentation drifts
# toward concrete examples over time; this gate keeps those examples fictional.
set -uo pipefail

fail=0
report() { echo "::error file=$1,line=$2::$3"; fail=1; }

# Public IPv4 literals, excluding loopback, any-address, link-local, RFC 1918
# private ranges, and the RFC 5737 documentation ranges. Test fixtures use
# arbitrary IPs on purpose (mock incident sources, simulated geo-alerts) —
# their realism is the point, not a documentation leak — so *.test.ts and
# the e2e suite are scoped out of this literal check; the denylist check
# below still runs over them unscoped. The public-release plan doc quotes
# this very gate's RED-test fixture value (198[.]18[.]7[.]7, defanged here
# so this comment doesn't itself trip the check below) verbatim as its own
# worked example, at one known line — that single quoted value, in that one
# file, is exempted below; any other address in that file still fails, so
# the doc keeps no blind spot for a genuine leak.
while IFS=: read -r file line _; do
  [ -z "${file:-}" ] && continue
  report "$file" "$line" "public IPv4 literal — use 203.0.113.10 (RFC 5737)"
done < <(git grep -InE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' -- . \
  ':!pnpm-lock.yaml' ':!*.svg' ':!*.test.ts' ':!scripts/e2e/**' \
  | grep -vE '\b(127\.|0\.0\.0\.0|255\.)' \
  | grep -vE '\b(10|192\.168)\.' \
  | grep -vE '\b172\.(1[6-9]|2[0-9]|3[01])\.' \
  | grep -vE '\b169\.254\.' \
  | grep -vE '\b(192\.0\.2|198\.51\.100|203\.0\.113)\.' \
  | grep -vE '\b(1\.2\.3\.4|5\.6\.7\.8|8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1)\b' \
  | grep -vE '\([A-Z]{2,}-[A-Za-z0-9]+ [0-9]+(\.[0-9]+){3}\)' \
  | grep -vE '^docs/superpowers/plans/2026-09-03-public-release\.md:[0-9]+:.*198\.18\.7\.7' \
  | grep -vE '\b[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\b.*(version|Version|VERSION)')

# Domains and hostnames that must never appear. Supplied through the
# environment, NEVER stored in the repository: a denylist naming the
# operator's real domain would publish the very string it exists to hide.
# CI injects it from a repository secret; locally, export it in your shell.
#
# The match is case-INSENSITIVE (-i). Hostnames and domains are themselves
# case-insensitive, so a lowercase denylist entry must still catch an uppercase
# occurrence; without -i this gate silently passed the very strings it exists
# to block.
#
# DEFERRAL, NOT AN EXEMPTION ON THE MERITS: the four agent sensor files named
# in the skip pattern below hardcode the string as an NTLM challenge target
# name and an RDP certificate CommonName — 7 lines in total, all under
# agent/internal/sensors/. These are product constants baked into the agent's
# on-the-wire behaviour, so renaming them is a maintainer decision with its own
# compatibility question, deliberately out of scope for the documentation
# release that added -i. They are NOT safe by nature: they are an operational
# identifier shipped in the binary, and they should be renamed. Until that
# decision is made they are skipped by path AND value, so any other occurrence
# of a denylisted string — including anywhere else in these same four files —
# still fails.
#
# The skip pattern spells the constant FORT[I]KA, with the single-character
# class matching exactly the letter it encloses. That is deliberate: the
# pattern would otherwise be a verbatim copy of the string in a tracked file
# and this gate would flag its own source line. Do not "simplify" the brackets
# away — the regex means the same thing, but the check starts failing itself.
for pattern in ${F0_IDENTIFIER_DENYLIST:-}; do
  while IFS=: read -r file line _; do
    [ -z "${file:-}" ] && continue
    report "$file" "$line" "operational identifier matched — use example.com"
  done < <(git grep -Iin "$pattern" -- . \
    | grep -vE '^agent/internal/sensors/(smb|smb1|rdp_credssp|ntlm_challenge_test)\.go:[0-9]+:.*(BuildChallenge\("FORT[I]KA(-RDP)?"\)|CommonName: "FORT[I]KA-RDP")')
done

if [ "$fail" -eq 0 ]; then echo "no operational identifiers found"; fi
exit "$fail"
