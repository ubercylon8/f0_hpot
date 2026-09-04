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
# this very gate's RED-test fixture verbatim as its own worked example —
# a permanent, deliberate exception, not a leak — so it is scoped out too.
while IFS=: read -r file line _; do
  [ -z "${file:-}" ] && continue
  report "$file" "$line" "public IPv4 literal — use 203.0.113.10 (RFC 5737)"
done < <(git grep -InE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' -- . \
  ':!pnpm-lock.yaml' ':!*.svg' ':!*.test.ts' ':!scripts/e2e/**' \
  ':!docs/superpowers/plans/2026-09-03-public-release.md' \
  | grep -vE '\b(127\.|0\.0\.0\.0|255\.)' \
  | grep -vE '\b(10|192\.168)\.' \
  | grep -vE '\b172\.(1[6-9]|2[0-9]|3[01])\.' \
  | grep -vE '\b169\.254\.' \
  | grep -vE '\b(192\.0\.2|198\.51\.100|203\.0\.113)\.' \
  | grep -vE '\b(1\.2\.3\.4|5\.6\.7\.8|8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1)\b' \
  | grep -vE '\([A-Z]{2,}-[A-Za-z0-9]+ [0-9]+(\.[0-9]+){3}\)' \
  | grep -vE '\b[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\b.*(version|Version|VERSION)')

# Domains and hostnames that must never appear. Supplied through the
# environment, NEVER stored in the repository: a denylist naming the
# operator's real domain would publish the very string it exists to hide.
# CI injects it from a repository secret; locally, export it in your shell.
for pattern in ${F0_IDENTIFIER_DENYLIST:-}; do
  while IFS=: read -r file line _; do
    [ -z "${file:-}" ] && continue
    report "$file" "$line" "operational identifier matched — use example.com"
  done < <(git grep -In "$pattern" -- .)
done

if [ "$fail" -eq 0 ]; then echo "no operational identifiers found"; fi
exit "$fail"
