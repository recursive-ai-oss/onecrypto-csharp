#!/usr/bin/env bash
# Compares the availability section a smoke app printed (between AVAILABILITY-BEGIN and AVAILABILITY-END) with the matching
# section of docs/availability.md. Used for the browser build, which cannot run the unit tests.
#
#   tools/check-availability.sh <smoke app output file>
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:?usage: check-availability.sh <smoke app output file>}"
section() { awk '/^<!-- platform: /{p=1} p{print} /^<!-- end -->/{p=0}' ; }
printed=$(sed -n '/^AVAILABILITY-BEGIN/,/^AVAILABILITY-END/p' "$out" | sed '1d;$d' | tr -d '\r')
key=$(printf '%s\n' "$printed" | sed -n 's/^<!-- platform: \(.*\) -->$/\1/p' | head -1)
[ -n "$key" ] || { echo "no availability section in $out" >&2; exit 1; }
committed=$(awk -v k="<!-- platform: $key -->" '$0==k{p=1} p{print} p&&/^<!-- end -->/{exit}' "$here/docs/availability.md")
[ -n "$committed" ] || { echo "docs/availability.md has no section for $key" >&2; exit 1; }
if [ "$printed" != "$committed" ]; then
  echo "availability table drifted for $key:" >&2
  diff <(printf '%s\n' "$committed") <(printf '%s\n' "$printed") >&2 || true
  exit 1
fi
echo "availability table matches for $key"
