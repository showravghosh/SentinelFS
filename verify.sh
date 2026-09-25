#!/usr/bin/env bash
# Milestone 1 verification: runs the documented example traces and checks decisions.
set -u
cd "$(dirname "$0")"

run() {
  echo "--- $1"
  shift
  python3 -m sentinelfs.cli run examples/protect_shadow.sfs --trace "$@"
  echo
}

echo "=== COMPILE ==="
python3 -m sentinelfs.cli compile examples/protect_shadow.sfs
echo

echo "=== TRACE EXECUTION ==="
run 'full matching sequence (expect DENY)'     'EXEC("/usr/bin/python3")' 'SPAWN("/bin/bash")' 'WRITE("/etc/shadow")'

run 'prefix only (expect ALLOW)'     'EXEC("/usr/bin/python3")'

run 'wrong final target (expect ALLOW)'     'EXEC("/usr/bin/python3")' 'SPAWN("/bin/bash")' 'WRITE("/tmp/test.txt")'

run 'noise interleaved (expect DENY)'     'OPEN("/var/log/syslog")' 'EXEC("/usr/bin/python3")' 'OPEN("/var/log/syslog")' 'SPAWN("/bin/bash")' 'WRITE("/etc/shadow")'
