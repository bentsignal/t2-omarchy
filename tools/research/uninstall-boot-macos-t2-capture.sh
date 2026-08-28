#!/bin/bash
set -euo pipefail

if [[ $(uname -s) != Darwin || $(id -u) -ne 0 ]]; then
  echo "usage: sudo $0" >&2
  exit 2
fi

plist=/Library/LaunchDaemons/com.bentsignal.t2-touch-id-boot-capture.plist
collector=/usr/local/libexec/t2-touch-id-boot-capture

if [[ -e $plist ]]; then
  launchctl bootout system "$plist" 2>/dev/null || true
  rm -f "$plist"
fi
rm -f "$collector"
echo "Removed the T2 boot collector. Evidence under /var/tmp was preserved."

