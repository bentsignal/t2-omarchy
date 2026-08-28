#!/bin/bash
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
  echo "This collector must be run from macOS." >&2
  exit 2
fi
if (( $# != 1 )); then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

capture_dir=$1
duration_seconds=60
mkdir -p "$capture_dir"
chmod 700 "$capture_dir"

sw_vers >"$capture_dir/sw_vers.txt"
uname -a >"$capture_dir/uname.txt"
ifconfig -a >"$capture_dir/ifconfig-before.txt"
netstat -anv -p tcp >"$capture_dir/tcp-listeners-before.txt" 2>&1 || true
launchctl print system/com.apple.remoted \
  >"$capture_dir/remoted-launchctl-before.txt" 2>&1 || true
launchctl print system/com.apple.biometrickitd \
  >"$capture_dir/biometrickitd-launchctl-before.txt" 2>&1 || true

# Restrict packet collection to interfaces whose current Ethernet address is
# in Apple's ac:de:48 T2 range. Never capture Wi-Fi or unrelated interfaces.
t2_interfaces=$(ifconfig -a | awk '
  /^[A-Za-z0-9][A-Za-z0-9._-]*:/ { iface=$1; sub(/:$/, "", iface) }
  /^[[:space:]]*ether ac:de:48:/ { print iface }
' | sort -u)
printf '%s\n' "$t2_interfaces" >"$capture_dir/t2-interfaces.txt"

echo "A macOS authorization prompt may appear for the bounded packet capture."
sudo -v

pids=""
for interface_name in $t2_interfaces; do
  case "$interface_name" in
    *[!A-Za-z0-9._-]*) echo "unsafe interface name" >&2; exit 2 ;;
  esac
  sudo tcpdump -i "$interface_name" -n -s 0 -U -w \
    "$capture_dir/$interface_name.pcap" >"$capture_dir/$interface_name-tcpdump.txt" 2>&1 &
  pids="$pids $!"
done

log stream --style ndjson --level debug \
  --predicate 'process == "remoted" OR process == "biometrickitd" OR subsystem CONTAINS[c] "RemoteServiceDiscovery" OR subsystem CONTAINS[c] "Biometric"' \
  >"$capture_dir/unified-log.ndjson" 2>"$capture_dir/unified-log-errors.txt" &
log_pid=$!

echo "Capture is running for $duration_seconds seconds. Unlock the Mac with Touch ID"
echo "once, then approve one harmless prompt with Touch ID if convenient."
sleep "$duration_seconds"

kill -INT $pids 2>/dev/null || true
kill -INT "$log_pid" 2>/dev/null || true
wait $pids 2>/dev/null || true
wait "$log_pid" 2>/dev/null || true

ifconfig -a >"$capture_dir/ifconfig-after.txt"
netstat -anv -p tcp >"$capture_dir/tcp-listeners-after.txt" 2>&1 || true
find "$capture_dir" -type f ! -name capture-sha256.txt \
  -exec shasum -a 256 {} + >"$capture_dir/capture-sha256.txt"

echo "Capture complete: $capture_dir"
