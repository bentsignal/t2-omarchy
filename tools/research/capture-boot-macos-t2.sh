#!/bin/bash
set -euo pipefail

if [[ $(uname -s) != Darwin || $(id -u) -ne 0 ]]; then
  echo "This collector must run as root on macOS." >&2
  exit 2
fi

capture_root=/var/tmp/t2-touch-id-boot-capture
launch_plist=/Library/LaunchDaemons/com.bentsignal.t2-touch-id-boot-capture.plist
duration_seconds=300

if [[ -e $capture_root ]]; then
  echo "Refusing to mix boot evidence: $capture_root already exists." >&2
  exit 3
fi
mkdir -m 700 "$capture_root"

cleanup() {
  for pid in ${capture_pids:-}; do
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -n ${log_pid:-} ]]; then
    kill -INT "$log_pid" 2>/dev/null || true
    wait "$log_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

date -u +%Y-%m-%dT%H:%M:%SZ >"$capture_root/collector-start-utc.txt"
sw_vers >"$capture_root/sw_vers.txt"
uname -a >"$capture_root/uname.txt"
sysctl -n kern.boottime >"$capture_root/kern-boottime.txt"

log stream --style ndjson --level debug \
  --predicate 'process == "remoted" OR process == "biometrickitd" OR subsystem CONTAINS[c] "RemoteServiceDiscovery" OR subsystem CONTAINS[c] "Biometric" OR subsystem == "com.apple.BridgeXPC"' \
  >"$capture_root/unified-log.ndjson" 2>"$capture_root/unified-log-errors.txt" &
log_pid=$!

# Wait up to two minutes for the AppleUSBNCMData interface. Never substitute
# Wi-Fi or an unproven interface.
t2_interfaces=""
for _ in $(jot 120); do
  t2_interfaces=$(ifconfig -a | awk '
    /^[A-Za-z0-9][A-Za-z0-9._-]*:/ { iface=$1; sub(/:$/, "", iface) }
    /^[[:space:]]*ether ac:de:48:/ { print iface }
  ' | sort -u)
  [[ -n $t2_interfaces ]] && break
  sleep 1
done
printf '%s\n' "$t2_interfaces" >"$capture_root/t2-interfaces.txt"

capture_pids=""
for interface_name in $t2_interfaces; do
  case "$interface_name" in
    *[!A-Za-z0-9._-]*) echo "unsafe interface name" >&2; exit 2 ;;
  esac
  capture_interface=$interface_name
  link_type_args=()
  if ! tcpdump -i "$interface_name" -L >/dev/null 2>&1; then
    capture_interface="pktap,$interface_name"
    link_type_args=(-y RAW)
  fi
  tcpdump -i "$capture_interface" "${link_type_args[@]}" -n -s 0 -U -w \
    "$capture_root/$interface_name.pcap" \
    >"$capture_root/$interface_name-tcpdump.txt" 2>&1 &
  capture_pids="$capture_pids $!"
done

snapshot() {
  sequence=$1
  snapshot_dir=$(printf '%s/snapshots/%04d' "$capture_root" "$sequence")
  mkdir -p "$snapshot_dir"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ >"$snapshot_dir/timestamp-utc.txt"
  ifconfig -a >"$snapshot_dir/ifconfig.txt"
  ndp -an >"$snapshot_dir/ndp.txt" 2>&1 || true
  netstat -anv -p tcp >"$snapshot_dir/netstat-tcp.txt" 2>&1 || true
  lsof -nP -iTCP >"$snapshot_dir/lsof-tcp.txt" 2>&1 || true
  launchctl print system/com.apple.remoted \
    >"$snapshot_dir/remoted-launchctl.txt" 2>&1 || true
  launchctl print system/com.apple.biometrickitd \
    >"$snapshot_dir/biometrickitd-launchctl.txt" 2>&1 || true
}

# Favor resolution during early activation, then reduce overhead while still
# covering first login. All collection stops within five minutes.
sequence=0
elapsed=0
while (( elapsed < duration_seconds )); do
  snapshot "$sequence"
  sequence=$((sequence + 1))
  if (( elapsed < 30 )); then
    sleep 1
    elapsed=$((elapsed + 1))
  else
    sleep 5
    elapsed=$((elapsed + 5))
  fi
done

cleanup
capture_pids=""
log_pid=""
date -u +%Y-%m-%dT%H:%M:%SZ >"$capture_root/collector-end-utc.txt"
find "$capture_root" -type f ! -name capture-sha256.txt \
  -exec shasum -a 256 {} + >"$capture_root/capture-sha256.txt"
chmod -R a+rX "$capture_root"

# One-shot persistence: remove only this collector's exact plist. The copied
# script and evidence remain until the explicit uninstall/cleanup step.
rm -f "$launch_plist"

