#!/bin/bash
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
  echo "This collector must be run from macOS." >&2
  exit 2
fi
if (( $# != 1 )); then
  echo "usage: $0 PRIVATE_OUTPUT_DIRECTORY" >&2
  exit 2
fi

capture_dir=$1
duration_seconds=120
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
sanitizer=$script_dir/sanitize-macos-enrollment-pcap.py
log_sanitizer=$script_dir/sanitize-macos-enrollment-log.py
if [[ ! -f $sanitizer || ! -f $log_sanitizer ]]; then
  echo "An enrollment sanitizer is missing." >&2
  exit 2
fi
if [[ -e $capture_dir ]]; then
  if [[ ! -d $capture_dir ]]; then
    echo "output exists and is not a directory: $capture_dir" >&2
    exit 2
  fi
  if [[ -n $(find "$capture_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "output directory must be empty: $capture_dir" >&2
    exit 2
  fi
fi
mkdir -p "$capture_dir"
chmod 700 "$capture_dir"

sw_vers >"$capture_dir/sw_vers.txt"
ifconfig -a >"$capture_dir/ifconfig-before.txt"
t2_interfaces=$(ifconfig -a | awk '
  /^[A-Za-z0-9][A-Za-z0-9._-]*:/ { iface=$1; sub(/:$/, "", iface) }
  /^[[:space:]]*ether ac:de:48:/ { print iface }
' | sort -u)
printf '%s\n' "$t2_interfaces" >"$capture_dir/t2-interfaces.txt"
if [[ -z $t2_interfaces ]]; then
  echo "No ac:de:48 T2 network interface was found." >&2
  exit 3
fi

echo "A macOS authorization prompt will appear for the T2-only packet capture."
sudo -v

pids=""
log_pid=""
cleanup() {
  if [[ -n $pids ]]; then
    kill -INT $pids 2>/dev/null || true
    wait $pids 2>/dev/null || true
  fi
  if [[ -n $log_pid ]]; then
    kill -INT "$log_pid" 2>/dev/null || true
    wait "$log_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

for interface_name in $t2_interfaces; do
  case "$interface_name" in
    *[!A-Za-z0-9._-]*) echo "unsafe interface name" >&2; exit 2 ;;
  esac
  # Direct BPF attachment can succeed on AppleUSBNCMData while silently
  # producing an empty DLT_RAW pcap. pktap remains scoped to this exact T2
  # interface, and RAW output strips pktap metadata from the evidence file.
  capture_interface="pktap,$interface_name"
  sudo tcpdump -i "$capture_interface" -y RAW -n -s 0 -U -w \
    "$capture_dir/$interface_name.pcap" \
    >"$capture_dir/$interface_name-tcpdump.txt" 2>&1 &
  pids="$pids $!"
done

sleep 1
for capture_pid in $pids; do
  if ! kill -0 "$capture_pid" 2>/dev/null; then
    echo "A T2 tcpdump process exited before the ceremony." >&2
    exit 4
  fi
done

log stream --style ndjson --level debug \
  --predicate 'process == "remoted" OR process == "biometrickitd" OR subsystem CONTAINS[c] "Biometric"' \
  >"$capture_dir/unified-log.ndjson" \
  2>"$capture_dir/unified-log-errors.txt" &
log_pid=$!

echo
echo "PRIVATE T2 capture is running for $duration_seconds seconds."
echo "Open Touch ID settings and begin Add Fingerprint with a finger that is not enrolled."
echo "Complete at least the first accepted scan, then cancel the enrollment if desired."
echo "Do not copy or commit this raw capture."
sleep "$duration_seconds"

kill -INT $pids 2>/dev/null || true
kill -INT "$log_pid" 2>/dev/null || true
wait $pids 2>/dev/null || true
wait "$log_pid" 2>/dev/null || true
pids=""
log_pid=""

ifconfig -a >"$capture_dir/ifconfig-after.txt"
sudo chown "$(id -u):$(id -g)" "$capture_dir"/*.pcap
chmod 600 "$capture_dir"/*.pcap "$capture_dir"/*.txt "$capture_dir"/*.ndjson

sanitized_count=0
sanitized_connections=0
for pcap_path in "$capture_dir"/*.pcap; do
  interface_name=$(basename "$pcap_path" .pcap)
  python3 "$sanitizer" "$pcap_path" \
    >"$capture_dir/$interface_name-sanitized-enrollment.json"
  chmod 600 "$capture_dir/$interface_name-sanitized-enrollment.json"
  connection_count=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["connection_count"])' \
    "$capture_dir/$interface_name-sanitized-enrollment.json")
  sanitized_connections=$((sanitized_connections + connection_count))
  sanitized_count=$((sanitized_count + 1))
done
if (( sanitized_count == 0 )); then
  echo "No pcap was produced." >&2
  exit 5
fi
python3 "$log_sanitizer" "$capture_dir/unified-log.ndjson" \
  >"$capture_dir/sanitized-enrollment-log.json"
chmod 600 "$capture_dir/sanitized-enrollment-log.json"
log_command_3_count=$(python3 -c \
  'import json,sys; print(len(json.load(open(sys.argv[1]))["command_3_windows"]))' \
  "$capture_dir/sanitized-enrollment-log.json")
if (( sanitized_connections == 0 && log_command_3_count == 0 )); then
  echo "No complete Bridge connection or logged command 3 was recovered." >&2
  exit 6
fi
if (( sanitized_connections == 0 )); then
  echo "Packet capture was empty; a sanitized command-3 log window was recovered." >&2
fi

find "$capture_dir" -type f ! -name capture-sha256.txt \
  -exec shasum -a 256 {} + >"$capture_dir/capture-sha256.txt"
chmod 600 "$capture_dir/capture-sha256.txt"

echo "Capture complete. Keep every file private: $capture_dir"
echo "The sanitized enrollment JSON files are safe summaries for Codex review."
