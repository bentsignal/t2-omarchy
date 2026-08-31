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
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
sanitizer=$script_dir/sanitize-macos-enrollment-log.py
if [[ ! -f $sanitizer ]]; then
  echo "The strict unified-log sanitizer is missing." >&2
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
chmod 600 "$capture_dir/sw_vers.txt"

log_pid=""
cleanup() {
  if [[ -n $log_pid ]]; then
    kill -INT "$log_pid" 2>/dev/null || true
    wait "$log_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

log stream --style ndjson --level debug \
  --predicate 'process == "remoted" OR process == "biometrickitd" OR subsystem CONTAINS[c] "Biometric"' \
  >"$capture_dir/unified-log.ndjson" \
  2>"$capture_dir/unified-log-errors.txt" &
log_pid=$!
sleep 2
if ! kill -0 "$log_pid" 2>/dev/null; then
  echo "The private unified-log stream exited before the ceremony." >&2
  exit 3
fi

echo
echo "PRIVATE Touch ID match logging is active."
echo "Lock this already-unlocked Mac with Control-Command-Q."
echo "Unlock it exactly once with the enrolled finger, return here, and press Enter."
echo "Do not copy or commit the raw log."
read -r
sleep 2

kill -INT "$log_pid" 2>/dev/null || true
wait "$log_pid" 2>/dev/null || true
log_pid=""
chmod 600 "$capture_dir/unified-log.ndjson" "$capture_dir/unified-log-errors.txt"

python3 "$sanitizer" "$capture_dir/unified-log.ndjson" \
  >"$capture_dir/sanitized-match-log.json"
chmod 600 "$capture_dir/sanitized-match-log.json"
command_4_count=$(python3 -c \
  'import json,sys; print(len(json.load(open(sys.argv[1]))["command_4_windows"]))' \
  "$capture_dir/sanitized-match-log.json")
if (( command_4_count == 0 )); then
  echo "No logged command 4 was recovered; keep the private directory for local diagnosis." >&2
  exit 4
fi

find "$capture_dir" -type f ! -name capture-sha256.txt \
  -exec shasum -a 256 {} + >"$capture_dir/capture-sha256.txt"
chmod 600 "$capture_dir/capture-sha256.txt"

echo "Match capture complete: $capture_dir"
echo "Keep the entire directory private; review only sanitized-match-log.json."
