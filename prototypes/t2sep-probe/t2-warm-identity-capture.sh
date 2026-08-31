#!/bin/bash
# SPDX-License-Identifier: MIT
# Capture the first privacy-safe identity count after a controlled macOS reboot.
set -euo pipefail

PATH=/usr/bin:/bin
export PATH
umask 077
ulimit -c 0

CONFIG_FILE=/etc/t2-touchid.conf
STATE_DIR=/var/lib/t2-touchid
OUTPUT=$STATE_DIR/warm-transition-identity.json
PORT_FILE=$STATE_DIR/biometric-port
LOCK_FILE=/run/t2-touchid/operation.lock
RAW=
SAFE=

cleanup() {
  [[ -z $RAW ]] || rm -f -- "$RAW"
  [[ -z $SAFE ]] || rm -f -- "$SAFE"
}
trap cleanup EXIT HUP INT TERM

[[ $EUID -eq 0 ]] || { echo "warm identity capture requires root" >&2; exit 1; }
[[ -r $CONFIG_FILE ]] || { echo "Touch ID configuration is unavailable" >&2; exit 1; }

for unit in fprintd.service t2-biometric-ready.service; do
  if systemctl is-enabled --quiet "$unit" || systemctl is-active --quiet "$unit"; then
    echo "$unit must remain disabled and inactive for warm capture" >&2
    exit 1
  fi
done

read_config() {
  sed -n "s/^$1=//p" "$CONFIG_FILE" | tail -n 1
}

host=$(read_config T2_TOUCHID_HOST)
interface=$(read_config T2_TOUCHID_INTERFACE)
project=$(read_config T2_TOUCHID_PROJECT_DIR)
macos_user_id=$(read_config T2_TOUCHID_MACOS_USER_ID)
[[ -n $host && -n $interface && -n $project ]] || exit 1
[[ $macos_user_id =~ ^[0-9]+$ && $macos_user_id -le 4294967295 ]] || exit 1
[[ -x $project/.venv/bin/python ]] || exit 1
[[ -f $project/src/bridge-xpc-probe.py ]] || exit 1
[[ -f $project/src/discover-biometric-port.py ]] || exit 1

python=$project/.venv/bin/python
source_dir=$project/src
install -d -o root -g root -m 0700 /run/t2-touchid "$STATE_DIR"
rm -f -- "$OUTPUT"
RAW=$(mktemp /run/t2-touchid/warm-identity.raw.XXXXXX)
SAFE=$(mktemp "$STATE_DIR/.warm-transition-identity.XXXXXX")

probe_port() {
  local port=$1
  [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]] || return 1
  timeout 20 flock --exclusive --timeout 10 --no-fork "$LOCK_FILE" \
    "$python" "$source_dir/bridge-xpc-probe.py" \
      --host "$host" --interface "$interface" --port "$port" \
      --initialize --identity-list --macos-user-id "$macos_user_id" \
      --timeout 5 >"$RAW"
}

port=
if [[ -r $PORT_FILE ]]; then
  candidate=$(<"$PORT_FILE")
  if probe_port "$candidate"; then
    port=$candidate
  fi
fi

deadline=$((SECONDS + 60))
while [[ -z $port && $SECONDS -lt $deadline ]]; do
  candidate=$("$python" "$source_dir/discover-biometric-port.py" \
    --host "$host" --interface "$interface" \
    --probe-timeout 0.2 --concurrency 256 2>/dev/null || true)
  if probe_port "$candidate"; then
    port=$candidate
    break
  fi
  sleep 1
done
[[ -n $port ]] || { echo "could not query the warm biometric service" >&2; exit 1; }

captured_at=$(date --utc +%Y-%m-%dT%H:%M:%SZ)
jq -e --arg captured_at "$captured_at" '
  select(.identity_list_reply.valid == true) |
  select(.identity_list_reply.status | type == "number") |
  select(
    ((.identity_record_count | type) == "number" and
      .identity_record_bytes_valid == true) or
    (.identity_list_reply.status == 0 and
      .identity_list_reply.output_length == null)
  ) |
  {
    schema_version: 1,
    captured_at: $captured_at,
    identity_list_reply: {
      valid: .identity_list_reply.valid,
      status: .identity_list_reply.status,
      status_hex: .identity_list_reply.status_hex,
      output_length: (.identity_list_reply.output_length // 0)
    },
    identity_record_count: (.identity_record_count // 0),
    identity_record_bytes_valid: (.identity_record_bytes_valid // true)
  }
' "$RAW" >"$SAFE"
[[ -s $SAFE ]] || { echo "privacy-safe warm result is empty" >&2; exit 1; }
chmod 0600 "$SAFE"
mv -f -- "$SAFE" "$OUTPUT"
SAFE=

port_tmp=$(mktemp "$STATE_DIR/.biometric-port.XXXXXX")
printf '%s\n' "$port" >"$port_tmp"
chmod 0600 "$port_tmp"
mv -f -- "$port_tmp" "$PORT_FILE"
logger --priority authpriv.info --tag t2-warm-identity \
  'captured privacy-safe pre-reset identity-list result'
