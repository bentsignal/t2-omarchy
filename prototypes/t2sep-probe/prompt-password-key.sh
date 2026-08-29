#!/usr/bin/env bash
set -euo pipefail
set +x

fifo=${1:-}
[[ -p $fifo ]] || { echo "secure prompt channel is missing" >&2; exit 1; }

serial=$(systemd-ask-password --echo=no --timeout=120 -n \
  "Enter the macOS account password for one T2 verification attempt:" |
  keyctl padd user "t2sep-password-$$" @s)
[[ $serial =~ ^[0-9]+$ ]] || { echo "temporary key creation failed" >&2; exit 1; }
printf '%s\n' "$serial" >"$fifo"
