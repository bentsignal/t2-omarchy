#!/usr/bin/env bash
set -euo pipefail

module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
module="$module_dir/t2sep_probe.ko"
device=/sys/bus/pci/devices/0000:04:00.2
confirmation=${1:-}
session_uid=${2:-}
serial=

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run through pkexec or sudo"
[[ $confirmation == I_UNDERSTAND_ONE_PASSWORD_ATTEMPT ]] ||
  die "missing exact interactive confirmation"
[[ $session_uid =~ ^[0-9]+$ && $session_uid -ge 10 && $session_uid -lt 2147483647 ]] ||
  die "macOS session UID must be explicit and in the supported range"
[[ -f $module && -d $device ]] || die "module or SEP PCI function is missing"
[[ $module -nt "$module_dir/t2sep_probe.c" &&
   $module -nt "$module_dir/Makefile" ]] ||
  die "kernel module is stale; rebuild it before touching hardware"
[[ $(cat /sys/class/dmi/id/product_name) == MacBookPro16,1 ]] || die "unsupported model"
[[ $(cat "$device/vendor") == 0x106b && $(cat "$device/device") == 0x1802 ]] ||
  die "SEP PCI identity mismatch"
[[ ! -L $device/driver ]] || die "SEP PCI function already has a driver"
[[ ! -d /sys/module/t2sep_probe ]] || die "t2sep_probe is already loaded"

cleanup() {
  [[ -d /sys/module/t2sep_probe ]] && rmmod t2sep_probe || true
  if [[ -n $serial ]]; then
    keyctl revoke "$serial" 2>/dev/null || true
    keyctl unlink "$serial" @s 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "A hidden prompt will ask once for the macOS account password (UID $session_uid)." >&2
set +x
serial=$(systemd-ask-password --echo=no --timeout=120 -n \
  "Enter the macOS account password for one T2 verification attempt:" |
  keyctl padd user "t2sep-password-$$" @s)
[[ $serial =~ ^[0-9]+$ ]] || die "temporary password key creation failed"

before=$(journalctl -k --show-cursor -n 0 --no-pager | sed -n 's/^-- cursor: //p')
[[ -n $before ]] || die "could not obtain a fresh kernel-journal cursor"
insmod "$module" apple_start_cpu_probe=1 apple_start_with_msi=1 \
  apple_send_control_nop=1 apple_probe_password_verification=1 \
  password_verification_confirmation=0x5041535356455249 \
  password_key_serial="$serial" macos_session_uid="$session_uid"
rmmod t2sep_probe

log=$(journalctl -k --after-cursor "$before" --no-pager)
printf '%s\n' "$log"
python3 "$module_dir/verify-password-authorization-log.py" <<<"$log" ||
  die "password-authorization transcript failed independent verification"
[[ ! -L $device/driver ]] || die "SEP remained bound after probe"
[[ ! -d /sys/module/t2sep_probe ]] || die "module remained loaded after probe"
trap - EXIT
cleanup
