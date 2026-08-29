#!/usr/bin/env bash
set -euo pipefail

module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
module="$module_dir/t2sep_probe.ko"
device=/sys/bus/pci/devices/0000:04:00.2
endpoint=${1:-}
confirmation=${2:-}

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run through pkexec or sudo"
[[ $endpoint == 7 || $endpoint == 10 ]] || die "endpoint must be 7 (AKS) or 10 (ACM)"
[[ $confirmation == I_UNDERSTAND_FIXED_CREDENTIAL_OOL_CAPTURE ]] ||
  die "missing exact interactive confirmation"
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
}
trap cleanup EXIT

before=$(journalctl -k --show-cursor -n 0 --no-pager | sed -n 's/^-- cursor: //p')
[[ -n $before ]] || die "could not obtain a fresh kernel-journal cursor"
insmod "$module" apple_start_cpu_probe=1 apple_start_with_msi=1 \
  apple_send_control_nop=1 apple_capture_credential_ool_acks=1 \
  credential_endpoint="$endpoint" credential_ool_confirmation=0x435245444f4f4c41
rmmod t2sep_probe
trap - EXIT

log=$(journalctl -k --after-cursor "$before" --no-pager)
printf '%s\n' "$log"
python3 "$module_dir/verify-credential-ool-log.py" "$endpoint" <<<"$log" ||
  die "credential OOL transcript failed independent verification"
[[ ! -L $device/driver ]] || die "SEP remained bound after probe"
[[ ! -d /sys/module/t2sep_probe ]] || die "module remained loaded after probe"
