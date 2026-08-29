#!/usr/bin/env bash
set -euo pipefail

module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
module="$module_dir/t2sep_probe.ko"
device=/sys/bus/pci/devices/0000:04:00.2
confirmation=${1:-}
session_uid=${2:-}
probe_mode=
serial=
prompt_dir=
prompt_fifo=
prompt_fd_open=0
prompt_pid=

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || die "run as the desktop user; this wrapper uses passwordless sudo internally"
sudo -n true || die "passwordless sudo is unavailable"
case $confirmation in
  I_UNDERSTAND_ONE_PASSWORD_ATTEMPT) probe_mode=existing ;;
  I_UNDERSTAND_EPHEMERAL_KEYBAG_ATTEMPT) probe_mode=ephemeral ;;
  *) die "missing exact interactive confirmation" ;;
esac
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
  if [[ -n $prompt_pid ]] && kill -0 "$prompt_pid" 2>/dev/null; then
    kill "$prompt_pid" 2>/dev/null || true
    wait "$prompt_pid" 2>/dev/null || true
  fi
  if (( prompt_fd_open )); then
    exec 9>&- 9<&-
    prompt_fd_open=0
  fi
  [[ -d /sys/module/t2sep_probe ]] && sudo -n rmmod t2sep_probe || true
  if [[ -n $serial ]]; then
    keyctl revoke "$serial" 2>/dev/null || true
    keyctl unlink "$serial" @s 2>/dev/null || true
  fi
  if [[ -n $prompt_fifo ]]; then
    rm -f -- "$prompt_fifo"
  fi
  if [[ -n $prompt_dir ]]; then
    rmdir -- "$prompt_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "A new terminal will ask once for the macOS account password (UID $session_uid)." >&2
set +x
prompt_dir=$(mktemp -d)
prompt_fifo="$prompt_dir/key-serial"
mkfifo -m 600 "$prompt_fifo"
# Open both ends here so a failed prompt process cannot leave this wrapper
# blocked forever while opening the FIFO. The timed read below is then the
# sole wait for the desktop terminal to return a key serial.
exec 9<>"$prompt_fifo"
prompt_fd_open=1
xdg-terminal-exec "$module_dir/prompt-password-key.sh" "$prompt_fifo" &
prompt_pid=$!
IFS= read -r -t 130 serial <&9 || die "password prompt timed out or was closed"
exec 9>&- 9<&-
prompt_fd_open=0
wait "$prompt_pid" || die "password prompt terminal failed"
prompt_pid=
[[ $serial =~ ^[0-9]+$ ]] || die "temporary password key creation failed"

before=$(sudo -n journalctl -k --show-cursor -n 0 --no-pager | sed -n 's/^-- cursor: //p')
[[ -n $before ]] || die "could not obtain a fresh kernel-journal cursor"
module_args=(apple_start_cpu_probe=1 apple_start_with_msi=1
  apple_send_control_nop=1 password_key_serial="$serial"
  macos_session_uid="$session_uid")
if [[ $probe_mode == ephemeral ]]; then
  module_args+=(apple_probe_ephemeral_keybag_authorization=1
    ephemeral_keybag_confirmation=0x4550484b42414731)
else
  module_args+=(apple_probe_password_verification=1
    password_verification_confirmation=0x5041535356455249)
fi
set +e
sudo -n insmod "$module" "${module_args[@]}"
load_status=$?
set -e
if [[ -d /sys/module/t2sep_probe ]]; then
  sudo -n rmmod t2sep_probe
fi

log=$(sudo -n journalctl -k --after-cursor "$before" --no-pager)
printf '%s\n' "$log"
(( load_status == 0 )) || die "kernel probe returned status $load_status; transcript printed above"
if [[ $probe_mode == ephemeral ]]; then
  python3 "$module_dir/verify-ephemeral-keybag-authorization-log.py" <<<"$log" ||
    die "ephemeral-keybag transcript failed independent verification"
else
  python3 "$module_dir/verify-password-authorization-log.py" <<<"$log" ||
    die "password-authorization transcript failed independent verification"
fi
[[ ! -L $device/driver ]] || die "SEP remained bound after probe"
[[ ! -d /sys/module/t2sep_probe ]] || die "module remained loaded after probe"
trap - EXIT
cleanup
