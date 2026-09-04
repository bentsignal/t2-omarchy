#!/usr/bin/env bash
set -euo pipefail
set +x

module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
module="$module_dir/t2sep_probe.ko"
device=/sys/bus/pci/devices/0000:04:00.2
credential_path=/sys/module/t2sep_probe/parameters/enrollment_credential
done_path=/sys/module/t2sep_probe/parameters/enrollment_done
confirmation=${1:-}
session_uid=${2:-}
interface=${3:-enp4s0f1u1}
serial=
prompt_dir=
prompt_fifo=
prompt_pid=
insmod_pid=
client_name=
client_confirmation=
catacomb_path=
global_input=
user_input=
authorize_policy=0
transactional=0

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || die "run as the desktop user"
sudo -n true || die "passwordless sudo is unavailable"
case $confirmation in
  I_UNDERSTAND_THIS_ONLY_READS_SKS_LOCK_STATE_WITH_AN_AUTHORIZED_BAG)
    client_name=authorized-sks-lock-state-client.py
    client_confirmation=$confirmation
    ;;
  I_UNDERSTAND_THIS_AUTHORIZES_ENROLLMENT_POLICY_WITHOUT_TOUCH)
    client_name=policy-authorization-no-touch-client.py
    client_confirmation=$confirmation
    authorize_policy=1
    ;;
  I_UNDERSTAND_THIS_CREATES_ONE_FINGERPRINT_IDENTITY)
    client_name=authorized-enrollment-client.py
    client_confirmation=$confirmation
    authorize_policy=1
    ;;
  I_UNDERSTAND_THIS_TRANSACTIONALLY_CREATES_ONE_FINGERPRINT_IDENTITY)
    client_name=transactional-enrollment-client.py
    client_confirmation=$confirmation
    authorize_policy=1
    transactional=1
    ;;
  I_UNDERSTAND_THIS_CREATES_ONE_USER_POLICY_AND_FINGERPRINT_IDENTITY)
    client_name=authorized-policy-enrollment-client.py
    client_confirmation=$confirmation
    catacomb_path="/var/lib/t2-touchid/$session_uid.catacomb"
    authorize_policy=1
    ;;
  I_UNDERSTAND_THIS_LOADS_RETAINED_MACOS_CATACOMBS_WITH_AN_AUTHORIZED_BAG)
    client_name=authorized-catacomb-load-client.py
    client_confirmation=$confirmation
    global_input=${4:-}
    user_input=${5:-}
    [[ $global_input = /* && $user_input = /* ]] ||
      die "authorized catacomb inputs must be absolute paths"
    ;;
  *) die "missing exact enrollment confirmation" ;;
esac
[[ $session_uid =~ ^[0-9]+$ && $session_uid -ge 10 && $session_uid -lt 2147483647 ]] ||
  die "macOS session UID must be explicit and supported"
[[ $interface =~ ^[[:alnum:]_.:-]+$ && -d /sys/class/net/$interface ]] ||
  die "network interface is missing or invalid"
[[ -f $module && -d $device ]] || die "module or SEP function is missing"
[[ $module -nt "$module_dir/t2sep_probe.c" ]] || die "kernel module is stale"
[[ ! -L $device/driver && ! -d /sys/module/t2sep_probe ]] ||
  die "SEP is busy or the probe module is already loaded"

python3 "$module_dir/biometric-connectivity-preflight.py" \
  --interface "$interface" \
  --confirm=I_UNDERSTAND_THIS_ONLY_QUERIES_THE_T2_BRIDGE_VERSION ||
  die "read-only BiometricKit preflight failed; password was not requested"

cleanup() {
  if [[ -n $prompt_pid ]] && kill -0 "$prompt_pid" 2>/dev/null; then
    kill "$prompt_pid" 2>/dev/null || true
    wait "$prompt_pid" 2>/dev/null || true
  fi
  if [[ -e $done_path ]]; then
    printf '1\n' | sudo -n tee "$done_path" >/dev/null 2>&1 || true
  fi
  if [[ -n $insmod_pid ]]; then
    wait "$insmod_pid" 2>/dev/null || true
  fi
  [[ -d /sys/module/t2sep_probe ]] && sudo -n rmmod t2sep_probe || true
  if [[ -n $serial ]]; then
    keyctl revoke "$serial" 2>/dev/null || true
    keyctl unlink "$serial" @s 2>/dev/null || true
  fi
  [[ -n $prompt_fifo ]] && rm -f -- "$prompt_fifo"
  [[ -n $prompt_dir ]] && rmdir -- "$prompt_dir" 2>/dev/null || true
}
trap cleanup EXIT

echo "A separate terminal will ask once for the macOS account password." >&2
prompt_dir=$(mktemp -d)
prompt_fifo="$prompt_dir/key-serial"
mkfifo -m 600 "$prompt_fifo"
exec 9<>"$prompt_fifo"
if command -v ghostty >/dev/null 2>&1; then
  # Force a distinct GTK process/window so a singleton on another workspace
  # cannot hide the one-shot password prompt.
  ghostty --gtk-single-instance=false -e \
    "$module_dir/prompt-password-key.sh" "$prompt_fifo" &
else
  xdg-terminal-exec "$module_dir/prompt-password-key.sh" "$prompt_fifo" &
fi
prompt_pid=$!
IFS= read -r -t 130 serial <&9 || die "password prompt timed out or was closed"
exec 9>&- 9<&-
wait "$prompt_pid" || die "password prompt terminal failed"
prompt_pid=
[[ $serial =~ ^[0-9]+$ ]] || die "temporary password key creation failed"

before=$(sudo -n journalctl -k --show-cursor -n 0 --no-pager |
  sed -n 's/^-- cursor: //p')
[[ -n $before ]] || die "could not obtain a fresh kernel-journal cursor"

sudo -n insmod "$module" apple_start_cpu_probe=1 apple_start_with_msi=1 \
  apple_send_control_nop=1 password_key_serial="$serial" \
  macos_session_uid="$session_uid" \
  apple_probe_authorized_enrollment_handoff=1 \
  apple_authorize_enrollment_policy="$authorize_policy" \
  authorized_enrollment_confirmation=0x41555448454e5231 &
insmod_pid=$!

ready=0
for _ in $(seq 1 200); do
  if sudo -n journalctl -k --after-cursor "$before" --no-pager 2>/dev/null |
      grep -q 'authorized enrollment handoff ready:'; then
    ready=1
    break
  fi
  kill -0 "$insmod_pid" 2>/dev/null || break
  sleep 0.1
done
(( ready )) || die "authorized credential did not become ready"

echo "Authorized BiometricKit operation is starting." >&2
set +e
if (( transactional )); then
  sudo -n cat "$credential_path" |
    sudo -n python3 "$module_dir/$client_name" \
      --user-id "$session_uid" --interface "$interface" \
      --state-root /var/lib/t2-touchid \
      --confirm="$client_confirmation"
  client_status=${PIPESTATUS[1]}
elif [[ -n $global_input ]]; then
  sudo -n cat "$credential_path" |
    python3 "$module_dir/$client_name" \
      --user-id "$session_uid" --interface "$interface" \
      --global-path "$global_input" --path "$user_input" \
      --confirm="$client_confirmation"
  client_status=${PIPESTATUS[1]}
elif [[ -n $catacomb_path ]]; then
  sudo -n cat "$credential_path" |
    sudo -n python3 "$module_dir/$client_name" \
      --user-id "$session_uid" --interface "$interface" \
      --catacomb-output "$catacomb_path" --confirm="$client_confirmation"
  client_status=${PIPESTATUS[1]}
else
  sudo -n cat "$credential_path" |
    python3 "$module_dir/$client_name" \
      --user-id "$session_uid" --interface "$interface" \
      --confirm="$client_confirmation"
  client_status=${PIPESTATUS[1]}
fi
set -e

printf '1\n' | sudo -n tee "$done_path" >/dev/null
set +e
wait "$insmod_pid"
load_status=$?
set -e
insmod_pid=
[[ -d /sys/module/t2sep_probe ]] && sudo -n rmmod t2sep_probe

log=$(sudo -n journalctl -k --after-cursor "$before" --no-pager)
printf '%s\n' "$log"
verifier_args=()
(( authorize_policy )) && verifier_args+=(--require-enrollment-policy)
python3 "$module_dir/verify-authorized-enrollment-handoff-log.py" \
  "${verifier_args[@]}" <<<"$log" ||
  die "kernel handoff transcript failed independent verification"
(( load_status == 0 )) || die "kernel handoff returned status $load_status"
(( client_status == 0 )) || die "BiometricKit enrollment client returned status $client_status"
[[ ! -L $device/driver && ! -d /sys/module/t2sep_probe ]] ||
  die "SEP cleanup was incomplete"
trap - EXIT
cleanup
