#!/bin/bash
# SPDX-License-Identifier: MIT
# Capture a redacted zero-to-one-completed-enrollment Catacomb fixture on macOS.
set -euo pipefail

fail() {
  echo "clean enrollment fixture failed: $1" >&2
  exit 1
}

[[ $(uname -s) == Darwin ]] || fail "this helper must run on macOS"
[[ $EUID -eq 0 ]] || fail "administrator privileges are required"
[[ $# -eq 0 ]] || fail "usage: sudo $0"
[[ -r /dev/tty && -w /dev/tty ]] || fail "an interactive terminal is required"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
validator="$script_dir/validate-current-macos-catacomb.py"
delta_tool="$script_dir/catacomb-identity-shape-delta.py"
[[ -f $validator && ! -L $validator ]] || fail "the Catacomb validator is unavailable"
[[ -f $delta_tool && ! -L $delta_tool ]] || fail "the shape-delta tool is unavailable"
python_bin=$(command -v python3) || fail "python3 is unavailable"
openssl_bin=$(command -v openssl) || fail "openssl is unavailable"

efi_device=/dev/disk0s1
efi_mount=/Volumes/EFI
certificate="$efi_mount/t2-touchid-keybag-transfer-cert.pem"
destination="$efi_mount/t2-touchid-catacomb-clean-single.cms"
destination_tmp="$efi_mount/.t2-touchid-catacomb-clean-single.cms.tmp.$$"
private_dir=""
daemon_pid=""

resume_daemon() {
  if [[ -n $daemon_pid ]]; then
    kill -CONT "$daemon_pid" 2>/dev/null || true
    daemon_pid=""
  fi
}

remove_private() {
  if [[ -n $private_dir && -d $private_dir ]]; then
    rm -f -- "$private_dir"/*
    rmdir -- "$private_dir"
    private_dir=""
  fi
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  resume_daemon
  remove_private || true
  rm -f -- "$destination_tmp"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

prompt() {
  printf '\n%s\nPress Enter here only after that step is complete.\n' "$1" >/dev/tty
  IFS= read -r _ </dev/tty || fail "interactive confirmation was interrupted"
}

snapshot() {
  label=$1
  archive="$private_dir/$label.tar.gz"
  validation="$private_dir/$label-validation.json"
  daemon_pids=$(pgrep -x biometrickitd || true)
  [[ $daemon_pids =~ ^[0-9]+$ ]] || fail "exactly one biometrickitd process is required"
  daemon_pid=$daemon_pids
  kill -STOP "$daemon_pid" || fail "biometrickitd could not be frozen"
  /usr/bin/tar -czf "$archive" -C /Library Catacomb \
    || fail "the $label Catacomb snapshot failed"
  chmod 600 "$archive"
  resume_daemon
  "$python_bin" "$validator" "$archive" --apple-user-id 501 >"$validation" \
    || fail "the $label Catacomb failed strict validation"
  chmod 600 "$validation"
}

require_count() {
  validation=$1
  relation=$2
  "$python_bin" - "$validation" "$relation" <<'PY' \
    || fail "the Catacomb identity count is not the required phase"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    result = json.load(stream)
count = result.get("identity_count")
valid = isinstance(count, int) and not isinstance(count, bool)
if sys.argv[2] == "nonempty":
    valid = valid and count > 0
elif sys.argv[2] == "empty":
    valid = valid and count == 0
else:
    valid = False
valid = valid and result.get("identifiers_redacted") is True
raise SystemExit(0 if valid else 1)
PY
}

if ! /sbin/mount | /usr/bin/grep -Fq "$efi_device on $efi_mount "; then
  [[ ! -e $efi_mount || -d $efi_mount ]] || fail "the EFI mount path is unsafe"
  mkdir -p "$efi_mount"
  if ! /sbin/mount_msdos "$efi_device" "$efi_mount" >/dev/null 2>&1; then
    /usr/bin/kmutil load -p /System/Library/Extensions/msdosfs.kext >/dev/null
    /sbin/mount_msdos "$efi_device" "$efi_mount" >/dev/null
  fi
fi
/sbin/mount | /usr/bin/grep -Fq "$efi_device on $efi_mount " \
  || fail "the expected EFI partition is not mounted"
[[ -f $certificate && ! -L $certificate ]] \
  || fail "the public transfer certificate is absent or unsafe"
[[ ! -L $destination ]] || fail "the encrypted destination is an unsafe symlink"
[[ -d /Library/Catacomb && ! -L /Library/Catacomb ]] \
  || fail "the macOS Catacomb directory is absent or unsafe"

umask 077
private_dir=$(mktemp -d /private/var/tmp/t2-clean-enrollment.XXXXXX) \
  || fail "a private temporary directory could not be created"
chmod 700 "$private_dir"

echo "This helper snapshots state only. You will delete and add the fingerprint in System Settings yourself."
snapshot starting
require_count "$private_dir/starting-validation.json" nonempty

prompt "In System Settings, remove every visible fingerprint, confirm the list is empty, then close System Settings."
snapshot empty
require_count "$private_dir/empty-validation.json" empty

prompt "In System Settings, add exactly ONE fingerprint and complete it. Do not start a second attempt; then close System Settings."
snapshot clean
require_count "$private_dir/clean-validation.json" nonempty

"$python_bin" "$delta_tool" \
  "$private_dir/starting.tar.gz" "$private_dir/empty.tar.gz" \
  --apple-user-id 501 >"$private_dir/removal-delta.json" \
  || fail "the removal transition could not be compared safely"
"$python_bin" "$delta_tool" \
  "$private_dir/empty.tar.gz" "$private_dir/clean.tar.gz" \
  --apple-user-id 501 >"$private_dir/addition-delta.json" \
  || fail "the clean enrollment transition could not be compared safely"
chmod 600 "$private_dir/removal-delta.json" "$private_dir/addition-delta.json"

"$python_bin" - \
  "$private_dir/starting-validation.json" \
  "$private_dir/empty-validation.json" \
  "$private_dir/clean-validation.json" \
  "$private_dir/removal-delta.json" \
  "$private_dir/addition-delta.json" \
  >"$private_dir/summary.json" <<'PY' \
  || fail "the clean enrollment transition is not internally consistent"
import json
import sys

values = []
for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict) or value.get("identifiers_redacted") is not True:
        raise SystemExit(1)
    values.append(value)
starting, empty, clean, removal, addition = values
starting_count = starting.get("identity_count")
empty_count = empty.get("identity_count")
clean_count = clean.get("identity_count")
valid = (
    isinstance(starting_count, int)
    and not isinstance(starting_count, bool)
    and starting_count > 0
    and empty_count == 0
    and isinstance(clean_count, int)
    and not isinstance(clean_count, bool)
    and clean_count > 0
    and removal.get("identity_records_added") == 0
    and removal.get("identity_records_removed") == starting_count
    and removal.get("after_identity_record_count") == 0
    and addition.get("before_identity_record_count") == 0
    and addition.get("after_identity_record_count") == clean_count
    and addition.get("identity_records_added") == clean_count
    and addition.get("identity_records_removed") == 0
)
if not valid:
    raise SystemExit(1)
summary = {
    "schema_version": 1,
    "starting_identity_record_count": starting_count,
    "empty_identity_record_count": empty_count,
    "clean_identity_record_count": clean_count,
    "clean_entity_number_count": clean.get("identity_entity_count"),
    "clean_entity_group_sizes": clean.get("identity_entity_group_sizes"),
    "clean_master_enrollment_count": clean.get("master_enrollment_count"),
    "clean_identity_records_added": addition.get("identity_records_added"),
    "clean_entity_number_count_delta": addition.get("entity_number_count_delta"),
    "clean_master_enrollment_count_delta": addition.get("master_enrollment_count_delta"),
    "clean_all_components_changed": addition.get("all_components_changed"),
    "one_completed_enrollment_between_empty_and_clean": True,
    "logical_finger_count_inferred": False,
    "identifiers_redacted": True,
    "raw_values_retained": False,
}
print(json.dumps(summary, sort_keys=True))
PY
chmod 600 "$private_dir/summary.json"

rm -f -- "$destination_tmp"
"$openssl_bin" cms -encrypt -binary -aes-256-cbc \
  -in "$private_dir/clean.tar.gz" \
  -outform DER \
  -out "$destination_tmp" \
  "$certificate" \
  || fail "CMS encryption failed"
chmod 600 "$destination_tmp"
"$openssl_bin" cms -cmsout -inform DER -in "$destination_tmp" -noout \
  >/dev/null || fail "CMS validation failed"
mv -f -- "$destination_tmp" "$destination"
/bin/sync

cms_bytes=$(stat -f '%z' "$destination") || fail "CMS size is unavailable"
[[ $cms_bytes =~ ^[1-9][0-9]*$ ]] || fail "the encrypted fixture is empty"
macos_build=$(sw_vers -buildVersion)
summary_line=$("$python_bin" - "$private_dir/summary.json" "$macos_build" "$cms_bytes" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    result = json.load(stream)
result.update(
    {
        "macos_build": sys.argv[2],
        "cms_bytes": int(sys.argv[3]),
        "cms_parse_valid": True,
        "plaintext_removed": True,
    }
)
print(json.dumps(result, sort_keys=True))
PY
)

remove_private || fail "private plaintext cleanup failed"
echo "$summary_line"
