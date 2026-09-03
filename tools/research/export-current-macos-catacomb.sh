#!/bin/bash
# SPDX-License-Identifier: MIT
# Export the current macOS Catacomb to an encrypted EFI handoff artifact.
set -euo pipefail

usage() {
  echo "Usage: sudo $0" >&2
  exit 2
}

fail() {
  echo "current Catacomb transfer failed: $1" >&2
  exit 1
}

[[ $(uname -s) == Darwin ]] || fail "this exporter must run on macOS"
[[ $EUID -eq 0 ]] || fail "administrator privileges are required"
[[ $# -eq 0 ]] || usage

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
checker="$script_dir/validate-current-macos-catacomb.py"
[[ -f $checker && ! -L $checker ]] || fail "the in-repo Catacomb validator is unavailable"
python_bin=$(command -v python3) || fail "python3 is unavailable"
openssl_bin=$(command -v openssl) || fail "openssl is unavailable"

efi_device=/dev/disk0s1
efi_mount=/Volumes/EFI
certificate="$efi_mount/t2-touchid-keybag-transfer-cert.pem"
destination="$efi_mount/t2-touchid-catacomb-current.cms"
destination_tmp="$efi_mount/.t2-touchid-catacomb-current.cms.tmp.$$"
private_dir=""
daemon_pid=""

resume_daemon() {
  if [[ -n $daemon_pid ]]; then
    kill -CONT "$daemon_pid" 2>/dev/null || true
    daemon_pid=""
  fi
}

remove_private() {
  if [[ -n $private_dir ]]; then
    rm -f -- "$private_dir/current-catacomb.tar.gz" \
      "$private_dir/validation.json" || return 1
    rmdir -- "$private_dir" 2>/dev/null || return 1
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

if ! /sbin/mount | /usr/bin/grep -Fq "$efi_device on $efi_mount "; then
  [[ ! -e $efi_mount || -d $efi_mount ]] || fail "the EFI mount path is unsafe"
  mkdir -p "$efi_mount"
  if ! /sbin/mount_msdos "$efi_device" "$efi_mount" >/dev/null 2>&1; then
    /usr/bin/kmutil load -p /System/Library/Extensions/msdosfs.kext >/dev/null
    /sbin/mount_msdos "$efi_device" "$efi_mount" >/dev/null
  fi
fi
/sbin/mount | /usr/bin/grep -Fq "$efi_device on $efi_mount " \
  || fail "the expected EFI partition is not mounted at /Volumes/EFI"
[[ -f $certificate && ! -L $certificate ]] \
  || fail "the public EFI transfer certificate is absent or unsafe"
[[ ! -L $destination ]] \
  || fail "the encrypted destination is an unsafe symbolic link"
[[ -d /Library/Catacomb && ! -L /Library/Catacomb ]] \
  || fail "the macOS Catacomb directory is absent or unsafe"

umask 077
private_dir=$(mktemp -d /private/var/tmp/t2-current-catacomb.XXXXXX) \
  || fail "a private temporary directory could not be created"
chmod 700 "$private_dir"
archive="$private_dir/current-catacomb.tar.gz"
validation="$private_dir/validation.json"

daemon_pids=$(pgrep -x biometrickitd || true)
[[ $daemon_pids =~ ^[0-9]+$ ]] \
  || fail "exactly one running biometrickitd process is required"
daemon_pid=$daemon_pids
kill -STOP "$daemon_pid" || fail "biometrickitd could not be frozen"

/usr/bin/tar -czf "$archive" -C /Library Catacomb \
  || fail "the private Catacomb snapshot failed"
chmod 600 "$archive"
resume_daemon

"$python_bin" "$checker" "$archive" --apple-user-id 501 >"$validation" \
  || fail "privacy-safe semantic validation failed"
chmod 600 "$validation"
"$python_bin" - "$validation" <<'PY' \
  || fail "the Catacomb does not satisfy the cold-restore gate"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    result = json.load(stream)
identity_count = result.get("identity_count")
required_true = (
    "schemas_valid",
    "foundation_readback",
    "semantic_round_trip_equal",
    "secure_envelopes_valid",
    "account_and_keybag_bindings_present",
    "identifiers_redacted",
)
valid = (
    result.get("component_count") == 3
    and isinstance(identity_count, int)
    and not isinstance(identity_count, bool)
    and identity_count > 0
    and all(result.get(name) is True for name in required_true)
)
raise SystemExit(0 if valid else 1)
PY

rm -f -- "$destination_tmp"
"$openssl_bin" cms -encrypt -binary -aes-256-cbc \
  -in "$archive" \
  -outform DER \
  -out "$destination_tmp" \
  "$certificate" \
  || fail "CMS encryption failed"
chmod 600 "$destination_tmp"
"$openssl_bin" cms -cmsout -inform DER -in "$destination_tmp" -noout \
  >/dev/null || fail "CMS parse validation failed"
mv -f -- "$destination_tmp" "$destination"
/bin/sync

cms_bytes=$(stat -f '%z' "$destination") \
  || fail "the encrypted artifact size is unavailable"
[[ $cms_bytes =~ ^[1-9][0-9]*$ ]] || fail "the encrypted artifact is empty"
macos_build=$(sw_vers -buildVersion)

remove_private || fail "private plaintext cleanup failed"
echo "current Catacomb transfer complete: macos_build=$macos_build validator=in-repo cms_bytes=$cms_bytes components=exact identity_nonzero=yes cms_parse=yes plaintext_removed=yes"
