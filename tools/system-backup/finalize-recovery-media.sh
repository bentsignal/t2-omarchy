#!/usr/bin/env bash
set -euo pipefail

backup_partition=/dev/sda1
expected_serial=NAA959T1
backup_root=/mnt/omarchy-backup
stamp=20260826T212118Z
source_bundle=/home/shawn/Downloads/recovery-media/t2-mbp16-audio-recovery.bundle
source_script=/home/shawn/t2-mbp16-audio-recovery/tools/system-backup/prepare-macos-space.sh

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run through pkexec or sudo"
[[ $(lsblk -dnro SERIAL /dev/sda | xargs) == "$expected_serial" ]] ||
  die "the pinned Seagate backup is not /dev/sda"
[[ $(blkid -s LABEL -o value "$backup_partition") == OMARCHY_BACKUP ]] ||
  die "backup filesystem label mismatch"
[[ -f $source_bundle && -f $source_script ]] || die "offline recovery files are missing"

mountpoint -q "$backup_root" || mount "$backup_partition" "$backup_root"
install -d -m 0755 "$backup_root/recovery-tools"
install -m 0644 "$source_bundle" "$backup_root/recovery-tools/"
install -m 0755 "$source_script" "$backup_root/recovery-tools/"

# Version 1 of the backup script accidentally hashed its own growing manifest.
# Remove only that known-unverifiable line; all payload lines remain intact.
manifest="$backup_root/metadata/$stamp/SHA256SUMS"
sed -i "\\|  metadata/$stamp/SHA256SUMS$|d" "$manifest"
sync

# The desktop automounter may have mounted the same filesystem a second time.
findmnt -rn -S "$backup_partition" -o TARGET | sort -r | while read -r target; do
  umount "$target"
done
echo "Offline recovery tools copied and Seagate backup safely unmounted."
