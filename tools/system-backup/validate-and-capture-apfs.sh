#!/usr/bin/env bash
set -euo pipefail

backup_disk=/dev/sda
backup_partition=/dev/sda1
expected_serial=NAA959T1
expected_uuid=2a922a39-ee48-4b12-8e6f-3c3a69b154a5
backup_mount=/run/media/shawn/OMARCHY_BACKUP
capture=/home/shawn/t2-mbp16-audio-recovery/tools/system-backup/capture-enrolled-apfs.sh

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run through pkexec or sudo"
[[ $(lsblk -dnro SERIAL "$backup_disk" | xargs) == "$expected_serial" ]] ||
  die "backup serial mismatch"
[[ $(lsblk -dnro UUID "$backup_partition") == "$expected_uuid" ]] ||
  die "backup filesystem UUID mismatch"
[[ $(findmnt -rn -S "$backup_partition" -o TARGET) == "$backup_mount" ]] ||
  die "backup mount mismatch"

usb_path=$(udevadm info -q path -p /sys/class/block/sda)
[[ $usb_path == *'/usb4/4-1/4-1.3/'* ]] ||
  die "Seagate is not on the validated Thunderbolt-hub path: $usb_path"

echo "Running read-only Btrfs scrub before APFS capture"
before=$(journalctl -k --show-cursor -n 0 --no-pager | sed -n 's/^-- cursor: //p')
btrfs scrub start -B -r "$backup_mount"

recent_errors=$(journalctl -k --after-cursor "$before" --no-pager |
  grep -Eic 'uas_eh_|reset SuperSpeed|I/O error, dev sda|device offline error, dev sda' || true)
[[ $recent_errors -eq 0 ]] || die "new USB/storage errors appeared during scrub"

echo "Backup scrub and transport validation passed; starting APFS baseline"
exec "$capture"
