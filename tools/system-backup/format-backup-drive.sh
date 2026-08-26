#!/usr/bin/env bash
set -euo pipefail

target=/dev/sda
expected_model="Expansion"
expected_serial="NAA959T1"
expected_min_bytes=900000000000

[[ $EUID -eq 0 ]] || { echo "Run through pkexec or sudo." >&2; exit 1; }
[[ -b $target ]] || { echo "$target is not a block device" >&2; exit 1; }

model=$(lsblk -dnro MODEL "$target" | sed 's/[[:space:]]*$//')
serial=$(lsblk -dnro SERIAL "$target" | sed 's/[[:space:]]*$//')
transport=$(lsblk -dnro TRAN "$target")
size=$(blockdev --getsize64 "$target")

[[ $model == "$expected_model" && $serial == "$expected_serial" ]] || {
  echo "Refusing: identity mismatch for $target ($model / $serial)" >&2
  exit 1
}
[[ $transport == usb && $size -ge $expected_min_bytes ]] || {
  echo "Refusing: target is not the expected approximately 1 TB USB disk" >&2
  exit 1
}
findmnt -rn -S /dev/nvme0n1 >/dev/null && true

echo "Formatting ONLY $target: $model, serial $serial, $size bytes"
umount "${target}1" 2>/dev/null || true
umount "${target}2" 2>/dev/null || true
wipefs --all "$target"
parted --script "$target" mklabel gpt mkpart OMARCHY_BACKUP btrfs 1MiB 100%
partprobe "$target"
udevadm settle
mkfs.btrfs -f -L OMARCHY_BACKUP "${target}1"
mkdir -p /mnt/omarchy-backup
mount "${target}1" /mnt/omarchy-backup
mkdir -p /mnt/omarchy-backup/{snapshots,metadata,efi-files}
sync
echo "Backup disk ready at /mnt/omarchy-backup"
