#!/usr/bin/env bash
set -euo pipefail

source_disk=/dev/nvme0n1
source_apfs=/dev/nvme0n1p3
expected_apfs_uuid=b673d4d8-c2b7-4c15-8e58-268ade21a855
expected_apfs_partuuid=a0aeaaa2-eb54-41f5-bedb-cbf6055b8b43
expected_apfs_size=137440149504
backup_disk=/dev/sda
backup_partition=/dev/sda1
expected_backup_serial=NAA959T1
expected_backup_uuid=2a922a39-ee48-4b12-8e6f-3c3a69b154a5
backup_mount=/run/media/shawn/OMARCHY_BACKUP
stamp=20260827-post-enrollment
destination="$backup_mount/apfs-baselines/$stamp"
image="$destination/nvme0n1p3.apfs.img"
partial="$image.partial"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run through pkexec or sudo"
[[ -b $source_disk && -b $source_apfs && -b $backup_disk && -b $backup_partition ]] ||
  die "an expected block device is missing"
[[ $(lsblk -dnro SERIAL "$backup_disk" | xargs) == "$expected_backup_serial" ]] ||
  die "backup disk serial mismatch"
[[ $(lsblk -dnro UUID "$backup_partition") == "$expected_backup_uuid" ]] ||
  die "backup filesystem UUID mismatch"
[[ $(lsblk -dnro UUID "$source_apfs") == "$expected_apfs_uuid" ]] ||
  die "APFS UUID mismatch"
[[ $(lsblk -dnro PARTUUID "$source_apfs") == "$expected_apfs_partuuid" ]] ||
  die "APFS PARTUUID mismatch"
[[ $(blockdev --getsize64 "$source_apfs") == "$expected_apfs_size" ]] ||
  die "APFS size mismatch"
[[ $(findmnt -rn -S "$source_apfs" | wc -l) -eq 0 ]] || die "APFS is mounted in Linux"
[[ $(findmnt -rn -S "$backup_partition" -o TARGET) == "$backup_mount" ]] ||
  die "backup is not mounted at the expected path"
mount_options=$(findmnt -rn -S "$backup_partition" -o OPTIONS)
[[ ,$mount_options, == *,rw,* ]] || die "backup filesystem is not mounted read-write"
[[ $(df -B1 --output=avail "$backup_mount" | tail -1) -gt 150000000000 ]] ||
  die "backup has insufficient free space"
[[ ! -e $image && ! -e $partial ]] || die "baseline or partial image already exists"

mkdir -p "$destination"
sfdisk --dump "$source_disk" > "$destination/nvme0n1.sfdisk"
lsblk -e7 -O > "$destination/lsblk.txt"
blkid > "$destination/blkid.txt"
efibootmgr -v > "$destination/efibootmgr.txt"

cleanup() {
  [[ -e $partial ]] && rm -f -- "$partial"
}
trap cleanup EXIT

echo "Hashing the enrolled APFS source"
sha256sum "$source_apfs" | awk '{print $1}' > "$destination/source.sha256"

echo "Capturing $expected_apfs_size APFS bytes sparsely to $image"
dd if="$source_apfs" of="$partial" bs=16M iflag=fullblock conv=sparse,fsync status=progress
mv -- "$partial" "$image"
sync

echo "Verifying saved APFS image"
sha256sum "$image" | awk '{print $1}' > "$destination/image.sha256"
cmp -s "$destination/source.sha256" "$destination/image.sha256" ||
  die "source and saved-image SHA-256 values differ"

sync
trap - EXIT
echo "Verified APFS baseline: $(cat "$destination/image.sha256")"
