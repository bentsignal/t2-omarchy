#!/usr/bin/env bash
set -euo pipefail

# Machine-specific, offline-only operation for the audited 2026-08-26 layout.
disk=/dev/nvme0n1
partition=/dev/nvme0n1p2
mapping=omarchy-resize
mountpoint=/mnt/omarchy-resize
expected_disk_guid=C9FB7A78-B04A-4B43-B8A9-26EA7F29987D
expected_luks_uuid=c63c47de-ab9b-4232-ba95-68f57ad5744c
expected_start=524544
expected_size=243751424
expected_sector_size=4096
expected_type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
btrfs_target=780G
new_partition_end=210721535
new_partition_size=210196992

die() { echo "ERROR: $*" >&2; exit 1; }
mode=${1:-}
[[ $mode == --audit || $mode == --apply ]] || die "usage: $0 --audit|--apply"
[[ -b $disk && -b $partition ]] || die "expected internal disk is absent"

sector_size=$(lsblk -dnro LOG-SEC "$disk")
disk_guid=$(lsblk -dnro PTUUID "$disk")
start_512=$(lsblk -dnro START "$partition")
start=$((start_512 * 512 / sector_size))
size_bytes=$(lsblk -bdnro SIZE "$partition")
size=$((size_bytes / sector_size))
type=$(lsblk -dnro PARTTYPE "$partition")
luks_uuid=$(lsblk -dnro UUID "$partition")

[[ $sector_size == "$expected_sector_size" ]] || die "sector-size mismatch: $sector_size"
[[ ${disk_guid^^} == "$expected_disk_guid" ]] || die "disk GUID mismatch: $disk_guid"
[[ $start == "$expected_start" && $size == "$expected_size" ]] ||
  die "partition geometry mismatch: start=$start size=$size"
[[ ${type^^} == "$expected_type" ]] || die "partition type mismatch: $type"
[[ $luks_uuid == "$expected_luks_uuid" ]] || die "LUKS UUID mismatch: $luks_uuid"

echo "Validated the exact backed-up Apple SSD layout."
echo "This will shrink Btrfs to $btrfs_target and leave 128 GiB for macOS."
[[ $mode == --audit ]] && exit 0
[[ $EUID -eq 0 ]] || die "run --apply as root from the Omarchy recovery USB"
[[ $(findmnt -rn -S "$partition" | wc -l) -eq 0 ]] || die "$partition is mounted"
[[ ! -e /dev/mapper/root ]] || die "installed root mapping is active; boot recovery media"
[[ ! -e /dev/mapper/$mapping ]] || die "temporary mapping already exists"
read -r -p "Type SHRINK-APPLE-SSD to continue: " confirmation
[[ $confirmation == SHRINK-APPLE-SSD ]] || die "confirmation did not match"

cryptsetup open "$partition" "$mapping"
cleanup() {
  mountpoint -q "$mountpoint" && umount "$mountpoint" || true
  [[ -e /dev/mapper/$mapping ]] && cryptsetup close "$mapping" || true
}
trap cleanup EXIT

mkdir -p "$mountpoint"
btrfs check --readonly "/dev/mapper/$mapping"
mount -o subvolid=5 "/dev/mapper/$mapping" "$mountpoint"
btrfs filesystem resize "$btrfs_target" "$mountpoint"
sync
umount "$mountpoint"
btrfs check --readonly "/dev/mapper/$mapping"
cryptsetup close "$mapping"

# Keep the start sector and every GPT attribute; change only partition 2's end.
parted --script "$disk" unit s resizepart 2 "${new_partition_end}s"
partprobe "$disk"
udevadm settle

actual_start_512=$(lsblk -dnro START "$partition")
actual_start=$((actual_start_512 * 512 / sector_size))
actual_size_bytes=$(lsblk -bdnro SIZE "$partition")
actual_size=$((actual_size_bytes / sector_size))
[[ $actual_start == "$expected_start" && $actual_size == "$new_partition_size" ]] ||
  die "post-resize geometry mismatch: start=$actual_start size=$actual_size"

cryptsetup open "$partition" "$mapping"
btrfs check --readonly "/dev/mapper/$mapping"
cryptsetup close "$mapping"
trap - EXIT

free_start=$((new_partition_end + 1))
echo "Verified. Unallocated macOS space begins at sector $free_start."
echo "Power off, disconnect backup/recovery USB disks, then use Internet Recovery."
