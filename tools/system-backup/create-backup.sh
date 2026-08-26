#!/usr/bin/env bash
set -euo pipefail

source_disk=/dev/nvme0n1
source_efi=/dev/nvme0n1p1
source_luks=/dev/nvme0n1p2
source_mapping=/dev/mapper/root
target_partition=/dev/sda1
target_root=/mnt/omarchy-backup
expected_target_serial=NAA959T1
stamp=$(date -u +%Y%m%dT%H%M%SZ)
top=/mnt/omarchy-btrfs-top

[[ $EUID -eq 0 ]] || { echo "Run through pkexec or sudo." >&2; exit 1; }
[[ $(lsblk -dnro SERIAL /dev/sda | xargs) == "$expected_target_serial" ]] || {
  echo "Refusing: /dev/sda is not the pinned Seagate backup disk" >&2
  exit 1
}
[[ $(blkid -s LABEL -o value "$target_partition") == OMARCHY_BACKUP ]] || {
  echo "Refusing: backup filesystem label is missing" >&2
  exit 1
}
[[ -b $source_disk && -b $source_efi && -b $source_luks && -b $source_mapping ]] || {
  echo "Expected internal Omarchy block devices are unavailable" >&2
  exit 1
}

mkdir -p "$target_root" "$top"
mountpoint -q "$target_root" || mount "$target_partition" "$target_root"
mountpoint -q "$top" || mount -o subvolid=5 "$source_mapping" "$top"
mkdir -p "$target_root/snapshots/$stamp" "$target_root/metadata/$stamp" "$target_root/efi-files/$stamp"

cleanup() {
  for subvol in @ @home @log @pkg; do
    [[ -d "$top/.backup-$stamp-$subvol" ]] && btrfs subvolume delete "$top/.backup-$stamp-$subvol" || true
  done
  mountpoint -q "$top" && umount "$top" || true
}
trap cleanup EXIT

for subvol in @ @home @log @pkg; do
  snap="$top/.backup-$stamp-$subvol"
  btrfs subvolume snapshot -r "$top/$subvol" "$snap"
  btrfs send "$snap" | btrfs receive "$target_root/snapshots/$stamp"
done

meta="$target_root/metadata/$stamp"
rsync -aHAX --numeric-ids /boot/ "$target_root/efi-files/$stamp/"
dd if="$source_efi" of="$meta/efi-partition.img" bs=16M status=progress conv=fsync
cryptsetup luksHeaderBackup "$source_luks" --header-backup-file "$meta/nvme0n1p2-luks-header.img"
sfdisk --dump "$source_disk" > "$meta/nvme0n1.sfdisk"
lsblk -e7 -O > "$meta/lsblk.txt"
blkid > "$meta/blkid.txt"
findmnt -R / > "$meta/findmnt.txt"
btrfs filesystem usage -T / > "$meta/btrfs-usage.txt"
btrfs subvolume list -ap "$top" > "$meta/btrfs-subvolumes.txt"
pacman -Qqe > "$meta/packages-explicit.txt"
pacman -Qqm > "$meta/packages-foreign.txt"
uname -a > "$meta/uname.txt"
cp -a /etc/fstab "$meta/fstab"
[[ -f /etc/crypttab ]] && cp -a /etc/crypttab "$meta/crypttab"

sync
btrfs scrub start -B -r "$target_root"
(
  cd "$target_root"
  find "snapshots/$stamp" "metadata/$stamp" "efi-files/$stamp" -type f -print0 |
    sort -z | xargs -0 sha256sum
) > "$target_root/metadata/$stamp/SHA256SUMS"
sync
echo "$stamp" > "$target_root/LATEST"
echo "Backup completed: $target_root ($stamp)"
