# Backup and temporary macOS dual boot

This document records the machine-specific plan for adding a small macOS
installation without reinstalling the existing encrypted Omarchy system. It is
not a generic unattended partitioning recipe: shrinking the live system disk
must be done from recovery media after a verified backup.

## Confirmed starting layout (2026-08-26)

- Internal disk: `/dev/nvme0n1`, Apple SSD AP1024N, about 1 TB
- `/dev/nvme0n1p1`: 2 GiB FAT32 EFI system partition, mounted at `/boot`
- `/dev/nvme0n1p2`: LUKS2 container occupying the remainder of the disk
- `/dev/mapper/root`: Btrfs with `@`, `@home`, `@log`, and `@pkg`
- Used Btrfs space at the audit: approximately 46 GiB
- Backup disk: USB Seagate Expansion, serial `NAA959T1`, about 1 TB

The Omarchy Mac installer officially assumes the whole disk. That is an
installer/support limitation, not proof that Intel T2 hardware cannot dual
boot. Do not rerun the full-disk Omarchy installer after adding macOS.

## Backup

The scripts in `tools/system-backup/` deliberately pin both source and target
disk identities. The format script destroys the old Omarchy installer image on
the external disk and creates a GPT/Btrfs backup disk. The backup script then:

1. creates read-only Btrfs snapshots of all four Omarchy subvolumes;
2. transfers them with `btrfs send/receive`;
3. copies the EFI system partition as both files and a raw image;
4. saves the LUKS header, GPT metadata, package lists, and system inventory;
5. records checksums and runs a read-only Btrfs scrub.

The snapshots provide a restore point, but the original disk remains the only
bootable copy until a restore is tested. Keep the backup disk disconnected
during macOS installation to prevent selecting it accidentally.

## Planned disk change

Target approximately 120 GiB of unallocated space for macOS. The safe order,
from T2-capable Linux recovery media, is:

1. check the Btrfs filesystem;
2. shrink Btrfs while the LUKS mapping is open;
3. close the mapping;
4. reduce the LUKS partition end, leaving a conservative margin;
5. reopen and verify LUKS and Btrfs before invoking Apple Recovery.

Exact sector boundaries must be computed from the live recovery environment.
Do not blindly paste boundaries from this document. LUKS2 metadata/header
backup does not contain filesystem data and is not a substitute for the Btrfs
backup.

In Internet Recovery, create/install macOS only in the newly unallocated tail
space. Never erase the physical Apple SSD or the Linux partitions. Keep the
macOS/APFS allocation until Touch ID works from Linux: Apple initialization is
expected to create the machine-specific xART/GigaLocker state required by the
SEP biometric endpoint.

After installation, inspect and record the new GPT before considering any
reclamation. Removing the whole Apple/APFS structure may also remove the xART
state that this exercise is intended to create.
