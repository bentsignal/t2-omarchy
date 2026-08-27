# Live macOS dual-boot resize handoff

Updated: 2026-08-27

This is a live recovery handoff for Codex. The machine is currently booted from the Omarchy recovery USB in an ArchISO TTY as root. This is a high-risk offline disk resize. Do not improvise destructive disk operations. Independently verify current state before any write.

## Goal

Shrink the existing encrypted Omarchy/Linux installation, leave exactly 128 GiB unallocated at the end of the internal SSD, boot and verify Linux, then install a small macOS system only into that free tail space. macOS is needed to initialize Touch ID machine-specific xART/GigaLocker state for Linux Touch ID development.

Do NOT install macOS until Linux has booted successfully after the resize.

## Hard safety rules

- Internal Apple SSD is expected at `/dev/nvme0n1`, but verify it before every destructive action.
- Never erase or format the physical Apple SSD.
- Never run the Omarchy installer against the internal SSD.
- Never modify the Linux EFI partition unnecessarily.
- Never modify the Seagate backup filesystem unnecessarily. It is currently mounted read-only.
- Never assume USB `/dev/sdX` names. Identify by model, serial, filesystem label, UUID, and capacity.
- If any identifier or geometry differs from this document, stop rather than adapting automatically.
- The intended resize geometry is machine-specific and already audited. Do not invent different target boundaries.
- Preserve the Seagate backup and SanDisk recovery media.

## Machine

- MacBook Pro 16-inch 2019, `MacBookPro16,1`, Intel + Apple T2.
- Recovery environment: Omarchy recovery USB, kernel banner observed as `Omarchy 7.1.8-arch1-Watanare-T2-3-t2`.
- Live environment currently accessed through TTY3 as `root`.

## Internal SSD identity and ORIGINAL GPT geometry

- Disk: `/dev/nvme0n1`
- Model: `APPLE SSD AP1024N`
- Capacity: about 1 TB / 931.8 GiB
- Logical/physical sector size: 4096/4096 bytes
- Total native sectors: `244276265`
- GPT disk GUID: `C9FB7A78-B04A-4B43-B8A9-26EA7F29987D`

Partition 1:
- `/dev/nvme0n1p1`
- 2 GiB FAT32 EFI
- Native start sector: 256
- Native end sector: 524543
- UUID: `CF7D-695E`

Partition 2:
- `/dev/nvme0n1p2`
- LUKS2
- LUKS UUID: `c63c47de-ab9b-4232-ba95-68f57ad5744c`
- Native start sector: `524544`
- ORIGINAL native end sector: `244275967`
- ORIGINAL size: `243751424` native 4096-byte sectors
- GPT type UUID: `4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709`

Unlocked filesystem:
- Btrfs UUID: `c0892194-86a3-43d9-8246-eb7d1b19ef57`
- Subvolumes: `@`, `@home`, `@log`, `@pkg`

## Backup

External Seagate Expansion 1 TB:
- Serial: `NAA959T1`
- Btrfs label: `OMARCHY_BACKUP`
- Btrfs UUID: `2a922a39-ee48-4b12-8e6f-3c3a69b154a5`
- Backup snapshot: `20260826T212118Z`
- Contains read-only snapshots of all four Btrfs subvolumes, raw 2 GiB EFI image + file copy, 16 MiB LUKS2 header backup, GPT/sfdisk metadata, package/filesystem/mount inventories, SHA-256 manifest.
- Prior Btrfs scrub checked 40.61 GiB and reported no errors.

During this recovery boot the Seagate only appeared when connected before boot. It is currently `/dev/sda`, partition `/dev/sda1`, identified by serial `NAA959T1`, label `OMARCHY_BACKUP`, UUID above. It was mounted read-only at `/mnt/backup` and `findmnt` confirmed `ro`.

Do not rely on `/dev/sda`; re-identify it if needed.

## Recovery USB

32 GB SanDisk Cruzer Fit:
- Serial: `4C530010630724110334`
- Official Omarchy 4.0.1 ISO
- ISO SHA-256 previously fully read-back verified: `69cbb4e10d98ad831c3c9f245b5757a9d1fedfd0c9592780e977d6f950dea8c3`

During current boot it is `/dev/sdb`, but do not rely on that name.

Important incident: on an earlier recovery boot, the live SquashFS began producing `/dev/loop0` I/O and SQUASHFS read errors, causing binaries such as `fdisk` and `sgdisk` to fail to execute. The machine was powered off, the SanDisk reseated, and recovery rebooted. Current boot has repeatedly been checked with:

`dmesg | grep -iE 'squashfs error|I/O error.*loop0' | tail -20`

and has remained clean. Check again before any destructive action.

## Audited resize script

Original backed-up script:
- Backup path: `/mnt/backup/recovery-tools/prepare-macos-space.sh`
- Copied to: `/root/prepare-macos-space.sh`
- Both copies were SHA-256 checked and were identical.
- SHA-256 observed: `092987642bf878f1d577beb79ab10abd4a3a9ed03cb80760fc59555efe9e0064`

Original script constants observed directly:

```text
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
```

Original intended result:
- Btrfs target: 780 GiB
- New partition 2 end: native sector `210721535`
- New partition 2 size: `210196992` native sectors
- Leave 128 GiB unallocated at disk tail.

Original script sequence:
1. Exact disk/GPT/partition/type/LUKS identity checks.
2. Opens LUKS as `omarchy-resize`.
3. `btrfs check --readonly`.
4. Mount top-level Btrfs with `subvolid=5`.
5. `btrfs filesystem resize 780G`.
6. Unmount and another read-only Btrfs check.
7. Close LUKS.
8. Change only partition 2 end.
9. Reopen LUKS and read-only Btrfs check.
10. Verify final partition start and size.

The partition resize line in the original script is:

```bash
parted --script "$disk" unit s resizepart 2 "${new_partition_end}s"
```

## CURRENT STATE: Btrfs has already been shrunk, GPT has NOT been changed

This is the most important part of the handoff.

The original script `--audit` passed before applying:

```text
Validated the exact backed-up Apple SSD layout.
This will shrink Btrfs to 780G and leave 128 GiB for macOS.
```

Then `/root/prepare-macos-space.sh --apply` was started. User typed the required confirmation `SHRINK-APPLE-SSD` and entered the normal Omarchy LUKS passphrase.

The script successfully:
- opened LUKS;
- ran the initial read-only Btrfs check with `no error found`;
- resized Btrfs from approximately 929.82 GiB to exactly 780.00 GiB;
- ran the post-resize read-only Btrfs check with `no error found`;
- closed the LUKS mapping.

It then reached GNU Parted and printed:

```text
Warning: Shrinking a partition can cause data loss, are you sure you want to continue?
```

The script aborted with status 1. No response was manually fed to Parted.

`sgdisk -p /dev/nvme0n1` was run immediately afterward and confirmed GPT partition 2 was STILL at the original geometry:

```text
2  524544  244275967  929.8 GiB  8304
```

Therefore the current state became:
- Btrfs = 780 GiB
- LUKS partition/GPT = original 929.8 GiB partition, end sector 244275967
- This is an intentional/safe intermediate state because the filesystem is smaller than its containing partition.

The Btrfs size was independently verified by reopening LUKS as `omarchy-verify` and running:

`btrfs filesystem show /dev/mapper/omarchy-verify`

Observed:

```text
Label: none  uuid: c0892194-86a3-43d9-8246-eb7d1b19ef57
Total devices 1 FS bytes used 50.80GiB
 devid 1 size 780.00GiB used 54.02GiB path /dev/mapper/omarchy-verify
```

The verification mapping was then cleanly closed. `/dev/mapper` showed only `control` before that verification, and `omarchy-verify` was closed afterward.

The original script `--audit` was rerun after the Btrfs shrink and still passed, because the GPT/LUKS outer geometry was unchanged.

## Parted 3.7 issue and failed workaround

Live environment has:

```text
parted (GNU parted) 3.7
```

`parted --help` shows:
- `-s, --script`: never prompts for user intervention
- `-f, --fix`: in script mode, fix instead of abort when asked

A TEMPORARY copy was made at:

`/root/prepare-macos-space-parted37.sh`

Only this substitution was made:

```text
parted --script
```

to:

```text
parted --script --fix
```

The temporary script's `--audit` passed.

It was then run with `--apply`. It again:
- passed identity checks;
- opened LUKS;
- ran Btrfs check successfully;
- reported resize from `780.00GiB to 780.00GiB`;
- ran another successful Btrfs check;
- closed LUKS;
- reached Parted.

Despite `--fix`, Parted again printed:

```text
Warning: Shrinking a partition can cause data loss, are you sure you want to continue?
```

and the script again exited status 1.

Immediately afterward, `sgdisk -p /dev/nvme0n1` AGAIN confirmed GPT was untouched:

```text
Disk /dev/nvme0n1: 244276265 sectors, 931.8 GiB
Sector size (logical/physical): 4096/4096 bytes
Disk identifier (GUID): C9FB7A78-B04A-4B43-B8A9-26EA7F29987D
...
Number  Start (sector)  End (sector)  Size       Code
1       256             524543        2.0 GiB    EF00
2       524544          244275967     929.8 GiB  8304
```

So DO NOT assume `--fix` works for this warning. It demonstrably did not in this environment.

Do not blindly rerun either apply script. Determine the correct, minimal way to complete only the already-audited partition-end change while preserving every GPT attribute and then perform the script's intended post-resize verification.

## Current Parted view before any GPT change

Read-only command:

`parted --script /dev/nvme0n1 unit s print free`

showed the original partition 2 still occupying:

```text
2  524544s  244275967s  243751424s
```

with only the normal tiny GPT tail free space.

## Codex environment

Codex CLI 0.150.1 was installed into the live environment using `/tmp` because `/root` lives on a 256 MB `airootfs` and filled up.

Installer was successfully run with temporary HOME `/tmp/codex-home`.

Codex is launched with roughly:

```bash
HOME=/tmp/codex-home /tmp/codex-home/.local/bin/codex
```

User has granted Codex Full Access.

Codex reports it cannot find system bubblewrap but can use bundled bubblewrap. It also reports an irrelevant failed `xcodebuildmcp` MCP startup because this is Linux. Ignore that macOS-specific MCP failure.

## What Codex should do next

1. Treat this as a high-risk recovery operation.
2. Re-identify ALL disks from the live machine. Do not trust `/dev/sda` or `/dev/sdb` names from this document.
3. Verify `/dev/nvme0n1` model, capacity, 4096-byte sector size, GPT GUID, partition 1, partition 2 start/end/type, and LUKS UUID.
4. Verify no installed-root or temporary LUKS mapping is active.
5. Verify the live USB has no new SquashFS/loop0 I/O errors.
6. Verify Btrfs remains exactly 780 GiB and passes a read-only check if appropriate, without growing it back.
7. Investigate GNU Parted 3.7 behavior for the `resizepart` shrink confirmation. Do not stack speculative command-line flags.
8. The only intended GPT change is partition 2 end from `244275967` to `210721535`, preserving start `524544`, partition type UUID, partition identity/attributes, partition number, and all other GPT data.
9. Do not invent a different target boundary.
10. Once a safe method is established, perform the partition-end change and then independently verify the resulting GPT geometry.
11. Reopen LUKS and run the intended post-resize `btrfs check --readonly`.
12. Close the mapping.
13. Confirm exactly 128 GiB is unallocated at the end of the SSD.
14. Do NOT install macOS yet.
15. Safely unmount the read-only Seagate backup, power off, disconnect both USB drives, boot the internal Omarchy installation, and verify Linux before proceeding to Apple Internet Recovery.

If anything differs from the expected identity or geometry, STOP and tell the user rather than adapting automatically.

## After Linux boots successfully

Only after the resized Linux system boots and is verified:
- verify `/boot`, all Btrfs subvolumes, expected audio configuration, and this repository;
- record the new GPT geometry;
- then power down and use Option-Command-R for Apple Internet Recovery.

In macOS Recovery:
- never erase the physical Apple SSD;
- never delete/reformat Linux EFI or LUKS partitions;
- use only the 128 GiB unallocated tail space;
- have the user inspect/photograph Disk Utility before confirming writes;
- allow Apple to create whatever APFS/helper partitions it requires only within that tail allocation;
- install macOS there;
- boot macOS, complete setup, enroll at least one Touch ID fingerprint;
- keep macOS installed because xART/GigaLocker state is needed for continuing Linux Touch ID work;
- return to Linux through the Option boot menu.

## Repository context

Repository: `bentsignal/t2-mbp16-audio-recovery`

Relevant existing files include:
- `docs/macos-dual-boot.md`
- `tools/system-backup/prepare-macos-space.sh`
- T2 SEP / Touch ID research and recovery tooling.

Checkpoint before this recovery session was commit `dda7b9a`.

This handoff documents changes that occurred AFTER that checkpoint and must take precedence for the live disk state.