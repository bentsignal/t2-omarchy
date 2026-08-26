#!/usr/bin/env bash
set -euo pipefail

target=/dev/sdb
image=/home/shawn/Downloads/recovery-media/omarchy-4.0.1.iso
expected_model="Cruzer Fit"
expected_serial="4C530010630724110334"
expected_size=6227752960
expected_sha256=69cbb4e10d98ad831c3c9f245b5757a9d1fedfd0c9592780e977d6f950dea8c3

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run through pkexec or sudo"
[[ -b $target && -f $image ]] || die "target or ISO is missing"

model=$(lsblk -dno MODEL "$target" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
serial=$(lsblk -dnro SERIAL "$target" | sed 's/[[:space:]]*$//')
transport=$(lsblk -dnro TRAN "$target")
capacity=$(blockdev --getsize64 "$target")
image_size=$(stat -c %s "$image")

[[ $model == "$expected_model" && $serial == "$expected_serial" ]] ||
  die "refusing identity mismatch: $model / $serial"
[[ $transport == usb && $capacity -ge 30000000000 && $capacity -lt 40000000000 ]] ||
  die "refusing unexpected transport/capacity: $transport / $capacity"
[[ $image_size == "$expected_size" ]] || die "ISO size mismatch: $image_size"
printf '%s  %s\n' "$expected_sha256" "$image" | sha256sum --check

while read -r mounted; do
  [[ -n $mounted ]] && umount "$mounted"
done < <(findmnt -rn -S "$target" -o TARGET; findmnt -rn -S "${target}1" -o TARGET; findmnt -rn -S "${target}2" -o TARGET)

echo "Writing Omarchy 4.0.1 to $target ($model, serial $serial)"
dd if="$image" of="$target" bs=16M iflag=fullblock oflag=direct status=progress conv=fsync
blockdev --flushbufs "$target"
udevadm settle

actual_sha256=$(head -c "$expected_size" "$target" | sha256sum | awk '{print $1}')
[[ $actual_sha256 == "$expected_sha256" ]] || die "device verification failed: $actual_sha256"
echo "Recovery USB verified: $actual_sha256"
