#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Install a pinned GPL driver snapshot without editing the reference checkout.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run this installer as root.' >&2; exit 1; }
[[ $# == 0 ]] || { echo 'This installer takes no arguments.' >&2; exit 1; }
command -v dkms >/dev/null || { echo 'Install dkms and matching kernel headers first.' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/../.." && pwd)
reference_dir="$project_dir/.local/references/t2-touchid-linux-latest/src"
version=0.1.0_826a86e
kernel_release=$(uname -r)
[[ -f /lib/modules/$kernel_release/build/Makefile ]] || { echo 'Running-kernel headers are missing.' >&2; exit 1; }
staging=$(mktemp -d /usr/src/.t2-sep-transport.XXXXXXXX)
trap 'rm -rf -- "$staging"' EXIT
for file in Makefile t2_sep_transport.c t2_acm_lifecycle.h t2_aks_protocol.h t2_sep_transport_uapi.h; do
  install -o root -g root -m 0644 "$reference_dir/$file" "$staging/$file"
done
(cd "$staging" && sha256sum --check "$script_dir/t2-sep-transport-source.sha256")
install -o root -g root -m 0644 "$script_dir/t2-sep-transport.dkms.conf" "$staging/dkms.conf"
destination=/usr/src/t2-sep-transport-$version
if [[ -e $destination || -L $destination ]]; then
  [[ -d $destination && ! -L $destination ]] || { echo 'Unsafe existing DKMS source path.' >&2; exit 1; }
  (cd "$destination" && sha256sum --check "$script_dir/t2-sep-transport-source.sha256")
  cmp "$staging/dkms.conf" "$destination/dkms.conf"
else
  mv -- "$staging" "$destination"
fi
if [[ ! -e /var/lib/dkms/t2-sep-transport/$version/source ]]; then
  dkms add -m t2-sep-transport -v "$version"
fi
systemd-run --scope --quiet -p MemoryMax=1G -p MemorySwapMax=256M -p TasksMax=64 \
  dkms install -m t2-sep-transport -v "$version" -k "$kernel_release"
# Loading is deliberately separate: do not replace an already-registered SEP.
modinfo -k "$kernel_release" -F filename t2_sep_transport
