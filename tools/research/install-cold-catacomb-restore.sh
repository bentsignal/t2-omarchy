#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail

[[ $EUID -eq 0 ]] || {
  echo "Run with sudo: sudo $0" >&2
  exit 1
}
[[ $# -eq 0 ]] || {
  echo "Usage: sudo $0" >&2
  exit 2
}

repo=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
source_dir=$repo/prototypes/t2sep-probe
target=/usr/local/libexec/t2-current-catacomb-restore
unit=/etc/systemd/system/t2-current-catacomb-restore.service
dropin=/etc/systemd/system/t2-biometric-ready.service.d
modules=(
  cold-catacomb-restore.py
  user-state-probe.py
  coupled-bridge-query.py
  bridge-query.py
  bridge-protocol.py
  rsd-query.py
  rsd-protocol.py
  biometric-command.py
)

[[ -r /etc/t2-touchid.conf ]] || {
  echo "Touch ID configuration is not installed." >&2
  exit 1
}
for name in "${modules[@]}"; do
  [[ -f $source_dir/$name && ! -L $source_dir/$name ]] || {
    echo "Required module is absent or unsafe: $name" >&2
    exit 1
  }
done

install -d -o root -g root -m 0755 "$target" "$dropin"
for name in "${modules[@]}"; do
  install -o root -g root -m 0755 "$source_dir/$name" "$target/$name"
done
install -o root -g root -m 0755 \
  "$repo/tools/research/validate-current-macos-catacomb.py" \
  "$target/validate-current-macos-catacomb.py"
install -o root -g root -m 0644 \
  "$repo/files/t2-current-catacomb-restore.service" "$unit"
install -o root -g root -m 0644 \
  "$repo/files/t2-biometric-ready-cold-restore.conf" \
  "$dropin/20-current-catacomb-restore.conf"

systemctl daemon-reload
systemctl enable t2-current-catacomb-restore.service
echo "Cold Catacomb restore installed but not armed."
echo "It remains gated by /var/lib/t2-touchid/cold-restore-enabled."
