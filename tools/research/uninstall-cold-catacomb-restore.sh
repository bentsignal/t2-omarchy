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

systemctl disable --now t2-current-catacomb-restore.service 2>/dev/null || true
rm -f -- /var/lib/t2-touchid/cold-restore-enabled
rm -f -- /etc/systemd/system/t2-current-catacomb-restore.service
rm -f -- /etc/systemd/system/t2-biometric-ready.service.d/20-current-catacomb-restore.conf
rm -rf -- /usr/local/libexec/t2-current-catacomb-restore
systemctl daemon-reload
echo "Cold Catacomb restore removed; private Catacomb stores were preserved."
