#!/usr/bin/env bash
set -euo pipefail

readonly MODEL_DIR="16_1"

printf 'This removes this repository\047s DSP configuration, but leaves plugin packages installed.\n'
read -r -p 'Continue? [y/N] ' answer
[[ "$answer" =~ ^[Yy]$ ]] || exit 0

sudo rm -f /etc/wireplumber/wireplumber.conf.d/51-t2-dsp.conf
sudo rm -f /usr/share/wireplumber/scripts/device/t2-force-unmute.lua
sudo rm -rf -- "/usr/share/t2-linux-audio/$MODEL_DIR"
systemctl --user restart wireplumber pipewire pipewire-pulse

printf 'Removed. Historical backups remain in %s\n' \
  "${XDG_STATE_HOME:-$HOME/.local/state}/t2-mbp16-audio-recovery/backups"

