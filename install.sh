#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_MODEL="MacBookPro16,1"
readonly UPSTREAM_REPO="https://github.com/lemmyg/t2-apple-audio-dsp.git"
readonly UPSTREAM_COMMIT="b5c5a1368f4eed5e1339a913a5c2d813374dd1c1"
readonly MODEL_DIR="16_1"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/t2-mbp16-audio-recovery"

model="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
if [[ "$model" != "$EXPECTED_MODEL" ]]; then
  printf 'Refusing to install: expected %s, detected %s\n' "$EXPECTED_MODEL" "${model:-unknown}" >&2
  exit 1
fi

for command in git jq pacman systemctl wpctl; do
  command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 1; }
done

printf 'Installing required audio plugins...\n'
sudo pacman -S --needed lsp-plugins-lv2 lv2 fftw libxslt cargo git base-devel
if ! pacman -Q bankstown swh-lv2-git >/dev/null 2>&1; then
  command -v yay >/dev/null || { printf 'Install yay, then rerun this installer.\n' >&2; exit 1; }
  yay -S --needed bankstown swh-lv2-git
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
git clone --filter=blob:none "$UPSTREAM_REPO" "$work_dir/upstream"
git -C "$work_dir/upstream" checkout --detach "$UPSTREAM_COMMIT"

mkdir -p "$STATE_DIR"
timestamp="$(date +%Y%m%d-%H%M%S)"
backup_dir="$STATE_DIR/backups/$timestamp"
mkdir -p "$backup_dir"
[[ ! -e /etc/wireplumber/wireplumber.conf.d/51-t2-dsp.conf ]] || \
  sudo cp -a /etc/wireplumber/wireplumber.conf.d/51-t2-dsp.conf "$backup_dir/"
[[ ! -e /usr/share/t2-linux-audio/$MODEL_DIR ]] || \
  sudo cp -a /usr/share/t2-linux-audio/$MODEL_DIR "$backup_dir/"

sudo install -d -o root -g root -m 0755 \
  /etc/wireplumber/wireplumber.conf.d \
  "/usr/share/t2-linux-audio/$MODEL_DIR" \
  /usr/share/wireplumber/scripts/device
sudo install -o root -g root -m 0644 \
  "$SCRIPT_DIR/files/51-t2-dsp.conf" \
  /etc/wireplumber/wireplumber.conf.d/51-t2-dsp.conf
sudo install -o root -g root -m 0644 \
  "$SCRIPT_DIR/files/graph.json" \
  "/usr/share/t2-linux-audio/$MODEL_DIR/graph.json"
sudo install -o root -g root -m 0644 \
  "$work_dir/upstream/configs/$MODEL_DIR"/*.wav \
  "/usr/share/t2-linux-audio/$MODEL_DIR/"
sudo install -o root -g root -m 0644 \
  "$work_dir/upstream/configs/t2-force-unmute.lua" \
  "/usr/share/t2-linux-audio/$MODEL_DIR/t2-force-unmute.lua"
sudo ln -sfn "/usr/share/t2-linux-audio/$MODEL_DIR/t2-force-unmute.lua" \
  /usr/share/wireplumber/scripts/device/t2-force-unmute.lua

systemctl --user restart wireplumber pipewire pipewire-pulse
sleep 3
wpctl status | grep -q 'audio_effect.t2-161-speakers' || {
  printf 'DSP node did not load. Check: journalctl --user -u wireplumber -b\n' >&2
  exit 1
}
pactl set-default-sink audio_effect.t2-161-speakers
pactl set-sink-volume audio_effect.t2-161-speakers 50%

printf '\nInstalled successfully. Default output: MacBook Pro T2 DSP Speakers (50%%).\n'
printf 'Backup saved under %s\n' "$backup_dir"

