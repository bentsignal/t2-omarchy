#!/usr/bin/env bash
set -euo pipefail

failed=0
check() {
  if eval "$2"; then printf 'OK   %s\n' "$1"; else printf 'FAIL %s\n' "$1"; failed=1; fi
}

check 'MacBookPro16,1 hardware' '[[ "$(cat /sys/class/dmi/id/product_name)" == MacBookPro16,1 ]]'
check 'T2 audio driver' 'grep "^t2bce_audio " /proc/modules >/dev/null'
check 'DSP graph JSON' 'jq empty /usr/share/t2-linux-audio/16_1/graph.json'
check 'Bankstown plugin' '[[ -e /usr/lib/lv2/bankstown.lv2/bankstown.so ]]'
check 'LSP plugins' 'pacman -Q lsp-plugins-lv2 >/dev/null'
check 'SWH LV2 plugins' 'pacman -Q swh-lv2-git >/dev/null'
check 'WirePlumber running' 'systemctl --user is-active --quiet wireplumber'
check 'Protected DSP sink' 'pactl list sinks short | grep -q audio_effect.t2-161-speakers'
check 'DSP is default' '[[ "$(pactl get-default-sink)" == audio_effect.t2-161-speakers ]]'

exit "$failed"
