#!/bin/bash
set -euo pipefail

if [[ $(uname -s) != Darwin || $(id -u) -ne 0 ]]; then
  echo "usage: sudo $0" >&2
  exit 2
fi

model=$(sysctl -n hw.model)
if [[ $model != MacBookPro16,1 ]]; then
  echo "Refusing unexpected model: $model" >&2
  exit 3
fi

source_dir=$(cd "$(dirname "$0")" && pwd -P)
collector_source="$source_dir/capture-boot-macos-t2.sh"
collector_target=/usr/local/libexec/t2-touch-id-boot-capture
plist_target=/Library/LaunchDaemons/com.bentsignal.t2-touch-id-boot-capture.plist
capture_root=/var/tmp/t2-touch-id-boot-capture

for path in "$collector_target" "$plist_target" "$capture_root"; do
  if [[ -e $path ]]; then
    echo "Refusing to overwrite existing path: $path" >&2
    exit 4
  fi
done

install -d -m 755 /usr/local/libexec
install -o root -g wheel -m 755 "$collector_source" "$collector_target"
install -o root -g wheel -m 644 \
  "$source_dir/com.bentsignal.t2-touch-id-boot-capture.plist" "$plist_target"
plutil -lint "$plist_target"

echo "Installed one-shot boot collector. Reboot when ready."
echo "Evidence will appear at $capture_root and collection ends after 300 seconds."

