#!/bin/sh
set -eu

interface=7-1:1.0
driver=/sys/bus/usb/drivers/cdc_ncm
probe_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
output=${1:-}

if [ "$(id -u)" -ne 0 ] || [ "$output" != /tmp/t2-ncm-apple-config-20260828.bin ] ||
   [ ! -L "$driver/$interface" ] || [ ! -x "$probe_dir/t2ncm-flags-probe" ] ||
   [ -e "$output" ]; then
    echo "exact root, NCM interface, probe, or private output invariant failed" >&2
    exit 1
fi

rebind() {
    if [ ! -L "$driver/$interface" ]; then
        printf '%s' "$interface" > "$driver/bind"
    fi
}
trap rebind EXIT HUP INT TERM
printf '%s' "$interface" > "$driver/unbind"
"$probe_dir/t2ncm-flags-probe" --live --apple-config \
    --confirm I_UNDERSTAND_THIS_TEMPORARILY_REPRODUCES_APPLE_NCM_CONFIGURATION \
    --output "$output"
