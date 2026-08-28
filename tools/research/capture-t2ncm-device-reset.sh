#!/bin/sh
set -eu
umask 077

output=${1:-}
monitor_pid=
helper=$(dirname "$0")/t2ncm-device-reset.py
interface=7-1:1.0
driver=/sys/bus/usb/drivers/cdc_ncm

if [ "$(id -u)" -ne 0 ] || [ "$output" != /tmp/t2-ncm-device-reset-20260828.pcap ] ||
   [ -e "$output" ] || [ ! -c /dev/usbmon7 ] || [ ! -x "$helper" ] ||
   [ ! -L "$driver/$interface" ]; then
    echo "exact root, output, usbmon, or helper invariant failed" >&2
    exit 1
fi

cleanup() {
    if [ -n "$monitor_pid" ]; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
    fi
    if [ ! -L "$driver/$interface" ] && [ -e /sys/bus/usb/devices/7-1:1.0 ]; then
        printf '%s' "$interface" > "$driver/bind" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

tcpdump -i usbmon7 -s 262144 -U -w "$output" >/dev/null 2>&1 &
monitor_pid=$!
sleep 1
printf '%s' "$interface" > "$driver/unbind"
"$helper" --live --confirm=I_UNDERSTAND_THIS_RESETS_ONLY_T2_NCM_USB
sleep 6
if [ ! -L "$driver/$interface" ]; then
    printf '%s' "$interface" > "$driver/bind"
fi
test -L /sys/bus/usb/drivers/cdc_ncm/7-1:1.0
test -L /sys/bus/usb/drivers/cdc_ncm/7-1:1.1
