#!/bin/sh
set -eu
umask 077

interface=7-1:1.0
driver=/sys/bus/usb/drivers/cdc_ncm
output=${1:-}
monitor_pid=

if [ "$(id -u)" -ne 0 ] || [ "$output" != /tmp/t2-ncm-usb-startup-20260828.pcap ] ||
   [ -e "$output" ] || [ ! -c /dev/usbmon7 ] || [ ! -L "$driver/$interface" ]; then
    echo "exact root, output, usbmon, or NCM binding invariant failed" >&2
    exit 1
fi

cleanup() {
    if [ -n "$monitor_pid" ]; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
    fi
    if [ ! -L "$driver/$interface" ]; then
        printf '%s' "$interface" > "$driver/bind"
    fi
}
trap cleanup EXIT HUP INT TERM

tcpdump -i usbmon7 -s 262144 -U -w "$output" >/dev/null 2>&1 &
monitor_pid=$!
sleep 1
printf '%s' "$interface" > "$driver/unbind"
sleep 1
printf '%s' "$interface" > "$driver/bind"
sleep 4
