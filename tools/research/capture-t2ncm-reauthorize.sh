#!/bin/sh
set -eu
umask 077

LIVE_T2_NCM_REAUTHORIZE_ENABLED=false
device=/sys/bus/usb/devices/7-1
output=${1:-}
monitor_pid=

if [ "$LIVE_T2_NCM_REAUTHORIZE_ENABLED" != true ]; then
    echo "live T2 NCM reauthorization is disabled in source" >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ] || [ "$output" != /tmp/t2-ncm-reauthorize-20260828.pcap ] ||
   [ -e "$output" ] || [ ! -c /dev/usbmon7 ] ||
   [ "$(cat "$device/idVendor")" != 05ac ] || [ "$(cat "$device/idProduct")" != 8233 ] ||
   [ "$(cat "$device/authorized")" != 1 ]; then
    echo "exact root, output, usbmon, identity, or authorization invariant failed" >&2
    exit 1
fi
case "$(readlink -f "$device")" in
    *0000:04:00.1/t2bce_core/*/t2bce_vhci/usb7/7-1) ;;
    *) echo "T2 bridge ancestry invariant failed" >&2; exit 1 ;;
esac

cleanup() {
    if [ -n "$monitor_pid" ]; then
        kill "$monitor_pid" 2>/dev/null || true
        wait "$monitor_pid" 2>/dev/null || true
    fi
    if [ -e "$device/authorized" ] && [ "$(cat "$device/authorized")" != 1 ]; then
        printf '1' > "$device/authorized" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

tcpdump -i usbmon7 -s 262144 -U -w "$output" >/dev/null 2>&1 &
monitor_pid=$!
sleep 1
printf '0' > "$device/authorized"
sleep 1
printf '1' > "$device/authorized"
sleep 6
test "$(cat "$device/authorized")" = 1
test -L /sys/bus/usb/drivers/cdc_ncm/7-1:1.0
test -L /sys/bus/usb/drivers/cdc_ncm/7-1:1.1
