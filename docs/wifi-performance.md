# Wi-Fi performance investigation

## Accepted fix and reboot persistence

Shawn confirmed on September 10, 2026 that the workaround “works like a charm.”
Keep `ipv6.method disabled` on the affected saved Wi-Fi profile. Power saving
is also disabled, but disabling power saving alone did not fix throughput.

Persistence was verified through NetworkManager: the active profile is stored
under `/etc/NetworkManager/system-connections/`, autoconnect is enabled, and
its saved properties report `ipv6.method: disabled` and
`802-11-wireless.powersave: 2`. NetworkManager loads this profile on reboot;
no login script or repeated command is needed. Live power saving is off and
there is no IPv6 default route. A reboot was not performed for this check.
The credential-bearing connection file is deliberately not copied into Git.

This is a per-network workaround, not a global setting. It survives reboot
and reconnect, but deleting/recreating the profile, reinstalling the OS, or
joining a different network does not carry the setting over automatically.
Do not assume every T2 Mac or Wi-Fi network requires IPv6 disabled.

To reproduce after a reinstall, substitute the affected saved Wi-Fi profile
name below (no Wi-Fi password is needed in these commands):

```bash
nmcli connection modify 'YOUR WI-FI PROFILE' ipv6.method disabled 802-11-wireless.powersave 2
nmcli connection up 'YOUR WI-FI PROFILE'
nmcli -f connection.autoconnect,ipv6.method,802-11-wireless.powersave connection show 'YOUR WI-FI PROFILE'
```

The second command briefly reconnects Wi-Fi. Restore IPv6 with
`nmcli connection modify 'YOUR WI-FI PROFILE' ipv6.method auto`, followed by
`nmcli device reapply wlp5s0` on this machine.

## Initial investigation

September 10, 2026, Linux: user reported roughly 64 Mbps download versus
500 Mbps on other devices. Wi-Fi 5 was already active: BCM4364 with brcmfmac,
5 GHz channel 157, 80 MHz width, 1300 Mbps reported RX/TX link rate, and
approximately -48 dBm signal. Link rate is not measured Internet throughput.
Firmware reported version 9.30.503.0.32.5.92; no firmware changes were made.
The Internet route used Wi-Fi; Tailscale reported no exit node.

The active NetworkManager profile explicitly enabled power saving (3),
overriding `/etc/NetworkManager/conf.d/omarchy-wifi-powersave.conf` (2).
Changed only that profile's `802-11-wireless.powersave` to 2 (disable).
NetworkManager could not reapply this property live, so applied it with
`pkexec /usr/bin/iw dev wlp5s0 set power_save off`, without reconnecting.
Verified both saved `disable` and live `Power save: off`.
To reverse, set the same profile property to 3 and use
`pkexec /usr/bin/iw dev wlp5s0 set power_save on`.

At this initial checkpoint, validation was incomplete: an OVH 100 MiB download before the change measured
104.7 Mbps. Subsequent requests were throttled or rejected with HTTP 429;
Cloudflare's test endpoint returned HTTP 403. A 100 MB range download from
mirrors.kernel.org after the change measured 68.9 Mbps. Different servers
and rate limiting prevent a valid before/after conclusion. The user was asked
to repeat the original speed test. There was no demonstrated throughput fix yet.

Reference: [NetworkManager wireless settings](https://networkmanager.dev/docs/api/latest/settings-802-11-wireless.html).

## Follow-up: IPv4 workaround verified

The user repeated Omarchy's built-in test and reported just under 50 Mbps;
power saving alone did not fix the issue. Their phone reaches about 600 Mbps
with Ookla, and this Mac has reached about 600 Mbps in Omarchy over Ethernet.

A bounded NDT7 download reproduced 55.6 Mbps over IPv6 outside the browser.
An IPv4 test reached 323.2 Mbps. A sequential comparison against the **same**
M-Lab server then measured 57.7 Mbps IPv6, 295.5 Mbps IPv4, and 54.2 Mbps IPv6.
The first IPv4 tests had substantial TCP retransmissions, so the remaining
gap to 600 Mbps could not be attributed solely to IP family.

Changed the active Wi-Fi profile's `ipv6.method` from `auto` to `disabled`.
Reapply initially failed because the previous power-saving profile change
was still unapplied in NetworkManager's active connection. Reactivated that
profile on wlp5s0; it stayed on the same 5 GHz access point. The next NDT7 test
measured **504.4 Mbps** over IPv4. Omarchy's own download test, bounded to
15 seconds, reported per-second rates of **397–632 Mbps** (most around 500–580).
The packaged test downloads from Netflix/Fast.com using eight workers and
reports interface byte-counter deltas; these samples are not a test average.

To distinguish the IP-family workaround from a connection-refresh effect,
restored `ipv6.method auto` and reapplied it **without reconnecting**. IPv6
returned, and NDT7 fell back to **56.2 Mbps**. Restored `disabled` and reapplied
successfully, again without reconnecting. Thus the IPv6 path remains slow
after the Wi-Fi refresh; its precise cause (host/driver, router, or upstream
path) is not established. This is a verified workaround, not a firmware fix.
The final 12-second Omarchy confirmation reported 323–537 Mbps, with 10 of
11 samples between 424 and 537 Mbps. Both bounded Omarchy runs exited via
the intended timeout; the packaged script's cleanup trap stopped its workers.

Final persistent settings on this Wi-Fi profile: power saving disabled and
IPv6 disabled. No global IPv6 setting, Tailscale setting, internal T2 network,
firmware, or driver was changed. IPv6-only destinations are unavailable
directly through this profile while the workaround is active.

To restore IPv6, set the affected profile's `ipv6.method` to `auto` with
`nmcli connection modify`, then `nmcli device reapply wlp5s0`. The download
diagnostic is `node tools/wifi-download-check.mjs` (or add `--ipv4` to prefer
IPv4). It uses M-Lab's public measurement service and prints only aggregate
metrics; inspect the reported address family rather than assuming selection.
Protocol reference: [NDT7 specification](https://github.com/m-lab/ndt-server/blob/main/spec/ndt7-protocol.md).
