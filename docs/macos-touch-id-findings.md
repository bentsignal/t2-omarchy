# macOS 26.6.2 T2 Touch ID findings

This is the sanitized handback from the passive macOS capture on the 2019
`MacBookPro16,1`. Raw binaries, pcaps, unified logs, host identifiers, and the
enrolled fingerprint UUID remain local and are not part of this repository.

## Installed system evidence

- macOS `26.6.2`, build `25G83`, x86_64.
- `/usr/libexec/remoted` is a universal x86_64/arm64e Mach-O with SHA-256
  `345bdb3e5444bf5bbaab2f29c514198eed763be5e165e809116f57c877e844f5`.
- `/usr/libexec/biometrickitd` has SHA-256
  `636dd137dace867359f389437c198d8c4cd9dc12896e9017d94cb6c567e84e4b`.
- BridgeXPC reports bundle version `39`, source version `39000000000000`.
- AppleEmbeddedOSSupport reports build `2433`, source version
  `166000000000000`.

The live `remoted` hash supersedes the previously inspected
`88e78e65...4056` binary for claims about this installed OS.

## Interface and address roles

macOS exposes the bridge as active interface `en6`, MTU 16000:

```text
host MAC:       ac:de:48:00:11:22
host IPv6:      fe80::aede:48ff:fe00:1122%en6
T2 MAC:         ac:de:48:33:44:55
T2 IPv6:        fe80::aede:48ff:fe33:4455%en6
```

The host address is proven by `ifconfig` and the permanent local NDP entry.
The T2 address and MAC are proven by the reachable neighbor entry and agree
with the earlier Linux wire observation. This corrects the prior inference
that the macOS host would use `fe80::aede:48ff:fe33:44aa`.

## Services and live biometric connection

Both `remoted` (PID 113) and `biometrickitd` (PID 333) were running before the
interaction. `remoted` owned 15 consecutive listeners on the host bridge
address, ports `49154` through `49168`. The live biometric path was already
established before capture:

```text
biometrickitd host endpoint: host IPv6 port 49174
remoted/T2-facing endpoint:  T2 IPv6 port 49165
state:                       ESTABLISHED
```

Boot-time `lsof` and unified network logs directly confirm both full endpoint
addresses. Port `49165` is a T2 service port; `remoted` first connects to it and
hands the connected socket to `biometrickitd` through its local XPC service.

Across the 60-second window the biometric socket counters changed from
283350/118410 to 421450/137756 receive/transmit bytes: +138100 RX and +19346 TX.
The socket and listener set remained established; no per-unlock TCP setup or
teardown was observed in the before/after snapshots. Ports `58783` and `52032`
were not active in either snapshot.

## Two successful unlock sequences

The unified log directly records two successful Touch ID unlocks. Timestamps
below are local time (`-0400`) on 2026-08-28:

| Event | Unlock 1 | Unlock 2 |
| --- | --- | --- |
| Match operation begins | 13:32:02.717 | 13:32:18.310 |
| Finger on sensor | 13:32:04.752 | 13:32:19.794 |
| `unlockedByMesa` | 13:32:05.164 | 13:32:20.196 |
| Successful match result | 13:32:05.170 | 13:32:20.217 |

For both operations, `biometrickitd` logged BridgeXPC request/reply traffic,
successful command returns, `MatchModeUnlock`, `FingerOn`, `unlockedByMesa`,
and an identity match for UID 501. The framework reported
`Unlocked:1,CredentialAdded:1,Ignored:0`. The private identity UUID is omitted.

## Packet-capture limitation

Direct BPF attachment to `en6` failed with `No such device exists`, despite
`ifconfig` and `tcpdump -D` listing it. macOS 26 accepted the scoped
`pktap,en6` fallback with RAW link type but delivered zero packets. Therefore
the byte chronology is not wire-proven. The unified log's BridgeXPC message
sizes and socket-counter deltas prove traffic, but do not expose its payload.
An empty pcap must not be interpreted as absence of bridge traffic.

## Boot-time activation sequence

A one-shot LaunchDaemon began collection approximately five seconds after
kernel boot. A post-boot query of the persistent unified-log store recovered
the earlier interval. All offsets below use kernel boot time as zero:

| Offset | Directly observed event |
| ---: | --- |
| +2.081 s | `remoted` starts. |
| +2.279 s | `localbridge` attaches; NCM host and device backends initialize. |
| +2.290 s | The internal bridge device becomes usable; its first connection attempt fails with `No route to host`. |
| +3.875 s | `pollConnect` succeeds after `en6` becomes routable. |
| +3.908 s | `remoted` begins the directory connection from host port `49153` to T2 port `59602`. |
| +3.945 s | The HTTP/2 transport is ready. |
| +3.973 s | Both peers decline TLS and the `localbridge` directory handshake completes. |
| +4.677 s | A client confirms `com.apple.eos.BiometricKit` exists in the directory. |
| +4.711 s | launchd schedules `biometrickitd`; it is running at +4.722 s. |
| +7.076 s | `biometrickitd` begins `setupConnection`. |
| +7.077 s | Its `eos` query fails; its `bridge` query returns `localbridge`, then it fetches `com.apple.eos.BiometricKit`. |
| +7.079 s | `remoted` receives CONNECT and connects to T2 port `49165` successfully. |
| +7.087 s | BridgeXPC uses the handed-off socket on `en6`; no TLS layer is present. |
| +7.092 s | TCP is ready. A 119-byte BridgeXPC HELO is sent and a 101-byte HELO is received. |
| +7.101 s | The first queued BridgeXPC request receives a successful reply. |
| +7.102 s | `biometrickitd` reports Bridge interface version 3 and begins sensor initialization. |

The directory connection is directly identified as:

```text
host: fe80::aede:48ff:fe00:1122%en6 port 49153
T2:   fe80::aede:48ff:fe33:4455%en6 port 59602
stack: TCP + HTTP/2 RemoteXPC, TLS disabled by both peers
```

This is the activation exchange that the earlier post-login experiment could
not observe. It also shows that port `58783`, although embedded in the inspected
`remoted` implementation for a different role, is not the directory endpoint
used by this Mac/T2 boot path. Port `59602` is directly observed for the current
boot, but it should still be discovered rather than assumed stable.

## Linux continuation

Current macOS does not use fixed ports `58783` or `52032` for this boot path.
The directory ran on T2 port `59602`, and its returned BiometricKit service ran
on T2 port `49165`. Linux must not hard-code either boot-dynamic value.

The bootstrap is a named DNS-SD endpoint. Independent verification of the
installed x86_64 `remoted` slice shows
`RSDRemoteNCMHostDevice::needsConnect` calling
`nw_endpoint_create_bonjour_service("ncm", "_remoted._tcp", "local.")`.
The exact sequence is at `0x100012aac` in slice SHA-256
`88e78e65...4056`; `macos-rsd-bootstrap-evidence.py` verifies it. If that
resolved endpoint is absent, the same method falls back to fixed port `58783`,
which explains the previously misunderstood literal.

A supervised Linux test from proven host address `...:1122` sent a generic
PTR browse, an exact `ncm._remoted._tcp.local.` SRV question, and the same SRV
question with the mDNS QU bit. TX advanced without errors and the T2 continued
answering ICMPv6, but RX did not advance for any DNS-SD query. Avahi independently
produced the same negative result. Thus the DNS-SD responder is dormant during
Linux boot; merely reproducing Network.framework's lookup does not activate
it. No port scan or TCP connection was attempted.

A final supervised diagnostic sent that exact SRV question directly to the
proven T2 link-local address on UDP port 5353, bypassing IPv6 multicast delivery
while retaining the five-second timeout and exact-interface/source gates. The
T2 still answered ICMPv6 but returned no DNS response; the private evidence file
was therefore not created. This rules out multicast reception as the remaining
explanation for the negative discovery result and strengthens the activation
boundary above. The direct-query option remains source-disabled by default.

The next reverse-engineering target is the action below `remoted` that makes
the bridgeOS DNS-SD responder available under macOS. Once that activation is
understood, the next fail-closed Linux experiment should reproduce only the
directory connection. After proof that TX advances, connect from
the proven host address to the T2 address using a freshly observed/discovered
directory port, perform the already bounded HTTP/2 RemoteXPC handshake with TLS
disabled, and passively recover `com.apple.eos.BiometricKit`. Keep the existing
five-second, byte/frame, ancestry, and source kill-switch gates. The successful
result must include the complete bounded server transcript and the named
service port. Do not send CONNECT or a biometric command in that first run.

An offline inspection of Sonoma 14.6.1's x86_64
`BootKernelExtensions.kc` identified one Apple-specific operation absent from
the USB descriptors. `AppleUSBNCMControl::cacheAppleInterfaceFlags` recognizes
vendor/product `05ac:8233` and issues an IN control transfer with
`bmRequestType=0xa1`, `bRequest=0xa0`, `wValue=0`, `wIndex=0`, and `wLength=4`.
The method is at `0xffffff8001db5002`; its call from
`AppleUSBNCMControl::start` is at `0xffffff8001db4ad6`. The returned interface
flags influence Apple-specific NCM behavior. This is a concrete candidate for
the pre-IP activation boundary, but it is not yet proven against the installed
macOS 26 driver or a Linux USB trace. A first live probe must therefore be
limited to this exact device-to-host four-byte read, validate device and
interface identity before opening usbfs, preserve the raw result privately,
and remain source-disabled outside a supervised run.

Only after independent transcript validation should a second supervised step
request the advertised service, perform the bounded BridgeXPC HELO exchange,
and stop before sending a Mesa command. The boot capture proves the sequence
and frame sizes but not private payload bytes.
