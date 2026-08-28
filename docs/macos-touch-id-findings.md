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

The endpoint addresses follow from the host interface/NDP roles and the local
listener ownership. macOS `netstat` truncates both printed IPv6 addresses, so
the full endpoint association is a supported inference rather than a packet
observation. Port `49165` is directly owned by `remoted`.

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

## Linux continuation

The most important correction is that current macOS does not use fixed ports
`58783` or `52032` for the active biometric connection. `remoted` dynamically
created a bank of host listeners and BiometricKit used port `49165` during this
boot. Linux should not hard-code that ephemeral value.

The next fail-closed Linux experiment should remain discovery-only. After a
narrow NCM rebind and proof that TX advances, reproduce only enough activation
to make the current `remoted` directory/listener bank appear, then passively
recover the advertised `com.apple.eos.BiometricKit` port. Keep the existing
five-second, byte/frame, ancestry, and source kill-switch gates. Do not send a
biometric command until the current service discovery and BridgeXPC handshake
are captured and independently decoded.

Boot-time macOS capture could still establish the missing activation sequence,
but installing a LaunchDaemon or restarting Apple daemons requires separate
approval and was not performed here.
