# Bounded pre-arm latency experiment — September 6, 2026

Current OS: Linux/Omarchy. Latest proven resume-to-sensor-ready remains
**5.666 seconds**, measured before this experiment. No new sleep or finger test
has been run for this change. Native enrollment remains the next main task;
Touch Bar work stays deferred.

## Network experiments: no improvement, settings restored

The measured 16:31 EDT resume contains a 2.108-second interface rebind followed
by about 1.5 seconds until the T2 peer becomes reachable. A local read-only
T2BCE reference (`a973d53`, `t2bce_vhci/transfer.c`,
`bce_vhci_transfer_queue_do_pause`) contains a 2,000-ms pending-OUT wait. The
live journal's `pause timeout waiting for 1 outputs` is consistent with that
wait; we have not established source identity with the installed kernel.
Removing this wait without understanding queue/DMA ownership is not a safe
latency fix. No driver/kernel changes were made.

`tools/research/measure-t2-nm-activation.py` measured only reactivation of the
dedicated T2 NetworkManager profile while awake, under the existing operation
lock. It validates the exact T2 USB/interface target and a dedicated
IPv4-disabled, manually addressed IPv6 profile. No biometric commands, sensor
resets, enrollment operations, Wi-Fi changes, or sleep were involved.

| Profile mode / temporary optimistic DAD | First TCP reachability | NM activation completion | IPv6 addresses |
|---|---:|---:|---:|
| default / off (baseline) | 1.209 s | 1.660 s | 2 |
| EUI64 / off | 1.661 s | 1.661 s | 1 |
| default / off (restore) | 1.209 s | 1.209 s | 2 |
| default / on | 1.811 s | 1.811 s | 2 |
| EUI64 / on | 1.861 s | 1.861 s | 1 |
| default / off (final restore) | 1.510 s | 1.760 s | 2 |

These single runs are diagnostic, not statistical benchmarks or measurements
across real suspend. Neither experiment demonstrated a useful improvement.
The profile is restored to `ipv6.addr-gen-mode=default`; this interface's
`optimistic_dad` and `use_optimistic` are both restored to zero. Duplicate-address
checks (`accept_dad=1`, `dad_transmits=1`) were never disabled.

[NetworkManager's IPv6 documentation](https://networkmanager.dev/docs/api/latest/settings-ipv6.html)
describes MAC-derived EUI64 generation; here it collapses the generated address
onto the already configured fixed address. The
[kernel sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html)
describes optimistic DAD and address selection. Enabling these interface-only
sysctls did not demonstrate earlier usability with this NM/manual-address setup.
Do not infer that a system-wide DAD change is needed.

The research helper intentionally retains the requested address mode on success,
restores the prior mode on ordinary failure, and restores temporary sysctls in
`finally`. SIGTERM unwinds cleanup; SIGKILL/power loss cannot. It is **not** an
installed service or general network tuning recommendation. Reproduction must
include explicit profile restoration and bounded root execution. Tests cover
profile guards and sysctl restoration helpers, not a simulated full NM rollback.

## Candidate improvement: event-driven pre-arm wait

The existing probe waits 500 ms after an accepted pre-arm command even when its
normal status-90 event has already arrived. The repo-owned
`tools/research/t2-bridge-probe-runtime.py` overlays only that waiting interval:

- A well-formed version-1 status-90 record, with the exact zero-detail shape,
  from pre-arm reply events or the pre-arm collector may end the wait early.
- Otherwise retain the 500-ms deadline. The original collector's 100-ms socket
  floor still applies; this is not a hard real-time deadline.
- The existing collector still validates and acknowledges each received event;
  batches and reply events are retained. No event or verdict is manufactured.
- Original sleep/pre-arm/wake/cancel commands, arguments, cleanup, command
  failures, actual unlock-match start, cue, and terminal identity checks remain.
- The temporary interception is restored in `finally`, before actual matching.

**Status 90 is an experimental early-end marker, not a proven complete sensor
readiness signal.** Prior traces show it during pre-arm, but do not prove that
all remaining settling time is unnecessary. This may save roughly 0–500 ms;
hardware acceptance and repeatability remain untested. If it regresses scans,
restore the original fixed wait instead of relaxing matching checks.

The source pin for the unchanged external probe is
`e5c5071f07836394fbfbc48805f7b806a8f37d1482835c34cb95aa38684162c5`.
The facade overlay replaces exactly one expected probe-script argument and
refuses an unexpected command shape. All other arguments, the shared operation
lock, cached-port retry rules, and existing source pin remain in force.
Privacy-safe journal timing now includes `prearm elapsed_ms=... early_marker=...`;
only an exact numeric/boolean stderr pattern is forwarded, not arbitrary probe
stderr or biometric data. The actual ready cue still comes only after the
second, unlock-match start is accepted.

## Deployment, rollback, and next test

Installed root-owned mode 0755:

- `/usr/local/libexec/t2-bridge-probe-runtime.py` (new wrapper)
- `/usr/local/libexec/t2-fprintd-runtime.py` (updated facade overlay)

The previous facade overlay is preserved at
`/usr/local/libexec/t2-fprintd-runtime.pre-event-wait.py`. Installation and daemon
restart were under the operation lock while the desktop was unlocked, with no
active scan/recovery. External checkouts, PAM, credentials, and biometric stores
were not edited.

Rollback while awake/unlocked, with no active verification or enrollment:

```bash
sudo flock --exclusive --nonblock /run/t2-touchid/operation.lock \
  /usr/bin/bash -c 'set -eu
  install -o root -g root -m 0755 /usr/local/libexec/t2-fprintd-runtime.pre-event-wait.py /usr/local/libexec/t2-fprintd-runtime.py
  systemctl restart fprintd.service'
```

This restores the fixed wait while retaining the earlier direct discovery,
guarded resume recovery, and accurate UI state fixes. The unused wrapper can
remain installed; no data deletion or reboot is required.

Offline tests exercise the pinned probe lifecycle with mocked transport:
marker in the reply, later marker, absent/malformed markers, retained events,
rejected sleep/start, receive/cancel errors, cleanup, source pins, and unchanged
positive/negative facade decisions. These do not substitute for hardware tests.
The complete research suite ran 189 tests with two expected environment skips;
all 26 runtime-overlay tests passed separately in the installed virtual
environment. Installed files match their repository sources, the new probe's
`--help` import/source-pin smoke check succeeds without device I/O, and
`fprintd.service` is active after restart.

Next, when Shawn is ready, perform **one combined sleep/wake acceptance**:
wait about 30 seconds asleep, wake, observe that the UI stays non-ready until
the real scan cue, then use the enrolled finger. Measure system-resume,
transport, discovery, pre-arm, and actual scan-ready timestamps separately.
Follow with a separately supervised unenrolled-finger control and password
fallback. Do not launch a surprise scan or suspend; no extra sleep solely for
the visual fix. Compare against 5.666 seconds, and report any failed candidate
honestly before moving back to native enrollment.
