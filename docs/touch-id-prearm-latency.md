# Bounded pre-arm latency experiment — September 6, 2026

## 18:20 control: visual fix passes; readiness takes 8.382 seconds

This was suspend/resume, not a reboot. System suspend began September 6 at
18:12:27.110459 EDT and returned at 18:19:55.247074. Shawn confirmed the first
visible Touch ID message correctly said waking up. The lock recorded fingerprint
success feedback followed by unlock at 18:20:05.512026.

| Event | September 6 EDT | After system resume |
|---|---|---:|
| System returned from suspend | 18:19:55.247074 | 0 |
| T2 carrier connected | 18:19:55.840244 | 0.593 s |
| Successful-resume guard verified | 18:19:57.194282 | 1.947 s |
| Guarded rebind started | 18:19:58.745992 | 3.499 s |
| Rebind finished | 18:20:00.822745 | 5.576 s |
| T2 peer reachable | 18:20:02.831091 | 7.584 s |
| Verification started | 18:20:02.843306 | 7.596 s |
| Actual accepted scan cue | 18:20:03.629351 | 8.382 s |
| Screen unlocked | 18:20:05.512026 | 10.265 s |

Readiness was **3.143 seconds slower** than the prior 5.239607-second control.
Rebind took 2076.7 ms; post-rebind reachability took about 2.008 seconds.
Direct discovery took 268.8 ms, pre-arm 170.6 ms (`early_marker=true`), and
verification-to-ready including discovery took 786.3 ms. Unlock time includes
the user's touch and must not be reported as sensor startup time.

The pre-sleep probe logged failure at 18:19:56.812951 (`elapsed_ms=40045.0`),
then attempted direct discovery and original discovery while recovery was in
progress. Discovery failed at 18:20:01.104173. After transport returned, a fresh
attempt used the direct directory successfully. The UI monitor acknowledged
preparation before freeze; the visible UI remained truthful, but aborting its
PAM attempt did not prevent this old backend work from appearing after wake.
Investigate cancellation and operation-lock timing before assigning causality.
The 50-ms polling change has no demonstrated improvement in this control.
Negative-finger testing and performance repeatability remain pending. No new
sleep or biometric test was initiated while recording these results.

## Hardware result at 17:32 EDT and next improvement

The next actual suspend/resume reached sensor readiness in **5.239607 s**,
versus 5.666429 s previously. The preparation optimization was used both before
sleep and after wake (`early_marker=true`). Post-wake pre-arm took **170.8 ms**,
and cached-endpoint verification-to-ready took **525.8 ms**, versus the earlier
awake cached control's 873.3 ms. This is evidence of a smaller startup delay,
not statistically established repeatability or a post-change negative control.
The probe finished normally and the lock logged `unlocked` at 17:32:36.107.

| Event | September 6 EDT | After system resume |
|---|---|---:|
| System returned from suspend | 17:32:29.242242 | 0 |
| Interface carrier connected (NM) | 17:32:29.824728 | 0.582 s |
| Interface-up check finished | 17:32:29.877946 | 0.636 s |
| Guarded rebind started | 17:32:30.378664 | 1.136 s |
| Rebind finished | 17:32:32.478671 | 3.236 s |
| T2 peer reachable | 17:32:33.886396 | 4.644 s |
| Verification started | 17:32:33.956293 | 4.714 s |
| Actual accepted scan cue | 17:32:34.481849 | 5.240 s |

The 500-ms interface-up polling interval is now **50 ms**, within the same
10-second deadline and exact-target validation. This reduces sampling delay,
not the actual time NM needs: in this run the old check saw carrier about
53 ms late, so do not claim the full 500 ms was avoidable. The three failed
probes, resume guard, rebind limits, and kernel queue-drain waits are unchanged.
The awake healthy no-rebind check passed in 4.4 ms after deployment; the faster
polling itself still needs a real resume measurement.

Shawn reported the premature ready cue still appeared. The UI needs a
**pre-freeze acknowledgement**, not just asynchronous file watchers; see the
new checkpoint in [readiness UI](touch-id-readiness-ui.md). No second sleep or
finger test was started while implementing that repair and the finer poll.

## Previous checkpoint (before this hardware test)

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
