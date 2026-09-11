# Touch ID implementation priorities

Latest continuation: a read-only version-1 capability handshake is configured
for the next supervised reboot; the running driver is unchanged. See
[startup control and decision points](touch-id-sep-dkms.md#startup-handshake-control-prepared-september-11).
Touch ID remains unavailable; this is not a completed repair.

Updated 2026-09-06 after Shawn authorized either work order.

September 11 after shutdown/update: kernel 7.2.4 was missing the custom SEP
module. A pinned DKMS installer now builds/installs it and enables rebuilds on
future kernel/header updates. Transport starts, but the original AKS timeout
persists: traced mailbox send succeeds, receive times out. fprintd remains
inactive and the icon absent. See [repair and current evidence](touch-id-sep-dkms.md).
Do not repeat the earlier shutdown proposal as if it had not been tried.

September 11 startup blocker: the next sleep test was not initiated because
fprintd cannot start. SEP keybag loading and a separate read-only capability
query both time out. Normal service retry and the subsequent shutdown/power-on both failed. See [diagnostic checkpoint](touch-id-sep-startup-timeout.md).
The single-cancel wake correction remains untested on hardware.

Latest checkpoint, 19:09 EDT: the 19:04 control failed because double cancellation
interrupted our new child cleanup and retained the claim. Transport recovered in
4.483 s, but Touch ID never reached ready; password unlock worked. The composition
bug is reproduced offline and corrected, deployed with tests and idle bus checks
passed. All waiting UI stages now say “Touch ID is preparing”. Real acceptance
of the correction is pending; latest successful readiness remains 4.982 s.
See [failure, correction, and rollback](touch-id-client-disconnect.md).

Latest implementation, 18:53 EDT: claiming-client disconnect now invokes backend
cleanup, and probe/discovery children are owned and reaped across cancellation.
Private-bus child/lock tests and live idle claim/disconnect checks pass. Changes
are deployed; real sleep/scan benefit remains unmeasured. A metadata-only bulk
OUT diagnostic patch builds but is not installed. See [implementation and next
control](touch-id-client-disconnect.md). Last measured readiness remains 4.982 s.

Latest control, 18:37 EDT: readiness **4.982 s**, fingerprint unlock completed.
Lock contention/interface-up contributed negligibly; the 2.112-s rebind and
1.407-s post-rebind wait remain. No verification-stop call was logged, so the
stop-order fix did not resolve pre-sleep backend quiescence. Traced queues
reported resumed/active, but an OUT completion still stalled. Temporary tracing
is now disabled. See [diagnostic conclusions](touch-id-resume-performance.md).
The older checkpoints below preserve chronology; no trace is currently armed.

Latest implementation, 18:28 EDT: Shawn's usability target is subsecond readiness.
An offline-reproduced stop/rediscovery race is fixed and deployed; lock-wait and
interface-up timing are now separate. Four kernel queue-state trace sites are
armed for the next supervised control. No new speed improvement is measured.
See [subsecond resume investigation](touch-id-resume-performance.md) for evidence,
validation, next-test questions, and required trace cleanup.

Latest checkpoint, 18:20 EDT: Shawn visually accepted the first waking-up
message after the pre-freeze UI fix. Fingerprint unlock completed, but
resume-to-ready regressed to **8.382 s** (previous 5.240 s). Old backend
verification/discovery continued during recovery; cancellation and lock timing
need investigation before attributing the slowdown. Status wording is simplified
at Shawn's request. See [UI](touch-id-readiness-ui.md) and
[timing evidence](touch-id-prearm-latency.md). Negative control remains pending.

The following checkpoints preserve earlier measurements.

Latest checkpoint, 17:32 EDT: pre-arm optimization exercised successfully;
resume-to-ready **5.240 s**, cached verification-to-ready **525.8 ms**. The
premature ready UI cue still failed visual acceptance. A pre-freeze user-session
delay-inhibitor/IPC latch and 50-ms interface-up polling are now deployed, with
offline and awake non-biometric checks passed; the next combined sleep/visual
control is pending. Details: [UI](touch-id-readiness-ui.md),
[timing](touch-id-prearm-latency.md). No new enrollment or Touch Bar work.

The goal remains usable, secure Touch ID on T2 Linux/Omarchy: Linux-native
enrollment, reliable verification after boot/resume, and password-fallback
integration. Working matching with a macOS-enrolled finger is an intermediate
result, not completion. Touch Bar work is explicitly deferred.

## 1. Active: verification startup and resume performance

Why first: authentication already works, but long startup delays harm everyday
use and complicate enrollment experiments. Make the underlying connection and
verification lifecycle predictable before adding enrollment mutations.

Latest measured cycle, September 6 EDT:

| Event | Timestamp | Elapsed after resume |
|---|---|---|
| System resumed | 15:13:40.211 | 0 |
| T2 transport recovered automatically | 15:13:50.964 | 10.753 s |
| Lock-screen PAM verification started | 15:13:51.059 | 10.848 s |
| Actual accepted scan cue | 15:14:16.293 | 36.082 s |
| Screen unlocked | 15:14:19.158 | 38.947 s |

The ~25.3 seconds after transport recovery is in the verification startup path,
not the lock-screen transition. Port rediscovery is a strong candidate, not yet
a confirmed attribution for that resume: the facade discards its cached endpoint on certain probe failures,
and discovery scans the 16,384-port dynamic range plus candidate handshakes.
Repeated connection setup/calibration/pre-arm also needs measurement. A no-I/O
probe CLI startup check took ~73 ms; that does not benchmark the full operation
but provides no justification for a language rewrite as the immediate fix.

An independent, awake, read-only discovery measurement on September 6 took
**23.474 seconds**, returned the same endpoint as the root-private cache, and
used **1.615 seconds of CPU** (77.8 MB peak memory). It ran the installed
discovery implementation under the normal operation lock and a bounded
systemd service; no biometric match/enrollment commands were sent. The helper
is `tools/research/measure-biometric-discovery.py`. This reproduces a delay
comparable to the unexplained startup interval, but stage timing on a subsequent
verification is still needed to prove that discovery caused that interval.
Prefer eliminating unnecessary full scans or using an evidence-validated
directory route; do not mistake a reachable cached port for authenticated
biometric success.

Instrumentation checkpoint: the repo-owned runtime overlay is deployed and
`fprintd.service` restarted successfully while the desktop was unlocked. The
research suite completed 155 tests with two expected environment-dependent
skips; all nine overlay tests passed under the installed runtime virtual
environment. This adds timing only, not a latency fix. No new supervised scan
or suspend control has been performed for this checkpoint.

Next work:

1. Measure discovery versus probe-to-ready without logging identifiers or
   payloads. The pinned facade overlay now journals those boundaries while
   preserving all original return values, failures, cancellations, and retries.
2. Remove measured redundant discovery/setup using validated endpoint/session
   lifecycle handling. Do not assume a cached endpoint remains valid forever.
3. Address the actual CDC-NCM/T2BCE resume stall so a watchdog/rebind workaround
   is not the normal wake path. Keep recovery bounded while that work proceeds.
4. Repeat awake and suspend/resume positive and negative controls, including
   immediate user interaction and password fallback. Record measured readiness,
   not a guessed sleep interval or user reaction time.

Checkpoint for moving on: a measured, materially faster and repeatable
verification path with known remaining limits and no weakened identity checks.
Do not let speculative micro-optimization or an unmeasured language rewrite
indefinitely displace enrollment. If a remaining kernel issue requires a
separate upstream effort, document that boundary and reassess enrollment order.

### Direct directory shortcut deployed (September 6)

The fixed directory route evidenced in `macos-touch-id-findings.md` was tested
read-only from Linux. Querying directory port 59602 returned the same current
BiometricKit endpoint as the private cache in **0.160 s**, compared with
**23.474 s** for the full scan. An installed-helper smoke test under the
facade's security restrictions took **0.286 s**, including child startup, and
again returned the same endpoint. These are discovery measurements, **not new
end-to-end wake or fingerprint acceptance measurements**.

`tools/research/t2-biometric-discover.py` is deployed root-owned at
`/usr/local/libexec/t2-biometric-discover.py`. It validates root-private
configuration, the exact T2BCE CDC-NCM interface, and the operation lock; sends
only the RemoteXPC directory handshake; and reads the advertised service port.
The directory hint is specific to the evidenced Intel implementation. The
biometric service port is never hard-coded. Raw directory records are not
logged; the returned port is consumed through a private subprocess pipe.

The repo-owned fprintd overlay now tries this helper **only when its in-memory
endpoint is absent**. Cached returns stay unchanged. A failed/invalid/unsupported
direct lookup falls back to the original full discovery. The helper has a
2-second exchange deadline and 0.5-second cleanup deadline; its caller enforces
5 seconds including startup and kills/reaps a timed-out or cancelled child.
Cancellation propagates without starting a fallback scan. The original
single-retry rule for a failed cached probe remains unchanged; genuine negative
matches are not retried. No identity, enrollment, calibration, or authentication
success criteria changed. A directory response is not authentication success.

Validation: 163 research tests, two expected environment skips; all 14 runtime
overlay tests passed in the installed virtual environment, including execution
of the pinned facade's negative-match and stale-cache retry paths with mocked
I/O. The service restarted successfully on the unlocked desktop. No live scan
or sleep was triggered. Next manual gates: awake positive/negative controls,
then immediate-interaction suspend/resume controls and journal stage timings.
The separate ~10.8-second transport recovery remains an unresolved latency
component; this change alone cannot establish instant wake.

Awake acceptance after deployment: Shawn reported successful fingerprint
unlock on September 6. The journal at 15:43:51–15:43:53 EDT shows a cached
discovery return (0.0 ms), **873.3 ms verification-to-ready**, and 2300.1 ms
total probe time including touch. This validates the awake cached path, not
the post-resume rediscovery path. Shawn authorized the next sleep/wake test;
its result is still pending.

Subsequent sleep controls returned sensor readiness in **11.779 s** and
**12.724 s** after Linux resumed, with cached discovery and ~0.87-second matcher
startup. They confirm that transport recovery, not the discovery shortcut, is
the remaining measured delay in those runs. A guarded earlier-repair path is
now deployed; see [resume recovery](touch-id-resume-recovery.md) for the changed
fault-evidence gate, tests, rollback, and pending supervised acceptance. It has
not yet been timed across a real sleep/wake. Enrollment remains next, not dropped.

Latest result, 16:31 EDT: the guarded early-recovery control reached sensor-ready
in **5.666 seconds** after resume (previous control: 12.724 seconds). Transport
returned in 4.307 seconds, direct-directory rediscovery took 262.5 ms, and total
verification-to-ready was 1.126 seconds. Shawn reported successful use and a
misleading initial ready cue; the user-owned UI now invalidates cached readiness
on refresh/new lock and watches status-file changes. See
[readiness notes](touch-id-readiness-ui.md) for the remaining visual acceptance
check. Repeatability and a post-change negative control remain pending; this is
not an instant-wake or completed-enrollment claim.

Next performance pass: network address-generation/optimistic-DAD experiments
did not improve awake link activation and were fully reverted. A pinned,
repo-owned event-driven pre-arm wait is now deployed for the next combined
sleep/visual control, with the previous runtime preserved for rollback. This
targets at most about half a second, not the remaining driver stall; no new
hardware benefit is yet measured. See [experiment details and next-test gate](touch-id-prearm-latency.md).

## 2. Next: Linux-native fingerprint enrollment

This remains required. Users should eventually enroll and manage fingerprints
in Linux without booting macOS. macOS here is a reverse-engineering reference,
not the intended enrollment dependency for a finished implementation.

Current checkpoint: the last live attempt stopped on auxiliary status 55 and
reconciled with one unchanged identity. The evidence-backed overlay handles that
and the other characterized auxiliary statuses, but successful native enrollment
and its full persistence lifecycle are not yet demonstrated. See
`touch-id-enrollment-presence-events.md` and the existing enrollment handoffs.

Resume with fresh read-only inventory/reconciliation, then a separately
supervised new-finger enrollment with readable cues. Preserve the existing
working fingerprint; prove persistence, matching, rejection of an unenrolled
finger, and reboot behavior. Do not convert a start-accepted event, auxiliary
status, or UI cue into enrollment success or authentication success.

## Deferred / out of scope for this checkpoint

- Touch Bar graphics-mode changes or renderer installation.
- Broad feature additions unrelated to authentication/enrollment.
- A language rewrite without evidence that CPU or memory cost warrants it.

Keep findings, changes, tests, and explicit manual-test boundaries committed and
pushed. No additional sleep or finger test should start without Shawn ready.
