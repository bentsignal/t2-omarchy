# Touch ID implementation priorities

Updated 2026-09-06 after Shawn authorized either work order.

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
