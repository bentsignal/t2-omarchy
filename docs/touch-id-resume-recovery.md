# Touch ID resume recovery — 2026-09-06

## Latest checkpoint

**September 6, 16:13 EDT: earlier, resume-only recovery is deployed for testing.**
See [the current roadmap](touch-id-roadmap.md) for priority and acceptance status.
The sections below preserve earlier iterations, including obsolete timing and
test instructions; do not ask for an arbitrary 30-second wait after wake.

The latest two controls confirmed real S3 suspend. Resume-to-sensor-ready was
11.779 seconds at 15:45:56–15:46:08 and 12.724 seconds at 15:56:27–15:56:40.
The latter spent 11.681 seconds restoring the transport, then 0.868 seconds
starting the matcher (plus scheduling). Both used the cached service endpoint,
so neither measured the direct-directory fallback. The lock screen unlocked
at 15:56:43.067. Keypress-to-first-visible-frame remains unmeasured.

### Earlier repair after a verified suspend

Repeated wake controls show the same failure: no T2 network response, then a
5-second-class transmit watchdog and an endpoint pause timeout, then successful
recovery by rebinding the **network interface only**. The previous helper waited
for that watchdog as its fault-evidence gate. The new path intentionally changes
that gate **only for one confirmed, recent resume**; it is a workaround, not a
proven kernel fix.

Before sleep, `t2-touchid-resume.service` invokes the helper's `--prepare-sleep`
mode. This publishes the existing sleeping UI state and writes a root-only,
atomic, single-use `/run/t2-touchid/resume-ticket.json`. It records the boot ID,
successful-suspend counter, monotonic time, and validated interface/target.
It sends no network or biometric commands. Failure to prepare the optional
guard does not prevent normal sleep.

After wake, `--after-resume` consumes that ticket under the operation lock.
The same boot and exact target must match, the kernel successful-suspend count
must have advanced by exactly one, and no more than 120 seconds of monotonic
(awake) time may have elapsed. Long time asleep does not expire the guard.
The counter's meaning is documented in the upstream
[Linux power sysfs ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-power).
Missing, unsafe, malformed, reused, failed-suspend, or stale evidence retains
the original watchdog-gated behavior. Public UI state never authorizes repair.

With a valid guard and an up, exactly validated T2 interface, three connection
probes are bounded to 350 ms each, separated by 250 ms. A reachable or refused
connection avoids rebind. Three failures allow one early CDC-NCM unbind/bind,
without waiting for the watchdog counter. Target validation and bind-in-finally
remain mandatory. Post-rebind checks poll every 100 ms with 250 ms connection
timeouts instead of adding whole-second sleeps. Total recovery remains bounded
by the existing service limit, with no restart loop or repeated rebind.

Tradeoff: immediately after a confirmed resume, a merely slow connection could
now receive one unnecessary network-interface rebind. This is deliberately
narrower than unconditional resetting on every wake, but it is less conservative
than waiting for a watchdog. No parent USB/T2 reset, firmware/driver replacement,
enrollment mutation, stored-fingerprint change, or authentication relaxation is
part of this patch. The pre-existing kernel endpoint-drain wait may still cost
time; do not promise subsecond wake before a live measurement.

Validation: 173 research tests completed, two expected environment skips. Tests
cover one-use tickets, failed/stale/changed-boot/changed-target guards, malformed
records, healthy and transient no-op paths, early rebind, and watchdog fallback.
Both unit files pass systemd validation. A live **awake** prepare/recover smoke
test rejected the guard because no sleep had occurred, confirmed a healthy
link in 4.5 ms, performed no rebind, and consumed the ticket. This does not prove
early-repair latency. The matcher was not restarted. No real sleep or touch was
requested during implementation.

Next manual gate: a separately authorized sleep/wake with immediate interaction,
then inspect guard acceptance, early-rebind duration, first sensor-ready time,
and positive/negative fingerprint controls. To disable only the optimization,
remove `--after-resume` from the recovery unit's ExecStart and reload systemd;
normal watchdog gating remains in the helper. Do this while awake with both
sleep/recovery units inactive. No biometric data needs removal.

### Previous checkpoint (historical)

The third real sleep/wake passed: Shawn unlocked with the enrolled finger after
automatic recovery at 13:32:22 EDT, about 12 seconds after resume. The following
historical sections preserve the preceding failures. Read
[readiness UX and Touch Bar investigation](touch-id-readiness-ui.md) for the
subsequent deployed status feed, user-owned lock-screen hint, latency adjustment,
and current supervised-test boundary. Those newer UX changes need acceptance;
the successful cycle below predates them.

## Finding and current state

Normal matching failed again after sleep, while fprintd remained active. The
internal T2 CDC-NCM interface had repeated kernel TX watchdog errors, a failed
IPv6 neighbor, and an unreachable cached biometric endpoint. Its TX error count
was 81. This repeats the September 5 failure, not evidence of an erased finger.

The new bounded recovery service ran at 12:32:47 EDT, confirmed repeated
unreachability with TX errors, rebound only the internal CDC-NCM interface at
12:32:55, and confirmed restored transport at 12:32:57. A read-only inventory
comparison then found:

- One live identity, stable across readbacks, exactly matching the saved archive.
- One archive entity, master enrollment count four, maximum five, reported free
  count two (the capacity semantics remain unproven).
- Exact expected protected policy. No biometric mutation was performed.
- The same known optional Catacomb-query rejections; the baseline's conservative
  `persistence_path_ready=false` and `safe_for_mutation=false` do not mean that
  the enrolled identity disappeared.

The matcher was restarted into a project-owned runtime overlay. A second
recovery invocation found a healthy transport and performed no rebind. A
synthetic start/stop of the sleep hook queued another healthy no-op correctly;
this is **not** an actual suspend/resume acceptance test.

Shawn subsequently confirmed both lock-screen controls on the deployed overlay:
the enrolled finger unlocked successfully, and an unenrolled finger did not.
These are user-observed end-to-end results, not an independently captured
fprintd trace. Normal matching after transport recovery is now accepted.

The first two actual sleep/wake tests failed on distinct readiness races; the
corrections below subsequently passed the third test. No new enrollment
trial was started during this repair.
Native enrollment remains at the status-55 overlay checkpoint described in
`touch-id-enrollment-presence-events.md`.

### First real wake: delayed watchdog race, corrected

The user-requested suspend started at 12:41:36 EDT and returned at 12:43:07.
The resume hook ran correctly. Recovery stopped at 12:43:11 because its three
failed connection probes completed while the NIC TX-error counter was still
zero. The first kernel CDC-NCM watchdog event arrived at **12:43:14**, reporting
a 5375 ms TX timeout. Thus the required fault evidence arrived three seconds
after the helper had already exited. Subsequent watchdog errors and the failed
neighbor confirmed the stalled transport remained unrecovered.

Shawn saw the fingerprint icon but no response to touches, then used password
fallback. fprintd logged `verify-unknown-error` feedback suppression, consistent
with the absence of a rejection toast. The daemon also logged stale VerifyStop
and Release cleanup errors at resume; those are recorded but not treated as
the cause of the demonstrably unreachable transport.

The helper now allows up to 12 additional seconds for delayed TX evidence after
the first three failed probes. It continues checking reachability and the exact
target; a naturally recovered peer produces no rebind. A deadline with no TX
evidence still fails closed. The existing 60-second unit bound and single-rebind
limit are unchanged. Tests cover delayed error arrival, natural recovery during
the grace window, target change, and absence of evidence through the deadline.

The deployed correction recovered the current stalled link at 12:45:34, and an
independent TCP check passed. **fprintd was not restarted** (same PID as before
sleep), avoiding a daemon restart that could mask a second resume issue. This
manual recovery does not establish automatic resume acceptance; another real
sleep/wake and successful scan are required.

### Second real wake: interface-up race, corrected

The next suspend ran from 12:51:22 to 13:00:43 EDT. The hook ran, but validation
stopped immediately because the configured interface was not yet up.
NetworkManager's journal then showed carrier connected at 13:00:43.654 and
activation completed at 13:00:45.159. The first TX watchdog arrived at 13:00:50.
Thus this attempt exited before the earlier watchdog-grace fix could run.
Waiting longer before touching would not have restarted the failed helper.

`InterfaceNotReady` now distinguishes an exactly validated T2 interface that is
still down from all other validation failures. The helper gives NetworkManager
up to 10 seconds to bring it up, repeating full validation without forcing any
network state. Wrong hardware/driver/configuration still fails immediately.
The total service timeout is now 75 seconds to cover the bounded lock, link-up,
watchdog-evidence, and post-rebind waits. There is still at most one rebind.
Tests cover down-to-up, permanently down, unsafe target, and the combined
down-to-up/delayed-watchdog/rebind/reachable sequence.

The installed helper manually restored transport at 13:09:01. Independent TCP
reachability passed, and fprintd still had the same PID: no daemon restart was
used to mask its post-suspend state. Another real sleep/wake test is required.

Shawn reported the lock screen going dark after about five seconds. There was
no second system suspend in the journal. Inspection of the installed Omarchy
`shell/plugins/lock/Service.qml` confirms its 5000 ms `idleBlankTimer` invokes
display/keyboard brightness-off commands, not system suspend; its fingerprint
PAM remains armed during the lock. No packaged Omarchy files or idle settings
were modified. For the test, allow recovery to run with the display dark, then
press a key to light it again before touching. Do not ask Shawn to race the
screen timeout or attribute this failed recovery to touching too soon.

### Next supervised test

The resume hook is enabled, fprintd is active, the previous recovery unit result
is successful, and the selected kernel sleep mode is `deep`. Save work, enter
actual suspend (not merely lock the screen), wait about 20 seconds, then wake.
Allow 30 seconds for recovery even if the display blanks, then press a key and
try the enrolled finger at the lock screen. Use password fallback if needed and
report the result. This Linux thread
cannot perform work while the machine is suspended.

On return, inspect the current-boot journal for `systemd-suspend.service`,
`t2-touchid-resume.service`, and `t2-ncm-recover.service` before any manual
recovery. Distinguish successful automatic rebind from a healthy no-op, a skipped
or failed hook, and a busy operation lock. A successful scan without a recorded
sleep interval does not prove resume acceptance. Do not start enrollment until
this checkpoint is resolved.

## Narrow recovery design

`tools/research/t2-ncm-recover.py` is installed root-owned under
`/usr/local/libexec`. It reads only root-private endpoint configuration and port
cache, acquires the existing Touch ID operation lock (at most 20 seconds), and
validates all of:

- The configured interface's actual sysfs ancestry includes `t2bce_vhci`.
- Its USB driver is exactly `cdc_ncm`, its parent is Apple USB `05ac:8233`, and
  it is interface `:1.0` of that parent. USB vendor `05ac` is not PCI vendor `106b`.
- The interface is up (allowing NetworkManager up to 10 seconds after wake),
  the endpoint is link-local IPv6, and the cached port is within the expected
  ephemeral range.

It attempts three bounded TCP connections, then allows up to 12 additional
seconds for delayed TX errors when the initial error counter is zero.
Connection refusal means the peer
is reachable but the cached service may be stale: that does **not** justify a
rebind. Only repeated unreachability with a nonzero NIC TX-error counter permits
one rebind. The counter is cumulative, so this is a conservative workaround
heuristic, not a proof of the underlying kernel defect. Target validation is
repeated immediately before the write. Bind is attempted in `finally` if the
interface was detached. There is no parent USB reset, sensor reset, keybag load,
Catacomb load, enrollment, deletion, or daemon restart in this helper.

The service caps memory at 64 MiB, tasks at 16, CPU at 50%, total runtime at 75
seconds, and starts at three per ten minutes. It has no restart loop. A busy
operation lock, unexpected device, missing cache, or failed recovery leaves
password fallback in place; these conditions require diagnosis rather than
escalating to a broader reset. Interrupted recovery must also be checked rather
than assumed successful.

`t2-touchid-resume.service` is wanted by `sleep.target`, runs a no-op before
sleep, and queues recovery nonblockingly when the target is stopped after wake.
It does not interact with the frozen user session from a sleep hook. This follows
the installed systemd sleep-target ordering; see the upstream
[sleep service documentation](https://github.com/systemd/systemd/blob/main/man/systemd-suspend.service.xml)
and [special targets](https://github.com/systemd/systemd/blob/main/man/systemd.special.xml).
It is a resume workaround, not a T2BCE kernel fix. Recovery can take several
seconds after wake, so an immediate verification may still require password or
a later retry.

## Accurate matcher error feedback

`tools/research/t2-fprintd-runtime.py` loads the installed external GPL facade
without changing its files. Its source SHA-256 must remain
`1cf34436fe6ae66e98229864b256b3ef1b5a21a772cb74ed50ed98acc840c336`.
An upstream change fails closed until the overlay is reviewed.

The overlay raises an error when there is no terminal match-result event,
instead of reporting `verify-no-match` for missing evidence. Every existing
success/identity/lifecycle check remains delegated to the original facade.
Its existing exception path returns `verify-unknown-error` to the PAM consumer;
the overlay suppresses the misleading rejection notification for that error
and writes a privacy-safe journal message. Actual match/no-match feedback retains
the current quiet-success/silent-rejection-toast behavior. PAM files and Omarchy
core/user configuration were not modified.

## Deployment and rollback

Installed files (all root-owned):

- `/usr/local/libexec/t2-ncm-recover.py` (0755)
- `/usr/local/libexec/t2-fprintd-runtime.py` (0755)
- `/etc/systemd/system/t2-ncm-recover.service` (0644)
- `/etc/systemd/system/t2-touchid-resume.service` (0644, enabled for sleep.target)
- `/etc/systemd/system/fprintd.service.d/t2-runtime.conf` (0644)

Their repository counterparts are under `tools/research/`; the last file's
source is `t2-fprintd-runtime.conf`. Initial installation verified each destination
was absent, used `install -o root -g root` with the above modes, reloaded systemd,
enabled the resume hook, and started recovery. The fprintd restart was protected
by the shared operation lock. No external reference checkout was modified.
This deployment presumes the already-working T2 runtime, private operation lock,
NetworkManager configuration, and credential services; it is not a fresh-machine
Touch ID installer.

To inspect without a touch:

```bash
sudo systemctl start t2-ncm-recover.service
sudo journalctl -u t2-ncm-recover.service -u fprintd.service -n 40 --no-pager
systemctl is-enabled t2-touchid-resume.service
```

Rollback while awake, with no active verification/enrollment: disable
`t2-touchid-resume.service`, confirm it and the recovery service are inactive,
then move `fprintd.service.d/t2-runtime.conf` to an unused filename outside that
drop-in directory. Reload systemd and restart fprintd under the operation lock.
The disabled helpers can remain installed for inspection; no biometric store,
PAM backup, enrollment fixture, or authentication fallback needs deletion.

## Verification

- 145 research tests pass, with two expected skips under system Python (macOS
  platform test and installed-runtime import test).
- The installed runtime's own Python environment separately passes all five
  facade-overlay tests, including the real pinned module import, positive and
  negative decisions, missing terminal results, and source-pin rejection.
- Recovery tests cover exact device validation, healthy/transient no-op,
  closed-port reachability, TX-evidence requirement, busy operation lock,
  changed target refusal, bind-on-unbind-error, and no repeated rebind on failure.
- `systemd-analyze verify` passes for both recovery units and the installed
  fprintd unit with its drop-ins.
- Live recovery and subsequent healthy no-op pass. Shawn confirms successful
  enrolled-finger unlock and rejection of an unenrolled finger after deployment.
  The first actual sleep/wake failed on delayed watchdog evidence, the second
  on interface-up timing. The corrected helper restored the link manually
  without restarting fprintd; automatic sleep/wake acceptance remains pending.
