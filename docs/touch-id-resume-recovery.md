# Touch ID resume recovery — 2026-09-06

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

Still required: a supervised enrolled-finger positive control, an unenrolled
negative control for the deployed facade overlay, then actual sleep/wake and
matching acceptance. No new enrollment trial was started during this repair.
Native enrollment remains at the status-55 overlay checkpoint described in
`touch-id-enrollment-presence-events.md`.

## Narrow recovery design

`tools/research/t2-ncm-recover.py` is installed root-owned under
`/usr/local/libexec`. It reads only root-private endpoint configuration and port
cache, acquires the existing Touch ID operation lock (at most 20 seconds), and
validates all of:

- The configured interface's actual sysfs ancestry includes `t2bce_vhci`.
- Its USB driver is exactly `cdc_ncm`, its parent is Apple USB `05ac:8233`, and
  it is interface `:1.0` of that parent. USB vendor `05ac` is not PCI vendor `106b`.
- The interface is up, the endpoint is link-local IPv6, and the cached port is
  within the expected ephemeral range.

It attempts three bounded TCP connections. Connection refusal means the peer
is reachable but the cached service may be stale: that does **not** justify a
rebind. Only repeated unreachability with a nonzero NIC TX-error counter permits
one rebind. The counter is cumulative, so this is a conservative workaround
heuristic, not a proof of the underlying kernel defect. Target validation is
repeated immediately before the write. Bind is attempted in `finally` if the
interface was detached. There is no parent USB reset, sensor reset, keybag load,
Catacomb load, enrollment, deletion, or daemon restart in this helper.

The service caps memory at 64 MiB, tasks at 16, CPU at 50%, total runtime at 60
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

- 138 research tests pass, with two expected skips under system Python (macOS
  platform test and installed-runtime import test).
- The installed runtime's own Python environment separately passes all five
  facade-overlay tests, including the real pinned module import, positive and
  negative decisions, missing terminal results, and source-pin rejection.
- Recovery tests cover exact device validation, healthy/transient no-op,
  closed-port reachability, TX-evidence requirement, busy operation lock,
  changed target refusal, bind-on-unbind-error, and no repeated rebind on failure.
- `systemd-analyze verify` passes for both recovery units and the installed
  fprintd unit with its drop-ins.
- Live recovery and subsequent healthy no-op pass; fingerprint and real
  sleep/wake acceptance remain pending.
