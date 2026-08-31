# macOS live-catacomb handoff

This is a bounded cross-OS collection plan for the next macOS boot. It exists
because Linux can now load and unlock the genuine UID-501 keybag, yet the
fingerprint identity-list reply is empty and the enrollment policy remains
unsatisfied. A fresh catacomb archive and a warm transition from macOS can
test whether daemon-owned biometric state is the missing input.

The macOS and Linux agents run on the same physical Mac and cannot run at the
same time. GitHub `main` is the handoff boundary. The macOS agent must commit
and push its sanitized report before the final reboot; it must not claim that
the Linux agent continues while macOS is active.

## Linux preflight completed

Before this handoff, Linux disabled `fprintd.service` and
`t2-biometric-ready.service`. Both had been enabled for `multi-user.target`,
and the readiness service performs sensor initialization that would destroy
the evidence before the first post-macOS query. The SEP transport, genuine
keybag load, and encrypted-credential unlock services remain enabled. Do not
reenable or manually start either biometric service on macOS or during the
first Linux boot. Their disabled state is intentional and reversible after
the immediate identity-list comparison.

Linux also installed and enabled `t2-warm-identity-capture.service`. It runs
before either reset-capable unit, refuses to proceed unless both remain
disabled and inactive, and sends only Bridge version negotiation plus
read-only UID-501 identity-list command `0x42`. It atomically stores only the
reply status, output length, record count, and structural-validity Boolean in
root-only `/var/lib/t2-touchid/warm-transition-identity.json`; UUIDs, identity
records, peer identifiers, and biometric bytes are never persisted. This
removes the need to race to launch Codex after selecting Linux.

Both reset-capable units also have a temporary condition requiring the absent
runtime marker `/run/t2-touchid/allow-reset-capable-services`. This prevents a
D-Bus activation from bypassing their disabled state after the capture and
resetting a potentially usable warm identity before the supervised comparison.
Do not create that marker during the handoff.

## Safety boundary

- Do not enroll or delete a fingerprint.
- Do not initiate matching or ask for a sensor touch.
- Do not change SIP, Secure Boot, FileVault, or source keybags.
- Never print, inspect in chat, or commit keybag, catacomb, identity, UUID,
  hash, path, or credential contents.
- Keep every plaintext private artifact on the encrypted macOS volume with
  `umask 077`. Transfer it to Linux only as CMS ciphertext.
- Require `/Volumes/EFI/t2-touchid-keybag-transfer-cert.pem`. It is a public
  throwaway certificate whose private key exists only in the LUKS-encrypted
  Linux home. If it is absent, stop and return to Linux.

## Authorized macOS task

1. Pull this repository and confirm this handoff is the newest `main` state.
2. Clone or update `jmurth1234/t2-touchid-linux` outside this MIT repository.
   Record its commit in the sanitized result. Do not copy its GPL source here.
3. Run its current `tools/macos/macos-export-touchid-catacomb.sh --no-reboot`.
   Require the full nonempty `t2-touchid-catacomb.tar.gz`; reject a diagnostic
   or partial result. Do not log archive members. Before encryption, run the
   same checkout's privacy-safe checker as root so the root-owned mode-0600
   archive must contain exactly the current master, bio-lockout, and UID-501
   components and must pass independent semantic readback:

   ```sh
   sudo python3 /absolute/checkout/src/t2-catacomb-fixture-check.py \
     --apple-user-id 501 \
     /absolute/checkout/tools/macos/t2-touchid-catacomb.tar.gz
   ```

   Treat any checker failure as a failed export; do not improvise a loadable
   archive from partial files.
4. Encrypt the archive with AES-256 CMS DER to an atomic EFI temporary name,
   validate the CMS structure, rename it, and `sync`:

   ```sh
   umask 077
   openssl cms -encrypt -binary -aes-256-cbc \
     -in /private/path/t2-touchid-catacomb.tar.gz \
     -outform DER \
     -out /Volumes/EFI/t2-touchid-catacomb.cms.tmp \
     /Volumes/EFI/t2-touchid-keybag-transfer-cert.pem
   openssl cms -cmsout -inform DER \
     -in /Volumes/EFI/t2-touchid-catacomb.cms.tmp -noout
   mv -f /Volumes/EFI/t2-touchid-catacomb.cms.tmp \
     /Volumes/EFI/t2-touchid-catacomb.cms
   sync
   ```

   Adapt only the private input path. Do not weaken the output name or
   encryption boundary.
5. Delete the plaintext archive, its private staging directory, and any
   temporary wrappers after the CMS envelope passes structural validation.
6. Append a sanitized result to this document: success/failure, macOS build,
   upstream commit, CMS byte lengths, whether a full catacomb was obtained,
   and confirmation that plaintext was removed. Commit and push that report
   to GitHub `main` before freezing any daemon.
7. Do not touch the sensor or change Touch ID settings between export and
   reboot. As the final macOS action, stop `biometrickitd` with `SIGSTOP` and
   warm reboot directly to Linux. If reboot cannot proceed, send `SIGCONT`
   before doing anything else. Do not perform further collection after the
   freeze.

## Linux return plan

Before resetting the sensor or loading a catacomb, Linux will inspect the
automatic fresh identity-list capture. If the warm transition preserved an
enrolled identity, the first match test will be supervised and will stop for
explicit user readiness before exactly one touch attempt. If the list is
empty, Linux will
decrypt and validate the fresh CMS archive only inside a mode-0700 directory
on the LUKS volume, load the full current catacomb through the bounded probe,
and query again. Boot-scoped ASIDs or process identities will not be replayed
across operating-system boots.

No successful enrollment, matching, or PAM integration is claimed by this
handoff. The encrypted EFI copies should remain as recovery artifacts until
the Linux validation is complete. After the comparison, Linux may reenable
the two biometric services and disable the temporary capture service only when
doing so cannot overwrite evidence.

## macOS return result

The full live Catacomb export completed on macOS build 25G83 using upstream
commit `558b8f4fd9d90adc6f163ade44dae22c91d712dd`. The unmodified privacy-safe
checker first accepted the exact master, bio-lockout, and UID-501 component
set and decoded all three, but failed while neutrally re-emitting the decoded
zero-identity user graph: the upstream deterministic builder unconditionally
added identity/accessory helper objects, which its own strict reachability
check correctly rejected as unreachable. That failed run produced no CMS and
removed its plaintext and staging directory.

The temporary external GPL checkout received a narrow zero-identity verifier
fix. Neutral secure-data replacement deep-copied the already strictly decoded
graph and replaced only its opaque secure envelope; it still required the
primary strict decoder and independent semantic oracle to agree, and did not
change deletion, enrollment, or nonempty-identity behavior. A dedicated
zero-identity regression plus all existing codec/fixture tests passed (19
tests total). No GPL source was copied into this repository.

The guarded retry passed the complete privacy-safe checker with all three
required components, `identity_count=0`, independent oracle readback, semantic
round-trip equality, preserved opaque envelopes and account/keybag bindings,
and redacted identifiers. The archive was streamed into AES-256 CMS DER using
the EFI public certificate. Final
`/Volumes/EFI/t2-touchid-catacomb.cms` is 1,946 bytes and passed an independent
`openssl cms -cmsout -inform DER -noout` parse. The plaintext archive, private
staging directory, external checkout, and all temporary wrappers were removed.
No source Catacomb, Touch ID setting, fingerprint, or BiometricKit operation
was changed or invoked. The validated CMS and public certificate remain on
EFI for Linux.

This report was committed before the final daemon freeze. The remaining macOS
action is exactly the handoff's `SIGSTOP` of the running `biometrickitd`
followed immediately by a warm reboot to Linux; if reboot scheduling fails,
the helper must send `SIGCONT` before returning.

## Linux return result

The guarded boot capture completed successfully after a bounded interface/port
retry and reported a structurally valid zero-record UID-501 identity list. The
fresh encrypted archive also strictly decodes to zero identities, so this is a
true empty first-enrollment baseline rather than evidence that a macOS identity
was lost during the transition.

Linux privately decrypted and revalidated all three components. The fresh
master and user secure envelopes are byte-identical to the older retained
copies that already returned load status 257, and the bio-lockout component is
valid. The root-only backup and encrypted EFI recovery artifact remain; no
private identifier, digest, envelope, or plaintext archive was committed.

The remaining blocker was initially characterized as a
protocol-1/zero-identity/absent-Catacomb shape, while the upstream experimental
broker assumed protocol 2 and a preexisting identity. A local GPL checkpoint
based on upstream `936a980` is branch `t2-v1-first-enrollment`, commit `703b287`.
It implements strict protocol-1 inventory, baseline, persistence,
reconciliation, and explicitly gated first-identity encoding. Its complete
dependency-independent test suite and build checks pass, and the real private
zero-identity archive passes the new offline codec path. The next Linux gates
are a read-only preflight, one reboot to activate the latest ACM
externalization-capable kernel transport, then a password-authorized policy-only
control before any supervised touch or enrollment.

That read-only preflight has now passed with zero identities, available
capacity, stable same-connection inventory, a verified local store, and no
mutation. The temporary service marker was removed, both reset-capable services
are disabled/inactive again, and the enrollment-journal audit is empty. The
next action is the single Linux reboot needed to replace the boot-pinned old
transport with the already-staged ACM-externalization-capable module.

The Linux reboot, keybag reload, and transient ACM lifecycle checks succeeded.
In the password-authorized policy-only control, command `0x13` externalized the
tracking context, password binding succeeded, policy 1007 became satisfied,
and mandatory context deletion completed; no biometric consumer or mutation
ran. The final post-reboot read-only enrollment preflight also passed with the
same zero-identity protocol-1 baseline. The cross-OS handoff is therefore
complete. Linux can proceed to one explicitly supervised first-enrollment run
without another macOS boot.

That first enrollment attempt accepted the password and satisfied policy 1007,
but its 48-byte protocol-1 start request returned synchronous status 22 before
any touch. This corrected the earlier inference: nil identity lists describe an
empty database, not the request version. The live Bridge handshake negotiated
client version 2, so Linux must retain the 68-byte version-2 built-in request.
The rejected attempt persisted only the refreshed bio-lockout component and
reconciled at E3 with zero identities and no unfinished operation.

The external GPL branch now has local commits `a697957` and `2f264ab` after
`703b287`. They implement the negotiated-version correction, a press-Enter plus
three-second human touch cue, and proof that any locally evolved Catacomb
exactly matches a unique earlier E3 digest before another operation. All 292
tests pass in the installed virtual environment. The corrected root-owned
runtime passed another real no-touch preflight with zero identities, available
capacity, stable same-connection inventory, and the evolved store matched to
the prior E3. The next action remains in the Linux thread: one supervised
version-2 enrollment retry. No additional macOS work or reboot is required.

The first corrected-length version-2 retry still returned synchronous status
22 before any sensor event. Its last 20 bytes were zero, which contradicted the
already pinned current-macOS serializer: built-in enrollment requires group type
1 followed by a zero UUID. External GPL commit `7175f54` now emits the exact
record, and its full 68-byte request matches the independent MIT-repository
serializer byte for byte with a dummy credential. All 292 tests and a fresh
no-touch hardware preflight pass. Linux is ready for one supervised retry; the
macOS thread has no work to perform.

The exact built-in-group retry still returned synchronous status 22 before any
service event, ruling out finger placement. Linux then found that the GPL
coordinator omitted the fresh-database setup already recovered here: global
and UID-501 `NoCatacomb`, mode-0 `SetProtectedConfig` for policy `(1,1,1,0)`,
and exact `GetProtectedConfig` readback, all on the authorized enrollment
connection before command 3. External GPL commit `7f3c8a1` composes and
journals that sequence, scrubs its authorization-bearing request, and fails
closed on every ambiguous result. The dependency-complete suite passes 297
tests, the changed runtime files are installed, and a no-touch hardware
preflight passed without mutation. The next supervised run is Linux-only; do
not reboot to macOS unless a later Linux finding explicitly requests it.

That first composed Linux run accepted the password but stopped at the
protected-policy readback before command 3 or any touch cue. Fresh-connection
reconciliation proved no persistent identity delta and left zero unfinished
operations. External GPL commit `4df6e98` corrects the parser's treatment of a
nonzero getter with nil output and adds privacy-safe status/length/policy-shape
diagnostics; all 299 tests pass and the installed module matches. The next
classification run remains Linux-only.

Its first relaunch stopped before password entry because the evolved-state gate
counted two equivalent E3 journal proofs as two distinct states. No journal or
biometric operation was created. External GPL commit `d93a60d` now requires one
distinct matching snapshot digest while accepting duplicate attestations of
that digest. All 299 tests and a real no-touch evolved-state preflight pass;
the next classification run remains Linux-only.

The next Linux run accepted the password but exposed one interleaved Bridge
service callback during protected-policy readback, still before command 3 or a
touch cue. It was rejected and then reconciled with zero persistent delta.
External GPL commit `3362f5a` now reports only validated public callback-header
metadata (type, version, ordinal, payload length) without payload bytes. All 300
tests pass. A Linux-only password run must identify that callback before it can
be safely queued or ignored.

The callback is version-1 SKS lock state (`0xe3ff800a`), ordinal zero, with a
22-byte payload. Matching-daemon code accepts at least the six-byte UID/state
prefix and permits trailing data; the event does not advance enrollment.
External GPL commit `696c7aa` now validates its exact Bridge framing, version,
minimum shape, and UID 501, then preserves the untouched callback in order for
the existing enrollment reducer. All other setup-time callbacks fail closed.
All 303 tests and a no-touch preflight pass. The next supervised attempt remains
Linux-only and may proceed to command 3.

That attempt accepted the password but failed safely during callback staging,
still before command 3 or any touch cue. Reconciliation again proved zero
identities, no persistent delta, and zero unfinished operations. A generic
setup boundary had hidden the transport's controlled reason. External GPL
commit `64f01b4` now carries that privacy-safe reason through the coordinator;
for an SKS user mismatch it exposes only the numeric Apple UIDs and never the
event payload or credential. All 304 tests and Python compilation pass, the
installed runtime modules byte-match the checkout, and a fresh no-touch
hardware preflight passes without mutation. The next step remains a single
Linux-only password run to classify the setup callback precisely.

That run classified the callback's embedded Apple UID as zero. It again
stopped before command 3 and reconciled to zero identities with no persistent
delta. External GPL commit `0a13de0` treats only a fully validated UID-zero SKS
record received during fresh setup as system-scoped setup state and consumes
it before the UID-501 enrollment reducer exists. UID 501 remains ordered into
the reducer; every other UID and any UID-zero record during active enrollment
still fail closed. All 305 tests pass, the installed modules byte-match, and
status plus no-touch hardware preflight are clean. The next supervised action
is Linux-only and may reach the explicit touch gate; macOS has no requested
work.

The next Linux run completed setup and reached the explicit human gate, but
command 3 synchronously returned status 22 without a service event; the sensor
did not evaluate the touch. Reconciliation completed with zero identities and
zero unfinished operations. That run reused the setup credential in command 3,
which is exactly the device-side replay/one-shot behavior static ACM evidence
could not settle. External GPL commit `7d55f8a` now keeps the same Bridge lease
but uses two separately created, password-authorized, mandatorily deleted ACM
contexts: setup-only, then enrollment-only. All 305 tests and no-touch gates
pass. The next Linux-only supervised run asks for two password entries and
tests only this authorization-lifetime distinction; macOS still has no work.

Both independently authorized contexts succeeded, but the split-context run
still received command-3 status 22 without an event. External GPL commit
`877c82a` removes the disproved split. Review also separated the explicit
accessory-group probe from ordinary built-in enrollment: type 1/zero UUID can
address the built-in sensor, but the exact ordinary Settings/UI path supplies
no accessory-group option, so its v2 suffix remains 20 zero bytes. External
GPL commit `e714986` restores that ordinary request while retaining strict
terminal-result group validation. All 305 tests and no-touch gates pass. The
next Linux-only run uses one password and tests only this request-shape
difference; macOS still has no requested work.

The ordinary zero-group run still returned synchronous command-3 status 22
without any service event. It reconciled cleanly with zero identities and no
unfinished operation, so the request group is not the missing prerequisite and
the presented finger was not evaluated. Linux will move the human touch cue
behind confirmed command-3 acceptance before any further supervised run.

The next Linux-only discriminator is the final Bridge lease's initialization
history. Older experiments performed exact same-session sensor/accessory
initialization but still used the incomplete authorization path that returned
status 261. The current policy-1007 plus fresh-setup coordinator performs its
sensor warm-up on a separate, discarded Bridge connection. Linux will first
run a password-free exact initialization diagnostic on the retained lease,
classify any callbacks, and then combine that sequence with the proven
authorization/setup path. The macOS thread has no requested work.

The password-free retained-lease diagnostic passed on the real T2. It confirmed
service-opened state, readiness, provisioning, first-attempt corrected reset,
post-reset cancellation, type-3 sensor information, calibration present,
exactly one built-in device record, the current nine-word system policy,
consistently absent version-0 catacomb/group state, and xART available. It
emitted no service callback and performed no fingerprint capture.

External GPL commits `282b678`, `f886a92`, `8718650`, and `e08c5cf` move the
human cue behind confirmed command-3 acceptance, implement and integrate the
exact retained-session sequence, and add it to no-touch preflight. All 314
tests pass and the installed runtime matches. The real composed preflight
passed with zero identities, available capacity, stable post-initialization
inventory, a verified local store, and no persistent mutation. Cleanup left
zero unfinished operations, both reset-capable services inactive, and no
temporary marker. The next action remains in the Linux thread: one supervised
password-authorized enrollment run. macOS has no requested work.

That combined Linux run accepted the password, satisfied policy 1007, completed
fresh protected setup, and still received synchronous command-3 status 22 with
no service event. The corrected human gate emitted no touch instruction, so no
finger was evaluated. Reconciliation is complete with zero identities and no
unfinished operation; cleanup left both reset-capable services inactive and no
temporary marker. Retained-lease initialization is therefore disproved.

The next cross-OS task is now macOS-side evidence collection rather than another
Linux password retry. Capture one tightly bounded Add Fingerprint attempt on
only the T2 network interface, keep the raw pcap private, and produce a sanitized
Bridge transcript containing command order, public command/version/value,
input/output lengths, synchronous status, and redacted structural checks. Do
not commit raw credential, UUID, Catacomb, fingerprint, or packet material.

### Next macOS pass: one private Add Fingerprint trace

The macOS thread should fetch `main`, read this section and the cross-OS skill,
then run the checked-in collector from the repository root with a new private
directory:

```bash
tools/research/capture-macos-enrollment-bridge.sh \
  "$HOME/t2-enrollment-private-$(date +%Y%m%d-%H%M%S)"
```

While its 120-second window is active, Shawn should open Touch ID settings,
begin Add Fingerprint with a finger not already enrolled, complete at least the
first accepted scan, and then cancel if he does not want to finish adding it.
The goal is an unquestionably accepted macOS command 3 and its immediate
predecessors, not another permanent identity.

The collector restricts tcpdump to `ac:de:48` T2 interfaces and generates one
`*-sanitized-enrollment.json` per pcap. Review those summaries locally. If they
report zero connections, debug the sanitizer against the private pcap without
printing or committing raw objects. Compare the real macOS command order and
the redacted command-3 structure with Linux's path: wrapper version/value,
input length, output capacity, flags, numeric UID, mode, credential length and
padding, optional device-group representation, synchronous status, and callback
headers. Never print the 16-byte credential, UUIDs, addresses, ports, packet
bytes, or callback payloads. Keep the entire private directory out of Git.

Commit and push only tooling fixes, tests, and a prose conclusion that states
the first proven difference (or byte-structural equality) and the exact next
Linux discriminator. The macOS thread should then tell Shawn to return to the
Linux thread; it must not imply that this Linux thread ran concurrently.

### 2026-08-31 macOS enrollment result and next Linux discriminator

Before either trace, the Touch ID settings UI showed **no enrolled fingers**.
That was unexpected to Shawn, who remembered enrolling one during macOS setup,
but it confirms that the earlier empty live identity list and zero-identity
Catacomb represented the real machine state. The absence explains why matching
could not possibly succeed; it does not explain Linux's synchronous command-3
status 22, which occurs before any finger is evaluated.

During the first private trace Shawn completed a new fingerprint enrollment.
The macOS UI now definitely contains one enrolled finger. This state change is
important: the previously transferred Catacomb/CMS was captured while there
were zero identities and is now stale for any attempt to match the newly
enrolled finger. Do not describe or load that older archive as current macOS
identity state. A future matching experiment needs a fresh privacy-preserving
export, while a deliberate Linux first-enrollment baseline may still choose to
retain zero identities.

Both private T2 pcaps contained only their 24-byte headers. A second trace with
exact-interface `pktap` also reported zero captured, received, and dropped
packets. This is the already documented macOS 26 BPF/pktap limitation, not
evidence that Bridge traffic was absent. Do not request another enrollment
ceremony solely to repeat packet capture. The first run captured the complete
successful enrollment in the private unified log; the second captured a
separate first accepted scan followed by cancellation. Both raw directories
remain outside Git with owner-only permissions.

The checked-in strict log sanitizer recovered the same accepted start from
both runs (137 generic commands in the complete run and 151 in the partial
run). The complete enrollment records `enroll` mode 1 for Apple UID 501 with
status zero. Its command 3 is version 2, value zero, has 68 input bytes, and
returns synchronous status zero. The three immediate predecessors are:

1. `0x52`, version 1, value zero, zero input bytes, status zero;
2. `0x54`, version 1, value zero, 20 input bytes, status zero;
3. `0x0c`, version 1, value zero, zero input bytes, status zero.

After the accepted start, the log shows the expected repeated `0x08`/`0x0e`
progress traffic. The private log format does not expose the Bridge wrapper's
output-capacity argument, credential flags/padding, or optional group bytes;
those remain established only by the existing static serializer evidence, not
by this runtime log.

The first proven live ordering difference is command `0x54`. Linux's retained
enrollment lease performs the built-in device-list command `0x52`, but has not
performed `0x54` before command 3. Current biometrickitd static evidence maps
`0x54` to its read-only `accessoryInfo:` query: version 1, value zero, a 20-byte
input consisting of type 2 plus the built-in accessory UUID, and an 83-byte
output. The method requires status zero, exactly 83 returned bytes, and a
nonzero first output byte.

The next Linux discriminator is therefore one bounded, read-only `0x54` on the
final retained enrollment lease immediately after `0x52`. For the built-in
accessory, serialize little-endian type 2 followed by the canonical zero UUID;
allocate exactly 83 output bytes; validate only status zero, returned length
83, and first byte nonzero; never print or persist the returned bytes. Then
send the already recovered `0x0c` cancellation and run the existing cleanup.
Only if this preflight matches macOS should Linux integrate the sequence and
justify one supervised enrollment retry. The live ordering difference is
proven; whether it causes the status-22 rejection is not yet proven.

### 2026-08-31 Linux return result and warm-state discriminator

The first boot-time capture after the successful macOS enrollment completed
before any Linux reset-capable service. Its privacy-safe result reported status
zero, 40 returned identity-record bytes, and two structurally valid records.
This proves that macOS's newly enrolled state was visible across the reboot;
the macOS settings result was not merely host-side metadata. The capture took
several connection retries because the link-local interface was not initially
ready, but eventually completed successfully without resetting the sensor.

Linux then implemented the bounded `0x52`/`0x54`/`0x0c` discriminator in the
external GPL checkout. On a normally initialized (and therefore reset) sensor,
`0x54` returned synchronous status zero and an exact 83-byte output, but the
required first-byte accessory-present flag was zero. The bytes were neither
printed nor persisted. A separate strict session diagnostic then confirmed
that version-0 Catacomb and group state were absent after reset. Inserting
`0x54` into enrollment is therefore not yet justified: the command shape is
accepted, but its semantic prerequisite is missing in the reset Linux state.

The next discriminator is a no-reset `0x54` query immediately after another
macOS-to-Linux warm transition. It must run before `warm_sensor`, sensor-session
initialization, fprintd, or the biometric-readiness service. Compare only the
public status, returned length, and first-byte-present Boolean, then cancel. If
the flag is nonzero only in the macOS-warmed state, the remaining enrollment
gap is the Catacomb/accessory-load lifecycle before command 3, not the `0x54`
serializer itself. If it remains zero, recover an earlier prerequisite from
the sanitized successful macOS command window before any further enrollment
attempt.
