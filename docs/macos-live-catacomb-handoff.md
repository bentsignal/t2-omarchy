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
