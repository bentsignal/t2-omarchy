# Touch ID cold-boot checkpoint

This checkpoint records the last known-good warm-transition configuration on
the MacBookPro16,1 before cold-boot restoration work begins. It deliberately
contains no password, keybag handle, biometric identifier, Catacomb payload,
network address, or private transfer artifact.

## Preserved implementation state

- Public MIT handoff repository: cold restoration implemented through commit
  `d282c08` on `main`, pushed to `bentsignal/t2-omarchy` before this checkpoint
  update.
- The external GPL checkout remains reference-only. It is not the project
  implementation or a cross-OS handoff worktree and must not be modified,
  installed, or pushed as part of this work.
- The deployed fprintd facade is byte-for-byte identical to the tested GPL
  source at SHA-256
  `1cf34436fe6ae66e98229864b256b3ef1b5a21a772cb74ed50ed98acc840c336`.
- The four deployed PAM profiles are byte-for-byte identical to their tested
  templates. Exact rollback state is stored root-only under
  `/var/lib/t2-touchid/pam-backups` for the Omarchy password and fingerprint
  services, Polkit, and sudo.
- The request and successful-match desktop feedback hooks are no-ops. A
  rejected fingerprint produces one notification with no sound.

## Proven behavior before cold-boot work

- A retained macOS-warm identity inventory contains two structurally valid
  records.
- The enrolled finger matches and an unenrolled finger is rejected through the
  stock fprintd D-Bus interface.
- Fingerprint authentication succeeds through the Omarchy lock screen,
  Polkit, and a forced real sudo PAM control.
- The successful match remains the fail-closed all-users pre-arm sequence on
  bridgeOS `23P6068`, with the terminal identity UUID attested against the
  scoped Apple-user inventory.

## Boot ordering at the warm checkpoint

The following prerequisite services are enabled and active:

1. `t2-sep-transport.service`
2. `t2-keybag-load.service`
3. `t2-credential-unlock.service`
4. `t2-warm-identity-capture.service`

`t2-current-catacomb-restore.service`, `t2-biometric-ready.service`, and
`fprintd.service` are now boot-enabled. The restore remains inactive in this
already-warm session and is armed for the first cold acceptance boot by a
root-owned, mode-0600 local marker. The readiness service performs no sensor
reset and succeeds only when the restore has completed and a live,
structurally valid, nonempty identity list exists.

The root-only local Catacomb store now contains the freshly exported,
structurally validated, nonempty master, selected-user, and biolockout
components. The previous zero-identity store is preserved in a separate
root-only rollback directory. Both stores have exactly three mode-0600 files
under mode-0700 directories, and no temporary plaintext remained after import.
Their contents, identifiers, paths, and hashes are intentionally not recorded.

## Cold-boot boundary

Keybag loading and encrypted-credential unlock already run unattended. The
missing transition is first acquiring the current encrypted Catacomb from the
macOS backing store, then restoring its components into the T2 BiometricKit
session after those keybags are unlocked and before the no-reset readiness
check. Readiness must remain fail-closed; fprintd must not start until
restoration is complete and a stable nonempty identity inventory has been
verified.

The first implementation must therefore be independently reversible, preserve
password login and PAM rollback, avoid sensor reset, reject stale or malformed
Catacomb state before dispatch, and never print or journal private component
bytes or biometric identifiers.

The bounded acquisition procedure is recorded in
[the current-Catacomb macOS handoff](macos-current-catacomb-cold-boot-handoff.md).

## Current MIT restore implementation

The accepted implementation lives entirely in this public MIT repository.
Commit `4130b26` adds an explicitly gated cold-restore service and a
same-connection restore primitive that:

1. strictly validates an exact three-component local store;
2. rejects the store before dispatch if its selected-user identity set is
   empty;
3. loads master, selected-user, and biolockout components in that order;
4. stops on the first nonzero Bridge status; and
5. requires two byte-identical, structurally valid, nonempty selected-user
   identity replies before declaring success.

Commit `d282c08` additionally serializes warm capture and cold restoration on a
shared runtime lock and orders restoration after warm capture, removing a boot
race without resetting the sensor. Biometric readiness requires restoration
and independently retains its own nonempty no-reset identity gate; fprintd is
ordered after readiness.

The implementation, importer, validator, unit/drop-in installation, and
protocol codecs pass 563 tests, with one expected macOS-only skip. systemd unit
verification passes. Installed executable and unit copies match their
committed sources. An offline validation of the installed restore against the
private current store passes with a nonempty identity set.

The host-encrypted unattended credential was reprovisioned after discovery
that the prior credential file was absent. Its mode is root-only, host-key
decryption succeeds, and the real `t2-credential-unlock.service` successfully
validated and unlocked both loaded keybags. No password or credential bytes are
recorded here. This closes the pre-Catacomb cold-boot prerequisite without
changing the live biometric state.

## Repository ownership correction

The external `t2-touchid-linux` checkout is reference-only. The prototype
recorded above at commit `826a86e` is not accepted project implementation and
must not be modified, installed, pushed, or treated as the durable handoff.
All cold-restore implementation and tests must be created in this repository.

## Current-Catacomb acquisition and Linux validation

macOS commit `4f05395` exported the current nonempty Catacomb on macOS build
`25G83` using the in-repository validator. Before import, Linux independently
decrypted the encrypted transfer into a root-only temporary directory,
validated its exact three-component schema and semantic round trip with the
in-repository validator, and removed the plaintext. The atomic importer then
installed it while preserving the earlier zero-identity baseline for rollback.

The boot service first requires two byte-identical, structurally valid identity
inventories for the configured user. If they are nonempty and the protected
policy is valid, it succeeds without cancellation, calibration upload, reset,
or Catacomb loading. Only an empty stable inventory reaches the experimental
fallback, which loads bridgeOS FDR calibration and then the general,
selected-user, and biolockout Catacomb components in order. It stops on the
first protocol error and requires another stable nonempty inventory before
success. It never resets the sensor. A failed run prevents readiness and
fprintd from starting; password authentication remains available.

## First cold acceptance test

The machine is now armed for one controlled full shutdown and default Linux
boot. EFI order places Limine/Linux first and macOS second. On return, inspect
the current-boot service order and safe restore result before any retry. Only
after a successful restore and stable nonempty inventory should the stock
fprintd positive and negative controls, lock screen, Polkit, and sudo be
retested. Do not blindly repeat a failed mutating restore.

## First cold acceptance result

After a complete shutdown and default Linux boot, the unattended genuine
keybag load and encrypted-credential unlock both succeeded. Crucially, the
boot-time capture taken before any restore command already reported a stable,
structurally valid, nonempty identity inventory. This proves the enrolled T2
identity state survives a full shutdown on this machine when Linux avoids the
old reset-capable startup path.

The initial service did not yet check for that state. It unnecessarily loaded
calibration and attempted the master component, which the already-populated T2
rejected with status 257. The service failed closed, and readiness and fprintd
remained off. A later read-only check still found the same nonempty inventory
and valid protected policy, confirming the rejection did not erase the live
identities. The arm marker was moved aside before further work.

The corrected service now short-circuits on the proven preexisting state using
only two identity reads and one protected-policy read. Offline tests prove that
this branch dispatches no biometric mutation. The unit also permits only one
failed start per hour, preventing the three dependency-driven retries observed
on the first boot. A second cold acceptance boot must prove automatic readiness,
fprintd startup, and positive/negative fingerprint verification.

The corrected installed service was then exercised on the same first cold
boot. It reported that restoration was not required, loaded zero components,
and passed its stable nonempty identity and protected-policy gates. The
no-reset readiness service and fprintd subsequently started cleanly. Through
the stock `fprintd-verify` client, the macOS-enrolled finger returned
`verify-match (done)` with exit status zero, while a separately supervised
unenrolled finger returned `verify-no-match (done)`. This proves real cold-boot
matching and rejection on the retained T2 state. It does not yet prove that the
corrected chain starts automatically, because those three services were
started manually after installing the fix during this boot.
