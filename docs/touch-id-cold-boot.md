# Touch ID cold-boot checkpoint

This checkpoint records the last known-good warm-transition configuration on
the MacBookPro16,1 before cold-boot restoration work begins. It deliberately
contains no password, keybag handle, biometric identifier, Catacomb payload,
network address, or private transfer artifact.

## Preserved implementation state

- Public MIT handoff repository: `main` commit `33987d8`, pushed to
  `bentsignal/t2-omarchy`.
- External GPL implementation worktree: clean local branch
  `t2-v1-first-enrollment` at commit `8d73e26`. Its configured remote is the
  upstream `jmurth1234/t2-touchid-linux` repository, so the local research
  branch has not been pushed without upstream authorization.
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

## Boot ordering at the checkpoint

The following services are enabled and active:

1. `t2-sep-transport.service`
2. `t2-keybag-load.service`
3. `t2-credential-unlock.service`
4. `t2-warm-identity-capture.service`

`t2-biometric-ready.service` and `fprintd.service` are active but intentionally
not boot-enabled. The readiness service performs no sensor reset and succeeds
only when a live, structurally valid, nonempty identity list already exists.

The root-only local Catacomb store contains the expected encrypted master,
selected-user, and biolockout components. Their contents and hashes are not
recorded here because they are private biometric state.

## Cold-boot boundary

Keybag loading and encrypted-credential unlock already run unattended. The
missing transition is restoring the encrypted Catacomb components into the T2
BiometricKit session after those keybags are unlocked and before the no-reset
readiness check. Readiness must remain fail-closed; fprintd must not start until
restoration is complete and a stable nonempty identity inventory has been
verified.

The first implementation must therefore be independently reversible, preserve
password login and PAM rollback, avoid sensor reset, reject stale or malformed
Catacomb state before dispatch, and never print or journal private component
bytes or biometric identifiers.
