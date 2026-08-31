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

Before resetting the sensor or loading a catacomb, Linux will query the fresh
identity list once. If the warm transition preserved an enrolled identity,
the first match test will be supervised and will stop for explicit user
readiness before exactly one touch attempt. If the list is empty, Linux will
decrypt and validate the fresh CMS archive only inside a mode-0700 directory
on the LUKS volume, load the full current catacomb through the bounded probe,
and query again. Boot-scoped ASIDs or process identities will not be replayed
across operating-system boots.

No successful enrollment, matching, or PAM integration is claimed by this
handoff. The encrypted EFI copies should remain as recovery artifacts until
the Linux validation is complete.
