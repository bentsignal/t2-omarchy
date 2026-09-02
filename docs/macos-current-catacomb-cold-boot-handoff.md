# macOS handoff: current Catacomb for Linux cold boot

This is a one-machine, two-OS handoff. The Linux and macOS Codex threads are
separate and cannot run concurrently. GitHub `main` is the durable boundary.
The macOS thread must fetch and fast-forward `main`, perform only the bounded
task below, append a sanitized result here, commit and push it, then reboot to
Linux. Never imply that the Linux thread continues while macOS is running.

## Why this pass is required

Warm Linux Touch ID is proven through fprintd, the Omarchy lock screen,
Polkit, and sudo. The live T2 currently reports a stable nonempty identity
inventory and matches the enrolled finger. However, Linux's root-only local
Catacomb and its backup both semantically describe the older zero-identity
baseline. Loading either after a cold boot would not restore the enrolled
finger.

The only authorized objective of this macOS pass is to export the *current*
complete `/Library/Catacomb` backing store, encrypt it to the existing Linux
transfer certificate, and return immediately to Linux. This is preservation,
not enrollment or matching research.

## Safety boundary

- Confirm in macOS Touch ID settings that the enrolled fingerprint is still
  listed. Do not add, remove, rename, or test a fingerprint.
- Do not change SIP, Secure Boot, FileVault, passwords, users, or keybags.
- Never print, inspect in chat, or commit Catacomb contents, identity records,
  UUIDs, hashes, credentials, archive member paths, or biometric bytes.
- Plaintext private artifacts must remain in a root-owned mode-0700 temporary
  directory on the encrypted macOS volume and must be deleted in the same run.
- Transfer only AES-256 CMS DER ciphertext to EFI. Never place a plaintext
  archive on EFI or in a Git checkout.
- Require `/Volumes/EFI/t2-touchid-keybag-transfer-cert.pem`. It is a public
  throwaway certificate; if it is absent, stop and return to Linux.
- Use the new output name
  `/Volumes/EFI/t2-touchid-catacomb-current.cms`. The older
  `t2-touchid-catacomb.cms` is the confirmed zero-identity baseline and must
  remain untouched as rollback evidence.

## macOS procedure

1. Fetch and fast-forward this repository. Read this file and
   `docs/touch-id-cold-boot.md` before acting.
2. Confirm the fingerprint is present in Touch ID settings, then close System
   Settings. Do not touch the sensor again during this pass.
3. Mount EFI if needed and verify that the public transfer certificate exists.
4. Locate the existing external GPL `t2-touchid-linux` checkout used by the
   macOS thread. Do not copy GPL source into this MIT repository. Use its
   privacy-safe fixture checker to validate the captured full archive as Apple
   user 501. Validation must establish all three required components and a
   nonzero selected-user identity count without printing identifiers or archive
   members. If the checker cannot establish a nonzero current archive, stop;
   do not overwrite any EFI artifact.
5. Perform the snapshot and encryption with this fail-closed lifecycle:

   - set `umask 077` and create a root-owned mode-0700 temporary directory on
     the encrypted macOS volume;
   - find the running `biometrickitd`, send it `SIGSTOP`, and record only that
     the freeze succeeded;
   - archive the complete `/Library/Catacomb` into that private directory;
   - send `SIGCONT` immediately after the snapshot is closed;
   - run the external GPL privacy-safe fixture checker against the private
     archive and require success plus a nonzero selected-user identity count;
   - encrypt the archive using the existing certificate:

     ```sh
     openssl cms -encrypt -binary -aes-256-cbc \
       -in /private/root-only/current-catacomb.tar.gz \
       -outform DER \
       -out /Volumes/EFI/t2-touchid-catacomb-current.cms.tmp \
       /Volumes/EFI/t2-touchid-keybag-transfer-cert.pem
     openssl cms -cmsout -inform DER \
       -in /Volumes/EFI/t2-touchid-catacomb-current.cms.tmp -noout
     mv -f /Volumes/EFI/t2-touchid-catacomb-current.cms.tmp \
       /Volumes/EFI/t2-touchid-catacomb-current.cms
     sync
     ```

   - remove the plaintext archive and its temporary directory, even on error;
   - if any step fails while the daemon is frozen, send `SIGCONT` before
     returning. Never leave `biometrickitd` stopped except during the final
     immediate reboot below.

6. Append a sanitized result to this document and push it to `main`. Record
   only success/failure, the macOS build, external GPL commit, CMS byte length,
   whether exactly the required component classes were validated, whether the
   selected-user identity count was nonzero, whether CMS parsing passed, and
   whether all plaintext was removed. Do not record the identity count itself,
   identifiers, private paths, hashes, or filenames discovered inside the
   archive.
7. As the final macOS action, freeze `biometrickitd` again and immediately warm
   reboot to Linux. If reboot scheduling fails, resume the daemon before doing
   anything else. Select Linux/Omarchy at startup.

## Linux return plan

On return, the Linux thread will first fetch the sanitized report and verify
the new CMS envelope exists without decrypting it to a persistent path. It
will decrypt and strictly validate the archive only inside a root-owned
mode-0700 temporary directory on the LUKS volume. It will then implement a
reversible, fail-closed restore service ordered after credential unlock and
before biometric readiness. The first actual cold shutdown will happen only
after that service, its rollback path, and the no-reset verification gate are
installed and tested.

The first cold-boot acceptance test is: unattended keybag and credential
unlock; strict current-Catacomb validation; ordered general, selected-user, and
biolockout restoration; stable nonempty identity inventory; then successful
fprintd positive and negative controls followed by lock-screen, Polkit, and
sudo checks. Password fallback must remain available throughout.

## macOS return result

Pending.
