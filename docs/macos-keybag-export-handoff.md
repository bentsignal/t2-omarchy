# macOS keybag export handoff

This is a temporary cross-OS discovery handoff for one physical dual-boot T2
Mac. Linux and macOS are separate Codex threads and only one OS/thread is
active at a time. GitHub `main` is the control plane. Never claim that the
inactive thread is still working.

## Why this pass is needed

Linux now creates an ACM context for Apple UID 501 and sends the exact
`TouchIdEnrollment` policy request. The preflight correctly reports passcode
requirement type 1. AKS selector 42 with canonical option `0x200` then reports
`authorized=yes`, conclusively accepting the entered macOS password, but the
committed policy remains unsatisfied with the same requirement.

The remaining controlled discriminator is keybag identity. Linux currently
creates a fresh type-0 keybag and promotes it to special selector `-501`; it is
not the established macOS UID-501 login keybag that the real enrollment path
resolves from caller handle `-3`. No genuine `user.kb`, `*.kb`, or
`t2-keybags.tar.gz` export exists on the Linux filesystems. Linux also cannot
mount the 128 GiB encrypted APFS container directly.

## Authorized macOS task

Export the current machine's AppleKeyStore keybag candidates using the
GPL-2.0 reference implementation at
<https://github.com/jmurth1234/t2-touchid-linux>, then transfer the resulting
private archive to Linux only as CMS ciphertext. Do not copy reference source
into this MIT repository.

1. Pull this repository and confirm this handoff is the newest `main` state.
2. Confirm `/Volumes/EFI/t2-touchid-keybag-transfer-cert.pem` exists. It is a
   throwaway public certificate; its private key exists only in the
   LUKS-encrypted Linux home. If the file is absent, stop and return to Linux.
3. Clone or update `jmurth1234/t2-touchid-linux` outside this repository. Run
   its `tools/macos/macos-export-keybags.sh` as the logged-in macOS UID-501
   user. Allow the normal administrator-password prompt. Never print, inspect,
   or paste candidate contents into chat.
4. Require the helper's private `tools/macos/t2-keybags.tar.gz` output to be a
   nonempty regular file owned/readable only by the current user or root.
5. Stream that archive into an atomic AES-256 CMS DER envelope using the EFI
   certificate. A suitable shape is:

   ```sh
   umask 077
   openssl cms -encrypt -binary -aes-256-cbc \
     -in /absolute/private/path/t2-keybags.tar.gz \
     -outform DER \
     -out /Volumes/EFI/t2-keybags.cms.tmp \
     /Volumes/EFI/t2-touchid-keybag-transfer-cert.pem
   openssl cms -cmsout -inform DER \
     -in /Volumes/EFI/t2-keybags.cms.tmp -noout
   mv -f /Volumes/EFI/t2-keybags.cms.tmp /Volumes/EFI/t2-keybags.cms
   sync
   ```

6. Delete the plaintext `t2-keybags.tar.gz` after the CMS envelope passes the
   structural check. Never add either artifact, candidate paths, keybag bytes,
   hashes, account UUIDs, or credentials to Git.
7. Append a sanitized result here: success/failure, macOS build, CMS byte
   length, and confirmation that the plaintext archive was removed. Commit and
   push only that report to GitHub `main`.
8. Tell the user to reboot into Linux. Do not claim Linux continues while
   macOS is active.

Do not enroll/delete a fingerprint, change SIP/Secure Boot, modify the source
keybags, or run a biometric command during this handoff.

## Linux return plan

Linux will verify and decrypt `/boot/t2-keybags.cms` with the private key under
`~/.local/state/t2-touchid-debug-20260830/keybag-transfer-key.pem` and matching
`keybag-transfer-cert.pem`, inspect the archive under a
mode-0700 directory on the LUKS volume without logging private paths or bytes,
and identify the established UID-501 keybag. The first hardware comparison
will be policy authorization only: no BiometricKit enrollment command and no
fingerprint touch. The encrypted EFI artifact and all decrypted temporary
copies will be removed after the bounded comparison.

## macOS return result

The export completed on macOS build 25G83 using upstream commit
`a3c0f113210cb9365ae48c2e20056063dbe6ef71`. The unmodified upstream script's
first run exposed a permission bug: its UID-501 shell could not open the
root-owned candidate list, so its superficially successful archive contained
no candidate copies. The resulting 1,658-byte CMS was rejected and deleted.

The temporary external checkout was retried with only the candidate-list read
routed through `sudo`, plus a fail-closed check requiring at least one
anonymized `candidate-NNNN` archive entry before encryption. The final
`/Volumes/EFI/t2-keybags.cms` is 32,042 bytes and passed independent
`openssl cms -cmsout -inform DER -noout` parsing. Its plaintext
`t2-keybags.tar.gz`, the upstream private work directory, the external clone,
and the temporary wrappers were removed. The EFI public certificate and final
CMS ciphertext remain for Linux. No candidate paths or bytes were printed or
committed, no source keybag was changed, and no BiometricKit or fingerprint
operation was performed.
