# macOS handoff: encrypted local catacomb comparison

Linux has isolated enrollment status 261 to missing per-user catacomb state.
The current read-only Linux result for UID 501 is: requested/effective policy
`(1,1,1,0)`, maximum identities 5, free identities 3, UID identity count 0,
and `GetCatacombUUID`/state/group-state all rejected. The macOS APFS container
is T2 hardware encrypted and cannot be mounted by Linux `apfs-fuse`.

This pass may copy the existing UID-501 macOS catacomb only as an encrypted,
short-lived local transfer. Never print, inspect, hash, commit, or upload the
catacomb or its encrypted transfer. Do not change or delete the source file or
the enrolled fingerprint.

1. Pull the latest repository and read this file plus `docs/touch-id.md`.
2. Locate the current catacomb used by `biometrickitd`. Static Catalina
   evidence points to a `Library/Catacomb` directory and `*.cat` files. Use
   daemon logs/static xrefs and root-readable filesystem metadata to identify
   the active UID-501 file. Validate only that its size is 33..307200 bytes,
   its first four bytes are `CAT1` (`43 41 54 31`), and its little-endian UID
   at offset 8 is 501. Do not output any other bytes, filename identifier, or
   digest.
3. Mount the internal 2 GiB EFI partition read/write. It contains
   `t2-touchid-transfer-cert.pem`, a two-day throwaway certificate whose
   private key exists only inside Linux's encrypted root filesystem.
4. Encrypt the validated source directly to
   `t2-touchid-transfer.cms` on EFI with CMS/S/MIME enveloped encryption and
   AES-256 using that certificate. Prefer an available Apple/OpenSSL command
   that streams source to destination without an unencrypted temporary copy.
   Verify only that CMS decryption syntax recognizes the envelope structure;
   macOS does not possess the private key and must not decrypt it.
5. Record only success/failure, source byte length, and encrypted byte length
   in the documentation. Do not add either transfer artifact to Git. Commit
   and push documentation/tooling findings only.

Linux will decrypt the transfer directly into root-only local storage, validate
the same magic/UID/size constraints, wrap it in the existing integrity envelope,
remove the short-lived EFI ciphertext, and issue the already bounded
`LoadCatacomb` comparison. This is reverse-engineering evidence, not the final
Linux-native enrollment dependency.
