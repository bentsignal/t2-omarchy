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

## macOS return result: transfer stopped on format mismatch

The requested validation failed closed before mounting EFI or creating any
transfer artifact. The active UID-501 source exists and is 708 bytes, within
the requested size bound, but it is an Apple binary keyed archive rather than
a raw `CAT1` transport blob. Its first four bytes are not `CAT1`, and offset 8
is not a little-endian UID. A metadata-only traversal confirmed that none of
the three current `.cat` archives, nor any data object embedded in them, begins
with `CAT1`. No source was changed, copied, hashed, uploaded, or committed, and
no plaintext or ciphertext temporary file was created.

The installed macOS 26.6.2 daemon explains the mismatch. Its archive layer
stores separate keyed fields including `CatacombSecureData`,
`CatacombIdentityList`, `CatacombUserID`, and version/UUID metadata. During
load, the superclass archive path reconstructs a component object. Current
Mesa `loadCatacombForComponent:` then obtains that component's decoded secure
data and passes the opaque data object's bytes and length directly to
`performLoadCatacombCommand:inData:`. That method issues outer command `0x40`
with those bytes; it does not pass the on-disk keyed archive as the command
payload and does not construct or validate a host-side `CAT1` header.

This disproves the proposed direct-file transfer and the current Linux rule
that command-`0x40` input must be a `CAT1` blob with UID at offset 8. Do not
relax that rule and send arbitrary archived bytes. Linux must first implement
and test a bounded parser for the macOS keyed archive or otherwise recover the
exact `CatacombSecureData` extraction semantics, while treating all extracted
bytes as opaque biometric material. It must also reconcile its KDK-derived
header interpretation with this checksum-pinned current-daemon call path.

After that correction, a new handoff may authorize streaming the entire
validated keyed archive through CMS to EFI. Linux can decrypt it only into a
root-only temporary input, extract exactly the secure-data object without
logging values, then send only that object to command `0x40`. This pass did not
perform that broader transfer because it was outside the original validation
gate and would have produced an artifact the current Linux loader rejects.

## Authorized follow-up: encrypt only decoded secure data

Linux now has a distinct, bounded one-shot loader for current macOS's decoded
`CatacombSecureData`; it does not weaken the separately retained KDK save-blob
validator. Perform this narrower transfer on macOS:

1. Revalidate the active keyed archive by its known path/ownership, byte length
   708, decoded `CatacombUserID` 501, and the archive structure established
   above. Do not require or synthesize `CAT1`.
2. Decode only the `CatacombSecureData` `NSData` through the same Foundation
   keyed-archive semantics used by the daemon. Require a nonempty length no
   greater than 307200 bytes. Do not print, hash, retain separately, or inspect
   the bytes.
3. Stream those decoded bytes directly into CMS/S/MIME AES-256 enveloped
   encryption using `t2-touchid-transfer-cert.pem` on the mounted 2 GiB EFI
   partition. Write only `/Volumes/EFI/t2-touchid-transfer.cms`; use an atomic
   temporary ciphertext name if needed, never a plaintext temporary file.
4. Record only success/failure, decoded secure-data byte length, and ciphertext
   byte length. Do not commit or upload the CMS artifact. Leave the source
   archive and enrolled fingerprint untouched. Commit and push only the
   sanitized report/tooling.

Linux will decrypt this ciphertext directly to a mode-0600 root-only temporary
file, run the separately confirmed one-shot command-`0x40` load, report only
status/policy length/identity count, and remove both temporary ciphertext and
plaintext immediately afterward.
