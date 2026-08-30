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

## macOS return result: decoded secure-data transfer complete

The authorized follow-up completed successfully. The active archive was
revalidated as root-owned, 708 bytes, structurally decodable by Foundation,
and carrying decoded UID 501. Foundation decoded a single nonempty
`CatacombSecureData` object of 104 bytes and streamed it directly to CMS
enveloped encryption; no plaintext temporary file was created.

The final EFI artifact is `/Volumes/EFI/t2-touchid-transfer.cms`, is 661 bytes,
and was produced with AES-256 for the throwaway certificate already placed on
EFI by Linux. OpenSSL's CMS parser accepted the resulting DER envelope
structure. macOS did not possess or use the private key and did not attempt
decryption. The source archive and enrolled fingerprint were untouched, and
neither source data nor ciphertext was printed, hashed, committed, or uploaded.

Linux may now follow the bounded one-shot procedure in commit `fecaba1`:
decrypt directly into its mode-0600 root-only temporary input, require exactly
the expected 104-byte decoded payload, issue command `0x40` once, report only
status/policy length/identity count, and remove both temporary artifacts.

## Linux return result and two-component follow-up

Linux decrypted the CMS envelope to the exact reported 104-byte payload and
issued one current command `0x40`. The host accepted the envelope, but the
biometric service returned status 257. Linux then removed the plaintext,
ciphertext, certificate, private key, and certificate copy as promised. No
transferred material remains.

The leading untested difference is the already observed macOS startup order:
macOS loads its non-user/general catacomb component before UID 501, whereas the
first comparison transferred only UID 501. The Linux probe now supports exactly
two decoded secure-data inputs and sends the general component first, then the
UID-501 component on one Bridge connection.

For the next macOS pass, generate a new transfer from the active archives:

1. Identify the exact non-user/general component loaded immediately before UID
   501 by current `biometrickitd`. Record only its decoded `CatacombUserID` (if
   present) and archive/secure-data lengths. Do not output archive filenames,
   UUIDs, hashes, or data.
2. Decode the general and UID-501 `CatacombSecureData` objects independently.
   Require each to be nonempty and at most 307200 bytes.
3. Encrypt them directly with the new EFI certificate to
   `t2-touchid-transfer-global.cms` and `t2-touchid-transfer-user.cms`.
   Never create plaintext temporary files. Validate only CMS structure and
   ciphertext lengths.
4. Leave all source archives and the enrolled fingerprint untouched. Commit
   and push only a sanitized report; never commit either CMS file.

## macOS return result: two-component transfer complete

The two active components were identified through Foundation keyed-archive
decoding without exposing filenames or opaque values. The general component
has decoded UID `-1`, a 599-byte archive, and 148 bytes of secure data. The
user component has decoded UID 501, a 708-byte archive, and 104 bytes of secure
data. Each archive is root/wheel-owned and each secure-data object is unique,
nonempty, and within the 300 KiB bound.

Both secure-data objects were streamed directly into separate AES-256 CMS DER
envelopes using the new throwaway EFI certificate. No plaintext temporary file
was created. The final artifacts are:

- `t2-touchid-transfer-global.cms`: 718 bytes, wrapping 148 bytes;
- `t2-touchid-transfer-user.cms`: 669 bytes, wrapping 104 bytes.

OpenSSL accepted both final CMS structures without decryption. The sources and
enrolled fingerprint were untouched, and no opaque data or ciphertext was
printed, hashed, committed, or uploaded. Linux should decrypt and load the
general component first and UID 501 second on the same Bridge connection, then
remove all temporary transfer material as specified by commit `400af66`.

## Linux return result: general component rejected

Linux decrypted both payloads to the exact reported lengths and issued the
general component first on a freshly initialized Bridge connection. The
general command-`0x40` request itself returned service status 257, so the user
component was not sent. Linux removed both plaintexts, both CMS files, the EFI
certificate, and both Linux key files immediately afterward. No transfer
material remains.

This rules out user-component ordering. Do not transfer either catacomb again
yet. The next macOS pass is static/read-only only and must recover:

1. The exact Bridge command version, `inValue`, input size/source, output
   pointer/size, and device-group argument (if any) used by current 25G83
   `performLoadCatacombCommand:inData:` for command `0x40`. The Linux attempt
   used KDK-derived version 1, `inValue=0`, direct bytes, and no output.
2. Every BiometricKit Bridge method or biometric command performed after
   connection initialization/accessory caching and before the first general
   `loadCatacombForComponent:` call. Record command/method IDs, versions,
   non-secret payload shapes, and ordering only.
3. Any current binary enum/string/control-flow evidence naming service status
   257, especially device-group/accessory/component failures.

Do not decode, transfer, print, hash, or modify catacomb data; do not enroll,
remove, or touch a fingerprint. Add checksum-pinned evidence tooling/tests,
update this file and `docs/touch-id.md`, commit, and push `main`.

## macOS return result: load ABI matches; initialization context does not

Static inspection of the installed macOS 26.6.2 (25G83) `biometrickitd`
x86_64 slice, SHA-256
`248d4521007f95c916ae682c1a3d13d1c431626f4be4e84a0758d6dfbc94ce20`,
proves that Linux already reproduced the current load envelope exactly.
`performLoadCatacombCommand:inData:` sends command `0x40` through the
compatibility wrapper, which inserts version 1. It uses `inValue=0`, passes
the supplied `NSData` bytes and exact length directly, requests no output,
and supplies no device-group argument. Do not change that framing and do not
transfer either catacomb again.

The missing distinction is earlier connection-local sensor context. Current
startup gets Bridge version with method 0, sets client version 2 with method
10 when the Bridge version is greater than one, and opens/checks the service
with method 1. Its successful sensor path then has these statically recovered
command shapes before the first general load:

1. `checkSensorReadiness`: command `0x53`, version 1, `inValue=0`, no input,
   one-byte output.
2. `cachePatch`: conditional internal-build path only; command `0x24`, version
   1, `inValue=0`, patch bytes as input, no output. Normal 25G83 startup gives
   no evidence that this optional command was issued.
3. `provisioningState`: command `0x10`, version 1, `inValue=0`, no input,
   exact four-byte output. The observed boot returned state 5.
4. `setMSRkData:`: conditional on provisioning state; command `0x5c`, version
   1, `inValue=0`, opaque MSRk bytes as input, no output. Do not synthesize or
   send those bytes.
5. `resetSensor`: command `0x02`, explicit version 2, `inValue=0`, no input or
   output, with at most three host retries.
6. `cacheSensorInfo`: command `0x35`, version 1, `inValue=0`, no input, exact
   12-byte output.
7. `setCalibrationData:source:`: command `0x20`, version 1; `inValue` is the
   calibration source, and the calibration `NSData` bytes/length are the
   input, with no output. The observed successful boot used source 0. Do not
   guess or transfer calibration bytes.

After `initSensor` succeeds, the host calls `cacheAccessories`, which builds
its accessory/device-group state from cached sensor information, immediately
before loading the general component. No separate direct Bridge command was
found for `cacheAccessories`. Sanitized live boot logs confirm the resulting
order: readiness, sensor initialization, accessory caching, general load,
then UID-501 load.

The load wrapper normalizes only raw statuses `0x8002`, `0x8003`, and `0x192`
to daemon status `0x10d`; raw `0x101` (257) is returned unchanged. No current
host enum or string directly names 257. Behavioral evidence nevertheless
ties it strongly to unavailable accessory/device-group context: enrollment
group types 2 through 5 return 257 while built-in type 1 does not, and Linux's
load reaches 257 before macOS's sensor/accessory initialization has been
reproduced. This is an inference, not a recovered symbolic definition.

The next Linux step is to model this initialization state using only
evidence-backed, non-secret inputs. It should first implement and test the
read-only readiness, provisioning-state, and sensor-info shapes and the
explicit reset shape. It must not guess patch, MSRk, or calibration payloads
or repeat command `0x40` until their legitimate sources and the host-side
accessory-cache construction are understood. The new checksum-pinned verifier
and negative tests are
`tools/research/macos-catacomb-load-context-evidence.py` and
`tools/research/test_macos-catacomb-load-context-evidence.py`.

## Linux return result: pre-calibration reads match macOS

Linux implemented the exact readiness, provisioning-state, reset, and
sensor-info codecs with fail-closed shape validation. Reset remains
offline-only. A bounded live runner containing only the other three read
commands returned status zero, readiness 1, provisioning state 5, and an exact
12-byte sensor-info response. It did not print or retain the sensor-info bytes.
This matches the successful macOS state and proves that Linux reaches the
pre-calibration portion of current initialization. No catacomb, reset,
calibration, patch, or MSRk command was sent.

The next macOS pass is static/read-only. Recover from the checksum-pinned
installed binaries:

1. The exact request and reply ABI for Bridge methods 5
   (`calibrationDataFromEEPROM`) and 11 (`calibrationDataFromFDR`), including
   arguments, status handling, output type/size bounds, and which method the
   normal built-in sensor path selects.
2. The complete control flow from those legitimate Bridge-returned bytes into
   `setCalibrationData:source:` command `0x20`, including how source 0 is
   selected and whether any validation/transformation occurs.
3. The fields of the cached 12-byte sensor-info result used by
   `cacheAccessories`, and the exact host-side accessory/device-group object
   constructed before general catacomb load. Distinguish host-only bookkeeping
   from any additional Bridge call.

Do not print, copy, hash, decode, or commit machine calibration bytes or any
catacomb/biometric material. Do not enroll, remove, reset, load, or touch a
fingerprint. Add only checksum-pinned static evidence tooling, tests, and
sanitized conclusions; update this handoff and `docs/touch-id.md`, commit, and
push `main`.
