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
5. `resetSensor`: command `0x02`, compatibility-wrapper version 1,
   `inValue=2`, no input or output, with at most three host retries. The
   earlier version-2/value-0 interpretation was corrected after Catalina's
   symbolized call fixed the current instruction sequence's argument mapping.
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

## macOS return result: calibration ABI and accessory command recovered

The installed Bridge transport implements `calibrationDataFromEEPROM` and
`calibrationDataFromFDR` as no-argument methods 5 and 11. Each sends a
one-element request array containing its method number. Transport failure or
a reply other than exactly one object returns nil; the sole reply object must
be `NSData`. Neither wrapper imposes a byte-length bound, so Linux must apply
its own conservative bound before retaining or forwarding a response.

Current `loadCalibrationData` first reads `performGetBiometrickitdInfoCommand:`.
On this normal boot its already-calibrated flag was set, so the daemon selected
source 0 and sent neither calibration retrieval method nor command `0x20`.
This corrects the earlier interpretation that source 0 was supplied to a
successful `0x20`: source 0 in the boot log means no calibration upload was
needed. When loading is required, the current non-internal paths are:

- non-Gibraltar: method 5 (`calibrationDataFromEEPROM`), then command `0x20`
  version 1 with source 2;
- Gibraltar: method 11 (`calibrationDataFromFDR`), then command `0x20` version
  1 with source 3.

An AppleInternal-only custom-file path uses source 5. The selected `NSData` is
not transformed or structurally validated by the daemon: its bytes and exact
length are passed directly to `setCalibrationData:source:`. Linux must not
invoke either setter path merely to reproduce a boot that already reports the
calibration-present flag.

The accessory trace also corrects the earlier host-only conclusion.
`cacheAccessories` calls `performGetBioDeviceListCommand:`. For communication
protocol versions above 1, that method sends read-only command `0x52` through
the version-1 compatibility wrapper, with `inValue=0`, no input, and a
264-byte output capacity. The reply length must be bounded and divisible by
the exact 44-byte device-record size. Protocol version 1 instead synthesizes
one local 44-byte built-in record: accessory type 1 plus zero UUID, device
group type 1 plus zero UUID, and flags 6. The common parser constructs the
host `BiometricKitAccessory` and `BiometricKitAccessoryGroup` objects from
those record fields. Thus current Linux is missing a separate `0x52` read,
not a hidden argument to command `0x40`.

The cached 12-byte command-`0x35` result is exactly three uint32 fields named
`version`, `structSize`, and `sensorType`. The daemon stores all 12 bytes;
`getSensorType` requires `structSize == 12` and returns the final word.
`cacheAccessories` does not derive its device group from those raw 12 bytes;
it obtains the independent bio-device list described above.

The next Linux step is a bounded read-only `0x52` probe after the already
successful readiness/provisioning/sensor-info sequence. Validate only status,
length, 44-byte divisibility, record count, and whether exactly one record has
built-in accessory/group types. Do not print UUIDs or other record bytes and
do not send calibration or catacomb commands yet. Evidence is pinned to
daemon SHA-256 `248d4521007f95c916ae682c1a3d13d1c431626f4be4e84a0758d6dfbc94ce20`,
BiometricSupport UUID `93788D32-9E1E-37CE-8E4A-EBE8ECBD6735`, and its
`__TEXT,__text` SHA-256
`f356bdc6419cb93dc3f0f8c40ffca8bc5bb7894b407264f9eeac06ddb2b103bc`.
The verifier and negative tests are
`tools/research/macos-calibration-accessory-evidence.py` and
`tools/research/test_macos_calibration_accessory_evidence.py`.

## Linux return result: built-in accessory context confirmed

The bounded Linux `0x52` probe returned status zero, one 44-byte record, and
exactly one built-in accessory/group classification. No record bytes or UUIDs
were printed or retained. Linux now validates readiness 1, provisioning and
sensor-info reply shapes, and exactly this built-in device list on the same
Bridge session before its gated general-then-user loader. All non-secret reads
match current macOS, so one further encrypted load comparison is justified.

For the next macOS pass, repeat only the already established two-component CMS
transfer using the fresh public certificate on the EFI partition:

1. Revalidate the active general component (decoded UID -1, 148-byte secure
   data) and UID-501 component (104-byte secure data) through Foundation keyed
   archive decoding. Fail closed if those identities or lengths changed.
2. Stream each decoded `CatacombSecureData` object directly into AES-256 CMS
   DER encryption using `/Volumes/EFI/t2-touchid-transfer-cert.pem`. Write
   `/Volumes/EFI/t2-touchid-transfer-global.cms` and
   `/Volumes/EFI/t2-touchid-transfer-user.cms` atomically. Never create a
   plaintext temporary file.
3. Validate only CMS structure and ciphertext lengths. Do not print, inspect,
   hash, decode, or commit source data, ciphertext, filenames, UUIDs, or other
   biometric material. Leave the archives and enrolled fingerprint untouched.
4. Commit and push only a sanitized success/failure report with the two decoded
   lengths and ciphertext lengths.

Linux will decrypt both into private temporary inputs, perform the now-complete
same-session read sequence, load general then UID 501 exactly once, report
only statuses/policy length/identity count, and immediately remove every
transfer artifact and throwaway key.

## macOS return result: post-accessory-context transfer complete

The authorized two-component transfer completed. A root-privileged,
Terminal-context helper found 40 files at either expected archive size; only
two were valid keyed archives, and each contained exactly one unique data
object of its previously established secure-data length. The 599-byte archive
yielded 148 bytes and the 708-byte archive yielded 104 bytes. No archive path,
UUID, data value, or hash was printed or retained.

The current private archive class would not instantiate in the standalone
helper, so this pass could not independently decode `CatacombUserID`. Selection
therefore used the exact root-owned archive sizes, keyed-archive structure,
unique expected-length data objects, and the size-to-UID mapping established
by the prior successful Foundation decode (599 -> general UID -1; 708 -> UID
501). This limitation is explicit rather than silently claiming a fresh UID
decode.

Each selected data object was streamed directly to OpenSSL CMS encryption;
no plaintext temporary file was created. The final EFI artifacts are:

- `t2-touchid-transfer-global.cms`: 711 bytes, wrapping 148 bytes;
- `t2-touchid-transfer-user.cms`: 662 bytes, wrapping 104 bytes.

Both final DER envelopes passed independent `openssl cms -cmsout -noout`
parsing. The source archives and enrolled fingerprint were untouched. Linux
may now perform the bounded same-session readiness/provisioning/sensor-info/
bio-device-list sequence, load general then UID 501 once, report only the
authorized status/length/count fields, and remove all transfer and key
artifacts immediately afterward.

## Linux return result: context reads succeed; reset prerequisite missing

Linux decrypted and length-validated the 148-byte general and 104-byte user
payloads, then ran readiness, provisioning state, sensor info, and `0x52` on
one Bridge session. Every read succeeded and the device list was exactly one
built-in record. The immediately following general command `0x40` still
returned status 257, so the user component was not sent. Linux then removed
both plaintexts, CMS files, the EFI certificate, and the throwaway key.

The remaining known startup difference was the then-misdecoded reset `0x02`
version 2/value 0 between
provisioning and sensor info. A separate bounded Linux run attempted that exact
no-input/no-output shape at most three times. All three attempts returned
signed status -536870206 (`0xe00002c2`, `kIOReturnBadArgument`); no subsequent
write or load was issued. This strongly indicates that a prerequisite before
reset is still missing rather than that accessory caching alone explains 257.

The next macOS pass is static/read-only only. Recover from the pinned current
daemon and support framework:

1. The exact predicate following provisioning state 5: whether `setMSRkData:`
   is invoked on this normal built-in-sensor boot, and every status/value test
   controlling that branch.
2. If MSRk is required, its legitimate source API and complete request/reply
   ABI, size bounds, validation/transformation, and command-`0x5c` call shape.
   Do not retrieve or expose machine MSRk bytes.
3. The complete caller and retry control flow for reset `0x02`, including any
   preceding command or host-side state not yet modeled and the interpretation
   of `0xe00002c2` at that point.
4. Any `performGetBiometrickitdInfoCommand:` fields or other initialization
   flags consulted between provisioning and reset. Record only field offsets,
   meanings, predicates, and non-secret shapes.

Do not create another catacomb transfer, reset the sensor, retrieve MSRk or
calibration data, or touch/enroll/remove a fingerprint. Add checksum-pinned
static evidence tooling and negative tests, update this handoff and
`docs/touch-id.md`, commit, and push `main`. This requested macOS pass was
superseded before reboot by the local Catalina cross-check described below.

## Linux correction: reset argument mapping

The retained checksum-known Catalina daemon has symbolized Objective-C
metadata for `resetSensor`. Its disassembly calls the compatibility
`performCommand:inValue:inData:inSize:outData:outSize:` selector with command
2 in `edx` and `inValue=2` in `ecx`; the wrapper supplies version 1. The current
25G83 byte sequence has the same command/value register setup. The earlier
analysis had mistaken `ecx=2` for an explicit version argument despite not
pinning the called selector. Linux's version-2/value-0 experiment therefore
tested the wrong envelope and its `kIOReturnBadArgument` is fully explained.

The corrected Linux reset (command `0x02`, version 1, `inValue=2`) succeeded on
its first live attempt. The same session then returned valid 12-byte sensor
info and exactly one built-in bio-device record. No MSRk, calibration,
catacomb, enrollment, or match operation was issued. Linux now reproduces the
complete normal no-calibration initialization sequence through accessory
caching.

The next macOS pass is authorized to repeat the established two-component CMS
transfer using the new EFI public certificate. Revalidate the active general
and UID-501 archives by the same fail-closed structure and established
599/708-byte archive to 148/104-byte secure-data mapping. Stream only those
two decoded data objects directly into atomic AES-256 CMS DER files named
`t2-touchid-transfer-global.cms` and `t2-touchid-transfer-user.cms` on EFI.
Never create plaintext temporary files, expose values/UUIDs/paths/hashes, or
change the archives or enrolled fingerprint. Validate only CMS structure and
lengths, then commit and push a sanitized report. Linux will perform exactly
one corrected-reset same-session ordered-load comparison and remove all
transfer material immediately.

## macOS return result: corrected-reset comparison transfer complete

The authorized repeat transfer completed using the new EFI public
certificate. The fail-closed extractor again required exact root ownership,
599/708-byte archive sizes, keyed-archive structure, and one unique secure-data
object of the established length in each archive. It selected 148 bytes from
the 599-byte general archive and 104 bytes from the 708-byte user archive.
Because the standalone helper still cannot instantiate the private archive
class, the UID classification relies explicitly on the previously established
599 -> general UID -1 and 708 -> UID 501 mapping rather than claiming a fresh
UID decode.

Both objects were streamed directly into atomic AES-256 CMS DER outputs; no
plaintext temporary file was created. The resulting EFI files are 721 bytes
for `t2-touchid-transfer-global.cms` and 672 bytes for
`t2-touchid-transfer-user.cms`. Each final envelope passed an independent
`openssl cms -cmsout -noout` parse. No archive path, UUID, plaintext, hash, or
secret value was printed or retained, and neither source archive nor the
enrolled fingerprint was changed.

Linux may now perform exactly one corrected-reset same-session ordered-load
comparison, general followed by UID 501, and must remove all CMS, certificate,
private-key, and decrypted transfer material immediately afterward.

## Linux return result: corrected reset still needs daemon-info read

The corrected reset succeeded in the ordered-load session, followed by valid
sensor info and one built-in device record. The general load nevertheless
returned 257; the user component was not sent, and every transfer artifact was
removed.

Local checksum-known Catalina disassembly then recovered the one remaining
normal initialization read. `performGetBiometrickitdInfoCommand:` sends
command `0x28` through the compatibility wrapper (version 1), with
`inValue=0`, no input, and an exact packed 23-byte `IIIQCCC` output. The final
byte at offset 22 is the calibration-present boolean checked by
`loadCalibrationData`. A bounded current-T2 run succeeded with an exact
23-byte reply and `calibration_present=True`; therefore macOS skips methods
5/11 and command `0x20` on this machine. The same session then returned one
built-in device record. Linux now implements that exact ordering between
sensor info and `0x52`, and fails closed if calibration is absent.

The next macOS pass may repeat the established general/UID-501 CMS transfer
using the fresh EFI certificate. Apply the same exact ownership, archive-size,
keyed-archive, unique-data-object, and 148/104-byte validation. Stream directly
to atomic AES-256 CMS DER outputs; create no plaintext file and expose no
paths, UUIDs, values, or hashes. This time Linux will move the two ciphertexts,
certificate, and private key into a mode-0700 directory on its LUKS-encrypted
home, with each file mode 0600, solely for repeated bounded local development
probes. It will never commit, upload, print, or persist decrypted bytes; every
plaintext will be unlinked immediately after its probe. This retained
encrypted copy avoids another macOS reboot for each non-secret sequence
correction. Commit and push only the sanitized transfer report.

## macOS return result: retained-development transfer complete

The authorized repeat transfer completed using the fresh EFI public
certificate. The fail-closed extractor required root ownership, exact 599/708
archive sizes, keyed-archive structure, and exactly one unique secure-data
object of the established length in each archive. It selected 148 bytes from
the 599-byte general archive and 104 bytes from the 708-byte user archive. The
standalone helper still cannot instantiate the private archive class, so UID
classification relies explicitly on the previously established 599 -> general
UID -1 and 708 -> UID 501 mapping rather than a fresh UID decode.

Each object was streamed directly into an atomic AES-256 CMS DER output with
no plaintext temporary file. `t2-touchid-transfer-global.cms` is 727 bytes and
`t2-touchid-transfer-user.cms` is 678 bytes. Both final envelopes passed
independent `openssl cms -cmsout -noout` parsing. No source path, UUID,
plaintext, hash, or secret value was printed or retained, and neither source
archive nor the enrolled fingerprint was changed.

Linux may now move the two ciphertexts, certificate, and private key into the
handoff's mode-0700 LUKS-home directory with individual mode 0600, use them
only for the authorized bounded local sequence probes, unlink plaintext after
every probe, and never commit, upload, or print any transfer material.
