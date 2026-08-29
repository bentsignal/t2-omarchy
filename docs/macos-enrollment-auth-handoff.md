# macOS handoff: T2 enrollment authorization

Pull the latest `main` branch of `https://github.com/bentsignal/t2-omarchy.git`
and read `docs/touch-id.md`, especially the live-match and live-enrollment
sections. Linux has now proven both successful and rejected T2 fingerprint
matching. Enrollment command 3 is reachable but returns synchronous status
`-3` before accepting a touch.

## Exact question

Recover the legitimate macOS 26.6.2 (`25G83`) path that produces the 40-byte
`authData` supplied to ordinary built-in Touch ID enrollment. Determine:

1. which process/framework creates it;
2. which authenticated API or T2/SEP service it calls;
3. whether the 32-byte token is one-shot, boot/session-bound, or reproducible
   after Linux verifies a password or an already-enrolled finger;
4. the exact non-secret request/response structure Linux must implement.

Do not seek a bypass. The intended Linux design must preserve the authorization
boundary and fail closed.

## Evidence already established

- Installed universal `usr/libexec/biometrickitd` SHA-256:
  `636dd137dace867359f389437c198d8c4cd9dc12896e9017d94cb6c567e84e4b`.
- Its x86_64 slice SHA-256:
  `248d4521007f95c916ae682c1a3d13d1c431626f4be4e84a0758d6dfbc94ce20`.
- `performEnrollCommand:` branches on communication protocol version. Above
  version 1 it sends command 3/version 2 with 68 input bytes.
- Resolved selectors prove those bytes are: four reserved/flags bytes,
  `userID`, 40-byte `authData`, then 20-byte `deviceGroup`.
- The `authData` type encoding is
  `{?="usingAuthToken"I"tokenLength"I"token"[32C]}`.
- Live bounded probes show built-in `deviceGroup` is type 1 plus a zero UUID.
  This still returns `-3`; group types 2..5 return 257.
- UID 501 and UID 1000 both return `-3`. Exact method 0, method 10 client
  version 2, and method 1 initialization does not change it.

## Work order

Prefer static analysis first:

1. Extract the current x86_64 `BiometricKit`, `BiometricSupport`,
   `LocalAuthentication`, and relevant System Settings biometric components
   from the live dyld shared cache/Cryptex.
2. Find xrefs to `BKOptionAuthWithAuthToken`, `authData`, enrollment option
   construction, and any ACM/LocalAuthentication credential export API.
3. Follow the token-producing call graph back to its authenticated service and
   record checksum-pinned instruction evidence, selectors, constants, sizes,
   and ordering.
4. Add/update offline evidence tools and tests in this repository, document the
   result in `docs/touch-id.md`, commit, and push `main`.

Only if static analysis cannot close the flow, perform one supervised dynamic
observation while the user starts adding a disposable new finger in System
Settings and authenticates normally. Capture only structure, call ordering,
status, and length. Never print, commit, paste into chat, or retain fingerprint
records, identity UUIDs, passwords, authorization-token bytes, or raw biometric
events. Cancel before the first finger touch unless observing later enrollment
state is strictly necessary and the user explicitly agrees.

Do not modify/delete the existing enrolled fingerprint, disable SIP, weaken
system security, or reboot without asking. Leave a concise Linux return handoff
in this file or a sibling document and push every durable finding.

## macOS 25G83 result (2026-08-28)

Static analysis closed the ordinary built-in enrollment request path without
capturing a password, authorization context, or biometric data:

1. `/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex` creates
   an ACM context, calls `_aks_verify_password` with the entered password and
   that context, then calls `ACMContextGetExternalForm`.
2. `ACMContextGetExternalForm` serializes exactly 16 bytes. The extension wraps
   them in `NSData` under `credset`, adds `userid`, and passes the dictionary to
   `BiometricKitUI`.
3. `BKUIFingerprintEnrollViewController` calls
   `-[BKEnrollOperation setCredentialSet:]`, `setUserID:`, and
   `startWithError:`.
4. Current `BiometricSupport` consumes the bytes under
   `BKOptionEnrollWithCredentialSet`. Its `parseAuthDict:toAuthData:` emits
   `usingAuthToken=0`, `tokenLength=16`, the 16-byte opaque external form, and
   16 zero padding bytes. `BKOptionEnrollWithAuthToken` is a distinct path and
   sets `usingAuthToken=1`; it is not the normal System Settings flow.

Linux should stop testing all-zero `authData`. The next bounded task is to
recover and implement the AppleCredentialManager/AppleKeyStore request used by
`_aks_verify_password` on T2, including context-create and external-form
semantics. Treat the 16-byte external form as an opaque, probably
boot/session-bound capability—not a password hash or replayable token. Do not
log it, persist it, copy it between OS boots, or accept it after transport reset
without evidence that the issuing state remains valid.

Useful pins: settings extension universal SHA-256
`14cc6fe7cccce11aad741af346df0e1275d98c16853574b0d7c634ef2e4798b3`;
x86_64 slice SHA-256
`e86ab74e0246bbd7b88cec36fd901106a49bab8e95edfc687e77d06083c359f1`.
Relevant x86_64 settings IMPs are `+[PSBiometricIdentity
getCredentialsData:ctp:]` at `0x100007a20` and
`-[SecurityShared(TouchIDEnrollment)
presentEnrollmentSheetInWindow:withData:completionHandler:]` at
`0x10000a3e8`. In the live dyld cache, `BiometricSupport` method offsets from
its image base are `0x19dc6` for `parseAuthDict:toAuthData:` and
`BiometricKit` uses `0x25f71` for
`-[BKEnrollOperation optionsDictionaryWithError:]`.

## Follow-up required after Linux status 261 (2026-08-29)

Linux now reproduces ACM context creation, type-0 AKS keybag creation,
promotion to selector `-501`, password verification, current global and UID
501 `NoCatacomb`, authenticated `(1,1,1,0)` protected-policy creation and exact
readback, and the current command-3 serializer. The service still returns
status `261` synchronously before a touch. Initializing the global component
did not change it, and `PrepareSaveCatacomb` rejects the pristine zero-identity
component with status 22.

On macOS, inspect the already pinned Settings extension call to
`_aks_verify_password` and record the exact non-secret value of its final
boolean/device-state argument. In the KDK implementation that boolean becomes
input device-state bit `0x80`; Linux currently sends zero. Also trace whether
the normal enrollment path performs any AKS/keybag/session call after password
verification and before `ACMContextGetExternalForm` or BiometricKit command 3.
Distinguish an established login keybag from the newly created/promoted bag
Linux uses. Do not capture or print the password, ACM external form, keybag
blob, biometric identity/template, or raw sensor events. Add checksum-pinned
instruction evidence, update this handoff and `docs/touch-id.md`, run tests,
commit, and push `main`.
