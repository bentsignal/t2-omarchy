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
