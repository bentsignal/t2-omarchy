# macOS handoff: per-user biometric state

Linux has ruled out system protected configuration and BridgeXPC connection
initialization as causes of synchronous enrollment status `261` (`0x105`).
Read `docs/touch-id.md` and preserve all existing safety constraints.

On the installed macOS 26.6.2 system, perform read-only/static analysis to:

1. Recover the current biometric command numbers, command versions, input
   layouts, and exact output sizes for `GetProtectedConfig`, `GetCatacombState`,
   `GetCatacombId`, and `GetCatacombGroupState` as used by current
   `/usr/libexec/biometrickitd`.
2. Determine the exact normal initialization sequence for per-user UID 501
   before enrollment, including whether user protected config or catacomb load
   occurs only after first unlock/login.
3. Use Apple-signed read-only APIs or existing logs to record status and shape
   only. Do not print identity UUIDs, catacomb UUIDs/hashes/data, credentials,
   templates, passwords, or raw biometric events.
4. Statistically compare the exact command-3 enrollment payload constructed by
   current macOS for built-in Touch ID with Linux's layout: version 2, 68-byte
   input, words `(flags=0, uid=501, usingAuthToken=0,
   credentialLength=16)`, 16-byte ACM external form, 16 zero padding bytes,
   device-group type 1, and zero group UUID. Do not enroll/remove a finger.
5. Do not issue any setter, load/save/prepare/confirm catacomb command, change a
   policy, or reboot as part of analysis. Commit and push sanitized findings
   plus an explicit Linux return handoff.

The Linux live path is fully bounded and cleans up successfully. The remaining
question is which already-existing per-user/database state current macOS reads
before command 3, not whether system-wide policy is populated.
