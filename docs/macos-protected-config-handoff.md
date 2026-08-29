# macOS handoff: biometric protected configuration

Pull latest `main` from `https://github.com/bentsignal/t2-omarchy.git` and read
the newest portion of `docs/touch-id.md`. Linux has now completed the exact
password-backed keybag creation, promotion to session selector `-501`, ACM
verification, enrollment credential handoff, and strict teardown. Promotion
changed the same current built-in enrollment request from synchronous status
`-3` to `261` (`0x105`), but no touch was requested and no identity was created.

The immediate job on macOS is read-only/static comparison of biometric
protected configuration:

1. Recover a safe way to issue or observe `GetSystemProtectedConfig`, biometric
   command `0x39`, against the already-running T2 BiometricKit service.
2. Record only its status, exact response length, and nine 32-bit configuration
   words. These are policy/timer fields, not fingerprint records or secrets.
   Do not print identity UUIDs, credential sets, passwords, templates, or raw
   biometric events.
3. Determine which macOS process/API owns `SetSystemProtectedConfig`, command
   `0x3a`, its exact input size/layout, when it is called during boot/login, and
   whether it is persistent. Prefer static analysis and existing unified logs.
4. Map the 36-byte fields using the matching KDK implementations of
   `AppleMesaSEPDriver::cacheSysProtectedConfigurationSpecific(bool)` and
   `IOBiometricService::cacheSysProtectedConfiguration(bool)`.
5. Do not send command `0x3a`, enroll/remove a finger, change Touch ID policy,
   or reboot as part of this handoff. Commit and push sanitized findings and a
   clear Linux return handoff.

Linux's read-only command-`0x39` result was status zero, output length 36, with
all nine words zero. The KDK-specific success path also expects exactly 36
bytes; one host-side failure path returns literal `0x105`, but that numerical
overlap alone does not prove the origin of the live enrollment status.

