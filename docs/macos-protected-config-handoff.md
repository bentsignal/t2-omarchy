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

## Installed macOS 26.6.2 findings (2026-08-29)

The installed user-space path changes the immediate Linux conclusion. The
current x86_64 `/usr/libexec/biometrickitd` does **not** use the Sonoma KDK's
legacy command `0x39`/`0x3a` pair. Its
`performGetSystemProtectedConfigCommand:` sends command **`0x43`**. Its
`performSetSystemProtectedConfigCommand:authData:` sends command **`0x44`**.
Therefore the successful all-zero Linux `0x39` response is not a capture of
this macOS installation's current protected policy; it is a compatible legacy
command response.

The safe, Apple-signed observation path is:

```sh
/usr/bin/bioutil --read --system
```

`bioutil` carries `com.apple.private.biometrickit.allow-config`; an unsigned
client is rejected by `biometrickitd` for lacking a
`com.apple.private.biometrickit.*` entitlement. The read-only command completed
with status zero and reported:

```text
Biometrics functionality: 1
Biometrics for unlock: 1
Biometric timeout (seconds): 172800
Match timeout (seconds): 14400
Passcode input timeout (seconds): 561600
```

No identity, credential, template, or raw event was requested or printed.

For protocol generation 3 and later, current command `0x43` requests exactly
36 output bytes. The daemon maps the nine little-endian words as follows:

| Word | `SystemProtectedConfig` property | Observed value |
|---:|---|---:|
| 0 | `unlockTokenMaxLifetime` (the deprecated biometric timeout) | 172800 |
| 1 | reserved/legacy | not exposed by `bioutil` |
| 2 | reserved/legacy | not exposed by `bioutil` |
| 3 | `biometryEnabled` | 1 |
| 4 | `unlockEnabled` | 1 |
| 5 | `identificationEnabled` | not exposed by `bioutil` |
| 6 | `loginEnabled` | not exposed by `bioutil` |
| 7 | `bioMatchLifespan` | 14400 |
| 8 | `passcodeInputLifespan` | 561600 |

The exact values of words 1, 2, 5, and 6 should be obtained by issuing the
read-only current command `0x43` from Linux. Do not fill them by inference.
The installed daemon's decoder provides an exact check: status zero and output
length 36. On older protocol generations it requests 28 bytes instead and does
not decode words 7 and 8.

The current setter is owned by `biometrickitd`, exposed to entitled clients as
`-[BiometricKit setSystemProtectedConfiguration:withOptions:]` and its XPC
variants. `/usr/bin/bioutil --write --system` is one entitled administrative
client, but it was not invoked. For protocol generation 3+, command `0x44`
serializes the nine configuration words followed by a 40-byte authorization
structure (`{ uint32_t, uint32_t, uint8_t[32] }`), for an exact 76-byte input.
The legacy path serializes seven words plus the same authorization structure,
68 bytes total. Static inspection found no separate host-side persistence
write in these methods: the getter queries the biometric service each time and
the setter sends the configuration to it. No `SetSystemProtectedConfig` event
was present in the available current-boot unified log, so boot/login timing and
cross-reboot persistence were not asserted.

### Linux return handoff

Add a default-safe read-only probe for biometric command `0x43`, requiring
status zero and exactly 36 bytes, and compare its nine words with the mapping
above. Keep `0x39` only as explicitly labeled legacy evidence. Do not send
`0x44`. If `0x43` returns the nonzero macOS policy, rerun the existing
enrollment attempt without changing it first; this distinguishes a getter/
command-version mismatch from an actual need to initialize protected policy.
