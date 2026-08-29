# macOS return handoff: per-user biometric state

Read-only/static analysis was completed against the installed macOS 26.6.2
`/usr/libexec/biometrickitd`. No enrollment, policy setter, catacomb mutation,
or raw biometric operation was issued. No identity or catacomb identifier,
hash, credential, template, or raw event is recorded here.

## Current wire commands

The x86_64 slice of the installed daemon gives these current command shapes:

| operation | command | version | input | output |
| --- | ---: | ---: | --- | --- |
| `GetProtectedConfig` | `0x2e` | 0 | one 32-bit UID | exactly 32 bytes: four 32-bit set-policy words followed by four 32-bit effective-policy words |
| `GetCatacombState` | `0x3c` | 0 | none | caller-sized buffer; returned length must be a multiple of 8 bytes |
| `GetCatacombId` (`performGetCatacombUUIDCommand`) | `0x38` | 0 | one 32-bit UID | exactly 16 bytes |
| `GetCatacombGroupState` | `0x50` | 0 | none | caller-sized buffer; returned length must be a multiple of 56 bytes; current daemon uses this command only with bridge protocol generation 2 or newer |

For the two state queries, the daemon passes a mutable data object's byte
pointer as the output buffer and its existing length as the capacity. The
bridge overwrites the length through the output-length pointer; the daemon
validates record alignment before accepting it. Thus these are variable arrays
of 8-byte and 56-byte records, respectively, rather than fixed scalar replies.
The older-protocol group-state path does not issue command `0x50`.

`GetCatacombId` above is the current method named
`performGetCatacombUUIDCommand:outUUID:`. Its result was characterized only by
size; its value was neither queried nor retained. The nearby catacomb-hash
getter is deliberately excluded because Linux does not need the value and the
handoff forbids exposing it.

## Normal UID 501 startup ordering

Sanitized unified-log evidence from the current boot records this order:

1. `biometrickitd` starts and initializes its Mesa implementation.
2. The Bridge reports interface generation 3.
3. Sensor-readiness and sensor initialization succeed.
4. Accessory state is cached.
5. The daemon enters its general `loadCatacomb` phase.
6. It loads the non-user component successfully.
7. It calls `loadCatacombForUser: 501` and loads that component successfully.
8. While loading UID 501 it reports that the user's protected configuration is
   present (the private value was not inspected).
9. The overall catacomb load completes successfully.
10. Only afterward does the daemon publish its XPC listener and service the
    initial UID 501 biometric-lockout-state reads.

This boot therefore shows that the existing UID 501 catacomb and user
protected configuration are loaded as part of daemon startup, before clients
can request enrollment. It does **not** support a separate lazy load performed
by command 3. Because this evidence came from an already provisioned user after
login, it cannot distinguish first-unlock key availability from login-session
availability on a pristine installation. It does establish the ordering that
Linux currently lacks: load existing per-user state before exposing enrollment.

The Apple-signed read-only `bioutil --read` path also successfully returned a
set and effective UID 501 protected configuration in the earlier macOS pass.
No private client or setter is necessary to establish that the state exists.

## Command-3 comparison

The installed daemon's current `performEnrollCommand:` has two protocol paths.
For bridge protocol generation 2 or newer it issues:

- command `3`;
- command version `2`;
- exactly `0x44` (68) input bytes;
- no output buffer.

The constructed v2 buffer is laid out as:

```text
+0x00  uint32 flags
+0x04  uint32 uid
+0x08  40-byte authorization/credential structure
+0x30  20-byte device-group structure
```

That is byte-for-byte the field partition implemented on Linux: flags 0 and
UID 501; then `usingAuthToken`, `credentialLength`, and a 32-byte credential
slot; then a 32-bit device-group type and 16-byte group UUID. With Linux's
non-secret parameters (`usingAuthToken=0`, credential length 16, 16-byte ACM
external form, 16-byte zero remainder, group type 1, zero group UUID), its
payload shape exactly matches the current macOS v2 serializer. The older bridge
path uses version 1 with a 48-byte input and is irrelevant to the current
interface-generation-3 machine.

## Linux next step

Do not keep changing command 3's size or version: those now match macOS. The
remaining high-value comparison is the state established before enrollment.
Linux should query the read-only user-state commands above and record only
status and returned length/record count. In particular, compare whether UID
501 has a protected-config reply and whether the catacomb state/group-state
arrays describe a loaded user component before enrollment. Do not print or
persist the 16-byte catacomb ID or any hash/data, and do not attempt a load,
save, prepare, confirm, setter, enrollment, or removal merely to populate it.

If Linux has no already-existing per-user catacomb to load, treat that as the
leading explanation for synchronous status `0x105`; do not infer that an
ephemeral ACM context alone creates the missing biometric database state.
