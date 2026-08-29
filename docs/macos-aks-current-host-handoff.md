# macOS handoff: recover the installed AKS protected-header ABI

We are blocked on one sharply defined mismatch. Linux can initialize the T2,
register the AKS endpoint-7 OOL buffers, and exchange real ACM messages. Two
correctly correlated protected AKS requests, capabilities `0x4d` and normal
environment `0x2a`, reach the service but receive no mailbox reply. This points
to the common protected AKS header rather than either operation body.

## Objective

Recover the exact x86_64 AppleKeyStore implementation from the **installed
macOS 26.6.2 build 25G83**, not the existing macOS 14.5 KDK, and compare it to
the Linux codec. In particular establish:

1. the exact installed `_gen_ipc_header` field layout and sources;
2. the exact installed `_payload_hash` algorithm and protected byte ranges;
3. capabilities operation, request size/body, and fallback behavior;
4. the endpoint-7 mailbox envelope and first-call correlation behavior;
5. whether an IPC session ID, encryption setup, boot nonce, or other prerequisite
   is established before the first protected request.

## Constraints

- Read-only inspection only. Do not alter enrollment, Touch ID settings, SIP,
  Secure Boot, NVRAM, the keybag, or AppleKeyStore state.
- Do not capture or commit passwords, fingerprint material, ACM contexts,
  host identifiers, raw unified logs, or whole Apple binaries.
- Large Apple binaries stay local and untracked. Commit only sanitized hashes,
  offsets, instruction-derived layouts, scripts, and findings.
- Work in this repository and push all useful findings to `main`.

## Suggested path

Locate the installed Boot Kernel Collection (normally under
`/System/Library/KernelCollections/`) and identify its AppleKeyStore image,
UUID, version, and SHA-256. Extract or inspect the x86_64 AppleKeyStore image
with a suitable Mach-O/kernel-collection tool. Preserve the extracted binary
outside Git. Disassemble the symbols/functions listed above and record exact
evidence in `docs/touch-id.md` or a focused sanitized findings file.

The existing comparison anchors are:

- Sonoma 14.5 KDK AppleKeyStore at the locally retained research path;
- Catalina 10.15.7 AppleKeyStore recovered from installer build 19H15;
- Linux implementation in `prototypes/t2sep-probe/t2sep_probe.c` and
  `prototypes/t2sep-probe/aks-transport.py`;
- live evidence and chronology in `docs/touch-id.md`.

Do as much as possible autonomously. If current macOS prevents safe read-only
extraction, document the exact blocker and the least-invasive next option.

## Results from the installed 25G83 kernel collection

Read-only inspection completed on 2026-08-29. The installed boot kernel
collection was
`/System/Library/KernelCollections/BootKernelExtensions.kc`, SHA-256
`c80161fa3065883753fc285339281361a8469cbb6fb27653c88e2a22eb4807a4`.
The AppleKeyStore fileset has UUID
`12144241-3811-396D-8297-C5432D2FB286`, source version 55, VM base
`0xffffff8001a73000`, and fileset file offset `0x1973000`.

The important result is that the Linux protected-header codec is already the
installed ABI:

- `_gen_ipc_header` zeros an `0x50`-byte header, writes the version at `+0x10`,
  continuous microseconds at `+0x14`, the process unique ID at `+0x28`, the
  audit session ID at `+0x30`, and the 20-byte cdhash at `+0x34`. Version 2
  additionally writes calendar time at `+0x48`; version 1 does not.
- `_payload_hash` is unkeyed SHA-256. It hashes header ranges `+0x10/4`,
  `+0x14/8`, `+0x1c/4`, `+0x20/8`, then `+0x28/0x20` for v1 or
  `+0x28/0x28` for v2, followed by the operation payload. The first 16 digest
  bytes are copied to header `+0`. Equivalently this is the contiguous range
  `header[0x10:0x48] + payload` for v1 and
  `header[0x10:0x50] + payload` for v2.
- There is no keyed MAC, encryption, nonce, or hidden boot value in this
  header/hash path.

`AppleKeyStore::init_sep_endpoint()` constructs its transport callback and
immediately calls `_ipc_get_capabilities` with version 1. On success it selects
`min(remote_version, 2)`; on failure it explicitly selects version 1. It then
calls `AppleKeyStore::set_env(bool)`. No protected AKS prerequisite occurs
before capabilities: there is no IPC session establishment, nonce exchange,
encryption setup, keybag operation, or ACM operation in between endpoint
creation and the capabilities call.

The installed endpoint parser also confirms the mailbox envelope used by the
Linux probe. `AppleKeyStore::sep_action()` reads the operation from byte 1,
uses its high bit as the reply bit, reads the correlation tag from byte 2, and
copies the complete 64-bit reply word to the waiter. It dispatches operation
`7` to the AKS out-of-line delivery path. Thus the current Linux capability
request word `0x00014d07` and correlated reply word `0x0001cd07` have the
right endpoint, operation, reply bit, and tag placement. The tag is carried
through the word; there is no evidence of a special first-call tag.

The installed `_ipc_get_capabilities` uses operation selector `0x4d` and the
same common protected descriptor family already modeled by the Linux probe.
The endpoint initialization result is the negotiated header version, not an
additional session handle.

### Consequence for Linux

The stalled request is not explained by header layout, protected hash ranges,
operation `0x4d`, endpoint `7`, reply-bit placement, correlation tag placement,
or a missing pre-capabilities handshake. The strongest remaining hypothesis is
the continuous-time value. macOS signs `mach_continuous_time` converted to
microseconds, while Linux currently signs `ktime_get_boottime_ns()`. Those are
host boot clocks, but the Linux probe resets/boots the T2 during its own
startup, so the value accepted by the service may need to be related to the
T2 boot epoch or otherwise translated. The next bounded experiment should
sweep plausible continuous-usec values while holding the now-verified header,
hash, body, and mailbox word fixed, and should log only candidate classes and
reply/no-reply status.

Process identity remains a lower-priority check. AppleKeyStore runs in kernel
process context, for which process unique ID zero, default audit session zero,
and absent cdhash remain consistent with the installed call sites and macOS
audit definitions.
