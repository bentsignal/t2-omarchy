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
