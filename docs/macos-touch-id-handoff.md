# macOS Codex handoff: T2 bridgeOS service activation

> **Current handoff (2026-08-28):** Linux now also mirrors every portable part
> of MultiverseSupport's socket setup (`AF_INET6`, TCP, nonblocking connect,
> exact address/scope, and interface binding). The T2 still sends HELO but does
> not answer the byte-exact method-zero request. XNU source proves Darwin's
> `SO_INTCOPROC_ALLOW` is a local interface access-control bit rather than a
> peer-visible wire signal; Linux already passes its effective gate.
> The exact current `23P6068` BridgeXPC 39 has now been recovered from Apple's
> iBridge2,14 restore IPSW. It confirms that peer HELO is only decoded/logged,
> never gates state, and kind-2 messages dispatch immediately. The next task is
> a narrow comparison with the already successful
> macOS boot connection; do not repeat enrollment or broad biometric captures.

Give the macOS Codex session this exact instruction:

> Continue from `1ede359` or later. Read this file, `docs/touch-id.md`, and
> `docs/macos-touch-id-findings.md`. First locate the private packet capture and
> logs from the already successful boot-time BiometricKit connection; do not
> put raw pcaps, serials, UUIDs, or fingerprint data in git. Isolate the TCP flow
> to the directory-advertised BiometricKit port (49165 in that recorded boot)
> and report a sanitized comparison: both complete endpoint tuples, TCP option
> state if recoverable, exact frame sizes/hashes/order/timing for client HELO,
> server HELO, method 0, and its reply, plus decoded non-private method status
> and bridge version. Use `macos-bridge-wire-compare.py` for the client frames.
> Determine whether the successful connection has any bytes, socket metadata,
> or TCP transition between HELO and method 0 that Linux lacks. Focus on
> RSD service handoff context and the daemon message/reply path; do not spend time on
> `SO_INTCOPROC_ALLOW` or HELO JSON-field negotiation, because recovered source
> shows neither can provide a peer-visible gate. If the old private capture is
> insufficient, make one narrow boot capture that stops immediately after the
> automatic bridge-version reply; do not enroll, match, touch the sensor,
> disable SIP, or capture later biometric traffic. Add only sanitized evidence,
> reproducible analysis tooling/tests, and conclusions to the repo, then commit
> and push a Linux handback. Explicitly state the next bounded Linux experiment
> authorized by the evidence.

The older activation instruction below is retained as history and is already
complete.

## 2026-08-28 Foundation wire reconstruction

Using the current macOS Foundation implementation, the first method-zero array
serializes to a 46-byte binary plist. With the installed BridgeXPC 39 header,
the complete request is exactly 62 bytes, byte-identical to
`bridge-query.py`, and SHA-256
`a60083fc2ec4be95418906235ac3024e9d01eb8661d82a34c2dea0bf3d0f4b1d`.

The HELO's four fields and types are also correct, but native Foundation does
not preserve the source dictionary's key order. Twenty-four fresh serializer
runs produced 15 distinct compact-JSON orderings, all with a 103-byte body and
119-byte frame. All 24 permutations are valid native encodings. The comparator
now distinguishes field equality, exact bytes, and native-order membership.

This rules out method-zero binary-plist serialization and any requirement for
one canonical HELO key order. A later live macOS trace may record the current
process's particular HELO ordering, but Linux should first investigate the
connection state between receipt of the server-first HELO and release of the
queued method request. It may test only semantically valid HELO encodings and
the already exact method-zero frame; it still must not send method 3 or any
biometric command.

> Continue the T2 Touch ID Linux investigation from the current `main` branch.
> Read `docs/touch-id.md`, `docs/macos-touch-id-findings.md`, and
> `docs/macos-touch-id-handoff.md` completely before acting.
>
> Linux now has healthy CDC-NCM connectivity to the T2, but bridgeOS's
> RSD/mDNS responder and dynamic BiometricKit listener remain dormant. Direct
> and multicast RSD queries time out, while ports 58783 and 52032 actively
> refuse connections. Catalina's Linux-native enrollment, identity-management,
> match commands, and terminal service-event semantics are already recovered;
> do not redo that work.
>
> Investigate what macOS does below `remoted` that activates bridgeOS Remote
> Service Discovery. Focus on early-boot IORegistry state, AppleUSBiBridge/T2
> USB power and configuration properties, the component represented by the
> observed `localbridge` attachment, relevant kernel/driver state, and any
> host-to-T2 state transition preceding the directory connection. Compare
> those facts with the documented Linux state. The current AppleUSBiBridge
> static analysis already shows one selected USB configuration and remote-wake
> calls confined to sleep/wake callbacks, so seek stronger evidence rather
> than merely repeating configuration or NCM queries.
>
> Perform as much read-only inspection and static analysis as possible. A new
> bounded boot or sleep/wake capture is allowed only when it targets a concrete
> unresolved transition. Do not modify fingerprint enrollment, reset or pair
> the Touch ID sensor, disable platform security, or publish raw/private
> biometric evidence. Record sanitized findings, reproducible tooling, and
> tests in the repository; push a clean checkpoint before handing back to
> Linux. State exactly which Linux experiment the new evidence authorizes.

## 2026-08-28 Multiverse resolution

The installed x86_64 `remoted` slice (SHA-256 `88e78e65...4056`) contains
`RSDRemoteMultiverseHostDevice::needsConnect`. Its unique verified instruction
sequence loads `0xe8d2` (59602) as the port argument to
`multiverse_device_connect`. That exactly matches the boot-observed T2
directory endpoint.

At boot, Multiverse identifies an already link-active `internal device`, marks
it usable, and `remoted` names it `localbridge`. Its first connection attempt
fails only because the IPv6 route is not ready; `pollConnect` then succeeds.
No separate IORegistry `localbridge` node or intervening host wake request was
found. The active USB topology is `Apple T2 Controller` (`05ac:8233`,
configuration 1, full device power) below `AppleUSBVHCIBCE`.

This authorizes one Linux experiment: with the proven interface ancestry and
host/T2 link-local addresses, connect only to T2 TCP port 59602 and perform the
bounded directory handshake already implemented by `rsd-query.py`. Stop after
passively obtaining `com.apple.eos.BiometricKit` and preserve the capped server
transcript. Do not request the advertised service or send BridgeXPC/biometric
traffic. Pin live enablement to this exact binary evidence and retain all
existing timeout, frame-count, byte-count, peer-address, and source kill
switches. DNS-SD is not a prerequisite for this internal-device route.

> Capture completed on macOS 26.6.2. See
> [`macos-touch-id-findings.md`](macos-touch-id-findings.md) for the sanitized
> handback and Linux continuation. Raw evidence remains local only.

This is the continuation point for the Linux Touch ID research on Shawn's
2019 `MacBookPro16,1`. It is intended to be read by a fresh Codex session
running on this machine's macOS installation.

## Start here

Clone the public repository and verify the handoff commit:

```bash
cd "$HOME"
git clone https://github.com/bentsignal/t2-omarchy.git
cd t2-omarchy
git log -1 --oneline
git status --short
```

The history must contain commit `77f7593` or a later descendant. The shorter
historical instruction used for the first capture was:

> Read `docs/macos-touch-id-handoff.md` completely, inspect the current git
> state, and continue the T2 Touch ID investigation from its macOS capture
> stage. Preserve the safety and evidence rules in that document. Work as far
> as possible autonomously, but ask before installing a LaunchDaemon,
> restarting Apple daemons, changing enrollment, or rebooting. Never commit
> raw captures or private unified logs to the public repository.

## Pre-capture evidence (superseded where noted)

The capture is complete. [`macos-touch-id-findings.md`](macos-touch-id-findings.md)
is authoritative when it conflicts with the pre-capture assumptions below.

Do not redo these Linux experiments unless later evidence contradicts them:

- The T2 CDC-NCM device transmits from Ethernet MAC
  `ac:de:48:33:44:55` and IPv6 link-local address
  `fe80::aede:48ff:fe33:4455`.
- The earlier address-helper inference predicted host address `...:44aa`.
  macOS directly disproved this: its host address is `...:1122`.
- After a narrow CDC-NCM USB rebind, Linux neighbor discovery and ICMPv6 echo
  to the T2 succeeded from that host peer address. The transport is real.
- TCP ports `58783` (current `remoted` device-role listener candidate) and
  `52032` (legacy BiometricKit listener) both actively refused connections
  during Linux boot. No `_remoted._tcp` mDNS answer appeared.
- The capture resolved the activation sequence. Later static verification
  proved directory port 59602 is fixed in this Intel Multiverse path, while
  the returned BiometricKit service port remains boot-dynamic.
- The current x86_64 `remoted` slice previously inspected has SHA-256
  `88e78e65b77e3c2338ca95c9ab201bfa0be90ce81e58ece1c4d1ad11273f4056`.
  Reconfirm this against the live installation rather than assuming it.
- Protocol codecs and runners are fail-closed. Live RSD and BridgeXPC paths
  retain source kill switches; do not enable them merely because a port or
  address is plausible.

The detailed research record is in `docs/touch-id.md`. Relevant implementation
and tests are under `prototypes/t2sep-probe/` and `tools/research/`.

## Collect live macOS evidence

First capture the exact installed binaries and launch metadata. This is
read-only and should not request authorization:

```bash
cd "$HOME/t2-omarchy"
./tools/research/capture-macos-bridge.sh \
  "$HOME/Desktop/t2-static-capture"
```

Then run the bounded runtime collector:

```bash
./tools/research/capture-live-macos-t2.sh \
  "$HOME/Desktop/t2-runtime-capture"
```

The runtime collector:

- requests `sudo` only for `tcpdump` and process-attributed `lsof` snapshots;
- captures for 60 seconds only on interfaces with an `ac:de:48` T2-range MAC;
- records `remoted`/`biometrickitd` logs and TCP listener snapshots;
- changes neither fingerprints nor Apple daemon state;
- exits nonzero rather than silently succeeding if no T2 interface exists or
  packet capture fails to start.
- refuses a nonempty output directory so stale and current evidence cannot be
  mixed. Choose a new directory name if either example path already exists.

During its 60-second window:

1. Lock the Mac with Control-Command-Q.
2. Unlock it once using the enrolled finger.
3. If convenient, approve one ordinary macOS action with Touch ID.
4. Avoid web browsing or unrelated network activity until capture completes.

If the collector reports that no `ac:de:48` interface exists, do not broaden
capture to Wi-Fi or all interfaces. Preserve `ifconfig-before.txt`, inspect it,
and adapt interface selection only from concrete macOS evidence.

## Analyze without mutating the system

Run the strict offline summary:

```bash
./tools/research/analyze-macos-t2-capture.py \
  "$HOME/Desktop/t2-runtime-capture" \
  >"$HOME/Desktop/t2-runtime-summary.json"
```

Then verify and inspect:

1. Confirm hashes in both capture directories before interpreting files.
2. Compare the live `remoted` SHA and architecture with the recorded binary.
3. Identify the actual macOS T2 interface, both IPv6 endpoints, active
   listeners, owning processes, and whether ports `58783` or `52032` appear.
4. Establish packet chronology around unlock: neighbor discovery, mDNS, TCP
   SYN/SYN-ACK, RSD/HTTP2, BridgeXPC, and teardown.
5. Correlate packets with `remoted` and `biometrickitd` log timestamps.
6. Distinguish boot-time activation from per-authentication traffic. A
   60-second post-login trace may prove the latter but miss the former.

If the trace has no activation sequence because the service was already awake,
design a boot-time capture next. Do **not** install a LaunchDaemon or change
Apple daemon state without explicit user approval. Keep such a collector
bounded, removable, and restricted to the proven T2 interface.

## Evidence and repository rules

- Treat `~/Desktop/t2-static-capture` and `~/Desktop/t2-runtime-capture` as
  local evidence. They may contain Apple binaries, packet payloads, hostnames,
  identifiers, or private log material. **Do not add or push them.**
- Commit only tooling, tests, documentation, hashes, addresses, decoded frame
  structure, and narrowly redacted/synthetic fixtures safe for a public repo.
- Preserve exact raw evidence locally until derived claims have independent
  verifiers and tests.
- Do not disable SIP, alter Secure Boot, erase fingerprints, reset the T2,
  write SEP mailboxes, or send biometric commands as part of capture.
- Passive collection and offline reverse engineering are authorized. Any new
  state-changing experiment needs a narrowly described rationale and explicit
  user approval.

## Definition of a useful macOS handback

Before returning to Linux, leave the repository clean and push a checkpoint
that records, without private raw data:

- the exact live binary hashes and macOS/bridgeOS-relevant version evidence;
- the proven T2 interface and address roles;
- listeners and their owning process/state;
- a timestamped, sanitized activation/authentication sequence;
- what remains inferred versus directly observed;
- the next fail-closed Linux experiment and its safety gates.

Also leave a concise continuation note in this document or a new linked file.
The Linux Codex session should be able to resume using only the pushed commit
and locally retained evidence explicitly copied back by the user.
