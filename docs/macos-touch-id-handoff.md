# macOS Codex handoff: T2 Touch ID activation capture

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

The history must contain commit `bfea2e5` or a later descendant. Give the new
Codex session this instruction:

> Read `docs/macos-touch-id-handoff.md` completely, inspect the current git
> state, and continue the T2 Touch ID investigation from its macOS capture
> stage. Preserve the safety and evidence rules in that document. Work as far
> as possible autonomously, but ask before installing a LaunchDaemon,
> restarting Apple daemons, changing enrollment, or rebooting. Never commit
> raw captures or private unified logs to the public repository.

## Established evidence

Do not redo these Linux experiments unless later evidence contradicts them:

- The T2 CDC-NCM device transmits from Ethernet MAC
  `ac:de:48:33:44:55` and IPv6 link-local address
  `fe80::aede:48ff:fe33:4455`.
- Disassembly of the installed macOS `remoted` address helper shows that the
  host peer address for that MAC is `fe80::aede:48ff:fe33:44aa`.
- After a narrow CDC-NCM USB rebind, Linux neighbor discovery and ICMPv6 echo
  to the T2 succeeded from that host peer address. The transport is real.
- TCP ports `58783` (current `remoted` device-role listener candidate) and
  `52032` (legacy BiometricKit listener) both actively refused connections
  during Linux boot. No `_remoted._tcp` mDNS answer appeared.
- Therefore the unresolved problem is activation: macOS starts or wakes a T2
  service that is dormant when Linux boots. Guessing more application payloads
  before capturing that activation exchange is not justified.
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
