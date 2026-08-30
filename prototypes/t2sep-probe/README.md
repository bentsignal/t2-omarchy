# T2 SEP read-only PCI probe

This is milestone zero of the Touch ID bring-up plan. It binds only to Apple
PCI device `106b:1802`, permits `MacBookPro16,1` by default, and reports the
PCI configuration and BAR resources already enumerated by the kernel.

By default it does **not** call `pci_enable_device()`, request or map BARs,
register interrupts, configure DMA, or write PCI/MMIO state. It cannot yet
communicate with the SEP or authenticate a fingerprint.

`no-catacomb-probe.py` is a default-off, explicitly confirmed live probe for
the current pristine-database initializer. It sends command `0x31`, version 1,
with only the selected UID, then reports sanitized shapes from the three
read-only state queries. It does not access macOS storage or persist a
catacomb. On the first T2 Linux run the initializer returned status zero while
all follow-up queries still returned `kIOReturnBadArgument`, showing that
per-user protected configuration remains a separate prerequisite.

An explicitly enabled second-stage probe maps BAR4 and reads only the
hypothesized T8012 mailbox send/receive status registers. The offsets come from
checkra1n/PongoOS's 32-bit SEP mailbox layout. It does not read the receive
payload, enable interrupts, acknowledge anything, or send a message.

The preferred status probe uses the Intel PCIe layout recovered from Apple's
`AppleSEPIntelIOP` driver in the macOS 14.5 Kernel Debug Kit. Apple maps BAR4
(PCI BAR register `0x20`), reads inbound/outbound FIFO status at offsets
`0x108`/`0x10c`, and accesses the 128-bit FIFOs at `0x810`/`0x820`. The probe
reads the status and CPU-control registers only; it does not access either FIFO
or reproduce Apple's startup writes.

`aks-transport.py` separately models AppleKeyStore's recovered endpoint-7
mailbox envelope, reply correlation, capability ordering, bounded request
sizes, byte-exact empty operation-`0x4d` capability bodies, and the
truncated-SHA-256 IPC integrity primitive. Its operation-`0x21` support is
limited to size planning and strict validation of the 96-byte successful
variant-1 response. The size planner returns exact field and padding offsets
for a future locked/scrubbed buffer without accepting either secret blob. Its
authorization plan requires explicit range-checked keybag-handle and selector
metadata from the active session and supplies no guessed Linux defaults. It
models the KDK-proven handle as a per-driver random 64-bit namespace plus a
non-reused client-unique ID (modulo 2^64), returns an opaque handle type, and
rejects bare integers so UID/PID constants cannot be substituted accidentally.
It also mirrors AppleKeyStore's authenticated login-session selector mapping
(UID 0 to `-4`, UID 10 through `INT32_MAX-1` to its negation), returns a
separate opaque selector type, and never reads the ambient process UID. It
performs no MMIO, DMA, live password prompting, or Linux identity substitution.

The same module now has an offline operation-`0x01` variant-1 keybag-create
codec, which addresses the prerequisite exposed by the first live
verify-secret rejection. It requires an explicit typed store value, client
namespace, requested selector, and two caller-owned mutable secret buffers; it
supplies no implicit Apple bag type. Exact bridgeOS 23P6068 clients establish
device `0`, backup `1`, and OTA-backup `3`: `keybagd`'s user-session creation
path passes `0` to `_aks_create_bag`, while MobileKeyBag's named backup and OTA
wrappers pass `1` and `3`. It serializes the exact protected header,
qword namespace, two metadata words, and two four-byte-aligned
length-prefixed blobs recovered from `_code_ipc_create_keybag`. Both input
buffers are consumed and wiped, and closing the request wipes its complete
backing store. The strict 92-byte success decoder returns only the signed
runtime selector; negative user-session selectors are valid Apple handles.
Exact offline operation-`0x05` unload and bounded operation-`0x02`
copy codecs provide the lifecycle teardown and independent presence check.
The SEP unload handler returns success even for an absent bag, so only the
subsequent copy result can establish removal. These remain offline until
store-type semantics are closed; they do not create or unload a live keybag.

The kernel probe now composes those exact operations as a separate, default-off
one-shot gate. With the ephemeral confirmation (distinct from the earlier
missing-bag diagnostic), it creates one store-type-0 user-session bag under a
fresh random namespace, uses the SEP-returned signed selector for verify-secret,
then sends unload and requires a copy operation to return the exact absent-bag
status before teardown can pass. The password remains in a temporary kernel
user key through create, is revoked before verify-secret is sent, and every OOL
buffer is scrubbed only after the corresponding reply or CPU stop. An
independent transcript verifier requires the full create/authorize/unload/
absence/context-delete/CPU-stop sequence exactly once.

This is an experiment boundary, not account authentication. Because the probe
creates the bag whose secret it then verifies, success establishes that Linux
can manufacture a fresh ACM credential context; it does not independently
prove knowledge of a pre-existing macOS account secret. Its purpose is to test
whether bridgeOS accepts that fresh context for Linux-native enrollment while
making the temporary AKS state auditable and bounded.

```bash
./run-password-authorization-probe.sh \
  I_UNDERSTAND_EPHEMERAL_KEYBAG_ATTEMPT 501
```

The first supervised run on 2026-08-29 passed the complete verifier: SEP
returned runtime selector `1`, accepted operation `0x21`, accepted unload, and
then returned `-3` to the independent copy-after-unload absence check. No
password, context, or returned device-state bytes were logged.

That run requested selector `-501`, incorrectly conflating the login-session
lookup selector with keybag creation's internal default. Exact disassembly of
bridgeOS 23P6068 AppleKeyStore shows public `_aks_create_bag` supplies `-1` to
its internal seven-argument create routine, while `keybagd` supplies only the
secret, length, store type zero, and output handle. The live creation gate now
uses that exact `-1`; the SEP-returned runtime selector remains the only handle
passed to verify and teardown.

A supervised rerun with that correction again created runtime selector `1`,
authorized the ACM context, and received synchronous BiometricKit status `-3`
before sensor activation. Full teardown passed. This rules out the create-time
selector discrepancy as the cause of the biometric rejection; no touch was
requested and no identity changed.

The next bounded gate now reproduces Apple's post-create system-bag transition
instead of treating creation as the complete user-session setup. The
symbol-rich 23F79 AppleKeyStore KDK identifies operation `0x0d` as
`ipc_make_system_keybag`. Its exact variant-0 request is the protected header,
client namespace, positive source runtime handle, negative target session
selector, and length-prefixed passcode. Service-side validation requires a
positive source, a target below `-2` other than `-5`, and an existing source
bag; it serializes and reloads the bag under the target before applying the
passcode. The Linux gate therefore promotes runtime selector `1` to the
explicit `-UID` selector, verifies the ACM context against that promoted bag,
then independently ensures absence for both target and source. Distinct
lifecycle labels and tags make either leaked mapping fail the strict transcript
verifier.

The first live promotion request exposed an additional ordering rule rather
than reaching enrollment. Before the tagged operation-`0x0d` reply, T2 emitted
two endpoint-7 keybag notifications with opcodes `0` and `4`, tag `1`, and the
exact target selector `-501`. The original single-reply waiter consumed the
first notification and failed closed; later reads proved the real correlated
reply was still queued as `00048d07 00580001 ...`. CPU stop and DMA scrub ran,
but ordinary message-level teardown could not be verified because the queue
was displaced. The new waiter requires those two notifications in exact order
before accepting the tagged reply, including its observed low flag `1`.
Cleanup is now state-adaptive: a strict copy first proves a mapping absent or
present, and only a proven-present mapping is unloaded and checked again. This
also covers the observed fact that promotion moves/remaps the positive source
rather than necessarily retaining two live bags. A corrected supervised run
is still required before BiometricKit acceptance is known.

The following run began with two replies still pending from that displaced
queue, so its control NOP correctly failed before OOL setup or password use.
The startup gate now handles this recoverable state only while CPU control is
the exact stopped value `0x7f`: it drains at most 16 already-pending mailbox
records without reading any OOL payload, requires the inbox to become empty,
and only then starts the CPU and sends the tagged NOP. A password-free live
validation drained the remaining endpoint-7 copy reply and endpoint-0 control
reply, then received the exact fresh NOP response `00010100 00000000
00000000 ...`. CPU stop and module removal completed normally. This avoids a
power cycle after a fail-closed correlation experiment without allowing live
traffic to be discarded while the SEP is running.

The next live run proved the promotion itself: after both required
notifications, operation `0x0d` returned status zero and a subsequent copy of
selector `-501` returned a valid 1612-byte bag. The reply's low word was `0`
rather than the earlier queued value `1`, proving it is transient queue state;
the validator now accepts only those two observed values with exact body size.
Unloading the system selector then emitted one additional exact endpoint-7
notification (opcode `1`, tag `0`, selector `-501`) before its tagged reply.
The displaced source copy subsequently returned status `-13`, establishing the
distinct invalidated-source result after a successful move. The waiter now
correlates that unload notification, and cleanup accepts `-13` as absence only
for the positive source lifecycle after promotion; ordinary missing bags still
require `-3`. The run did not reach ACM verification or BiometricKit, and CPU
stop/scrub/module removal completed. A password-free resynchronization drained
the remaining ACM delete reply and revalidated a fresh control NOP.

A subsequent fully correlated run completed promotion, verification, handoff,
and teardown. It created runtime selector `3`, promoted it to `-501`, authorized
the ACM context against `-501`, and delivered the context to the exact current
enrollment request. That changed the synchronous BiometricKit result from
`-3` to `261` (`0x105`), but still did not request a touch or create an
identity. Cleanup proved the 1612-byte system mapping present and then absent;
in this run the positive source mapping was also retained, so it too was
unloaded and independently proved absent. The adaptive two-role cleanup is
therefore required: successful promotion may retain the source even though one
earlier displaced run reported source status `-13`.

Static KDK analysis shows one relevant use of `0x105`:
`AppleMesaSEPDriver::cacheSysProtectedConfigurationSpecific(bool)` returns it
when the cached system-configuration object is unavailable, while the success
path sends `GetSystemProtectedConfig` (`0x39`) and consumes a 36-byte response.
This is evidence for the next configuration-lifecycle gate, not yet proof that
the live `261` has that exact origin. A read-only Linux command-`0x39` query
subsequently succeeded with the exact 36-byte response shape, but every 32-bit
field was zero. The next safe comparison is the same query under macOS; command
`0x3a` must not be sent until its ownership, field meanings, and macOS values
are independently recovered.

`run-authorized-enrollment-probe.sh` is the separately confirmed next-stage
experiment. It repeats that proven lifecycle but keeps the authorized ACM
context and temporary keybag live while one BiometricKit enrollment runs. A
root-only module parameter exposes the context's 16-byte external form exactly
once; the runner pipes it directly to the enrollment client on standard input,
never an argument or log. The client consumes it into Apple's exact 68-byte
version-2 built-in enrollment request and scrubs its owner after the synchronous
send. A distinct write-only acknowledgement ends the handoff. Both waits are
capped at five minutes, and timeout, client failure, or shell exit still leads
to unload, copy-after-unload proof, context deletion, CPU stop, and DMA scrub.
An independent verifier requires the handoff markers to occur strictly between
authorization and unload. This path has passed build and offline tests but must
not be described as live-proven until its first supervised run succeeds.

The first combined attempt proved the kernel half but failed before any
BiometricKit command because NetworkManager had left the T2 NCM interface
disconnected and therefore installed no scoped IPv6 route. The client returned
`ENETUNREACH`; the handoff acknowledgement, keybag unload/absence proof,
context delete, CPU stop, and scrub still all passed. Restoring the manual
`fe80::aede:48ff:fe00:1122/64` profile made the peer answer three scoped pings
and restored the read-only `(0, 3)` BiometricKit reply. The runner now performs
that exact method-zero query before opening the password prompt, so a missing
route or stale service port fails without consuming a credential attempt.

```bash
./run-authorized-enrollment-probe.sh \
  I_UNDERSTAND_THIS_CREATES_ONE_FINGERPRINT_IDENTITY 501
```

`acm-transport.py` models AppleCredentialManager's distinct fixed-endpoint-10
envelope, OOL length bound, reply message-type correlation, zero-status SCRD
initialization with Apple's fixed KDK-derived version `0x28`, and zero-status
exact-length context creation. Its current path sends selector `0x24` first and
expects 21 bytes, accepting only an exact empty status-`-3` reply as permission
to fall back to legacy selector `1` and 17 bytes, matching the pinned
`LibCall_ACMContextCreate` branch. It also models the source-proven selector-2
context deletion, including its exact 16-byte external-form body, empty reply,
mutable caller-owned buffers, and explicit scrub. Its state does not advance
when a request is merely constructed or sent, and it never stores or returns
the opaque context bytes. It likewise has no device-I/O path.

`credential-services-bootstrap.py` composes fixed ACM/AKS OOL registration,
independently observed acknowledgement profiles, and stop-scrub-release
ownership. Separate supervised 2026-08-28 captures established fixed
acknowledgement profiles for both mappings of each service: AKS `(opcode 1,
target 7)` and ACM `(opcode 1, target 10)`. The pure bootstrap deliberately has
no kernel or DMA-allocation path. Its dual-service model reserves four globally
distinct control tags and four non-overlapping mappings, validates every ACK
before committing either endpoint, and stops both idle endpoints before any
mapping can be scrubbed or released.

`run-dual-credential-ool-capture.sh` is the next separately gated, unexecuted
hardware discriminator for that model. It allocates four zeroed 16 KiB DMA
mappings under the existing 32-bit mask, registers AKS with tags 2/3 and ACM
with tags 4/5, sends no service envelope, stops the CPU, then scrubs and frees
all four mappings. A cursor-bounded independent verifier requires the exact
already observed `(1/7, 1/7, 1/10, 1/10)` ACK sequence, distinct non-overlapping
addresses, nonzero observations on both MSI vectors, and complete PCI/module
teardown. It must not be run without the user present.

`credential-session.py` is the socket- and device-free boundary that joins
that dual transport lifetime to `credential-authorization.py`. No ACM or AKS
request can be built until all four registrations are accepted. It permits one
tracked exchange at a time, drains the matching operation before validating a
reply, refuses global teardown while either endpoint is active, and requires a
live ACM context to be deleted or explicitly abandoned via stop-before-scrub.
It contains no live-send method and does not expose password contents.

`run-aks-capabilities-probe.sh` is the separately confirmed next-stage wrapper.
Its default-off kernel gate sends only the non-mutating empty operation `0x4d`
after the proven AKS registrations and strictly validates its protected
reply. A live run proved that this T2 returns the version-1 header in its
compact 72-byte form: 4-byte header length + 72-byte header + 16-byte body =
92 bytes. The digest, zero status, and remote version 2 all validated. Both
that observed form and the 100-byte 80-byte-header form are modeled strictly.
The wrapper requires a fresh journal cursor and has no stale recent-log
fallback.

`run-aks-time-sweep-probe.sh` tries at most five non-secret continuous-time
classes and stops on the first strict reply. The first live candidate, zero,
succeeded; continuous time was not the cause of the earlier apparent timeout.
The old parser discarded the immediate 92-byte response because it expected
only 100 bytes. A subsequent live startup-prefix run negotiated version 2 and
completed operation `0x2a` environment setup with a validated zero-status
response.

`run-credential-startup-probe.sh` is the next default-off, separately
confirmed integration gate. It keeps AKS and ACM registered simultaneously,
completes the validated AKS capability/environment prefix, and only then runs
the validated secret-free ACM ephemeral context create/delete lifecycle. Its
independent verifier requires all four non-overlapping DMA registrations,
strict service ordering, both service state machines, CPU stop before four
buffer scrubs/releases, MSI activity, PCI restoration/release, unload, and
unbind. A live run passed the entire sequence: AKS negotiated version 2 and
accepted environment setup, ACM initialized and created/deleted its current
21-byte context, both MSI vectors fired 11 times, and the composite transcript
verification passed after complete teardown. No password, context bytes, or
biometric data were logged.

`run-password-authorization-probe.sh` is the first password-bearing gate. It
prompts once through `systemd-ask-password` and pipes the bytes directly into
a temporary kernel `user` key; the password is never a shell variable,
argument, environment value, module parameter, or log field. The module
accepts only that key type and 1..256 bytes, constructs one bounded
operation-`0x21` request in coherent memory, revokes the key before sending,
and erases both AKS buffers immediately after a reply. It always attempts to
delete the ephemeral ACM context, then stops SEP and scrubs all four buffers.
The independent verifier accepts only a correlated 96-byte success reply,
authorization-before-delete ordering, and complete combined teardown. The
first live attempt reached operation `0x21` and received the correlated,
bodyless service status `-1` (`ff03a107 00000000 ...`). Static inspection of
the pinned AppleKeyStore implementation shows that its handler first calls
`keybag_for_handle` and returns exactly `-1` when the requested keybag is not
loaded. Linux had started a fresh client namespace but had neither created nor
loaded a keybag, so this result must not be labeled a wrong password. The next
authorization stage is an explicit create/load-keybag lifecycle under the same
client namespace, followed by verification using the returned handle.

`run-acm-context-lifecycle-probe.sh` is a different, mutually exclusive
wrapper. It uses the observed ACM `(1/10, 1/10)` OOL profile, sends exact SCRD
initialization, then Apple's bodyless selector-`0x1d` readiness ping before
attempting current selector `0x24` and its exact legacy selector-1 fallback.
If creation succeeds it deletes that same token-free ephemeral context before
CPU stop. It never logs the 17/21-byte response or the 16-byte external form.
The kernel path validates every
endpoint/type/length/status/reserved/error field, stops before DMA cleanup on
all exits, and requires its own confirmation. The independent cursor-bounded
verifier additionally proves exact phase ordering, secret-free log markers,
MSI activity, PCI restoration/release, unload, and unbind. The code is built
and tested but must not be run unattended.

The live T2 requires a zero 32-bit domain body on both create selectors, even
though the inspected client-side wrapper passes no body to its transport.
This matches the pinned service-side `CreateCredentialSet` validation exactly:
body sizes below four return `-3`. The verified current request is therefore
12 bytes (`DRCS 24 00 04 01` plus domain zero), returns 21 bytes, and has been
successfully deleted with selector 2 in a complete verified live lifecycle.

The kernel module now contains a separate, default-off capture gate for the
two fixed credential endpoints. It registers two 16 KiB zeroed mappings and
captures only their control acknowledgements; it sends no ACM or AKS service
message. `run-credential-ool-capture.sh` adds model/PCI/driver checks, an exact
interactive confirmation, cursor-bounded logs, independent verification, and
unload checks. It now refuses to run without a fresh journal cursor and has no
recent-log fallback. The verifier binds the requests to the logged distinct
DMA mappings, requires exact tags, zero status/reserved words, both MSI
vectors, stop-before-scrub, PCI restoration/release, and final probe removal.
Do not run it unattended. Its only accepted endpoints are `7`
(AKS) and `10` (ACM), and the two services must be captured in separate runs.

Build against the running kernel:

```bash
make
modinfo ./t2sep_probe.ko
```

Before loading, confirm the SEP function is still unbound:

```bash
readlink /sys/bus/pci/devices/0000:04:00.2/driver || true
```

Load, inspect, and unload interactively:

```bash
sudo insmod ./t2sep_probe.ko
sudo journalctl -k -n 30 --no-pager
sudo rmmod t2sep_probe
```

Apple's control endpoint provides a NOP command. This is the first bounded
request/response test: it sends one NOP with tag 1, waits up to five seconds,
and consumes at most one 128-bit response. The probe rejects Apple's transport
error bits and requires the exact previously observed NOP header plus zero
data/reserved words. The fourth word is transport metadata and is logged
separately. It requires the recovered transport enable sequence and two MSI
vectors:

```bash
sudo insmod ./t2sep_probe.ko apple_start_cpu_probe=1 \
  apple_start_with_msi=1 apple_send_control_nop=1
sudo rmmod t2sep_probe
```

Apple enables two MSI event sources before starting the SEP CPU. The bounded
variant below allocates exactly two MSI vectors, records interrupt counts,
runs the same start/stop probe, then frees both vectors and restores the PCI
enable state:

```bash
sudo insmod ./t2sep_probe.ko apple_start_cpu_probe=1 apple_start_with_msi=1
sudo rmmod t2sep_probe
```

Run the recovered Apple-layout read-only probe with:

```bash
sudo insmod ./t2sep_probe.ko read_apple_layout=1
sudo journalctl -k -n 30 --no-pager
sudo rmmod t2sep_probe
```

The next explicitly gated experiment reproduces the three MMIO writes in
Apple's `_startCPUGated()`, polls only the two FIFO status words for up to one
second, and then reproduces Apple's `_stopCPUGated()` write. It never reads or
writes either payload FIFO:

```bash
sudo insmod ./t2sep_probe.ko apple_start_cpu_probe=1
sudo journalctl -k --since "10 seconds ago" --no-pager | grep t2sep_probe
sudo rmmod t2sep_probe
```

The first reversible state-changing experiment temporarily enables PCI memory
decoding through the kernel's normal PCI API, scans the status candidates, and
disables the function before probe returns. Because firmware left this
function's PCI command word enabled despite Linux's enable refcount being zero,
the probe saves and restores that word exactly:

```bash
sudo insmod ./t2sep_probe.ko temporarily_enable_device=1 scan_apertures=1
sudo rmmod t2sep_probe
```

Run the separately gated status-register experiment with:

```bash
sudo insmod ./t2sep_probe.ko read_mailbox_status=1
sudo journalctl -k -n 30 --no-pager
sudo rmmod t2sep_probe
```

If status bit `0x20000` is clear, PongoOS treats the receive mailbox as
non-empty. The next gate consumes and decodes at most one inbound message. It
still performs no MMIO write, but unlike the status-only probe this read may
advance the hardware receive FIFO:

```bash
sudo insmod ./t2sep_probe.ko read_mailbox_status=1 read_one_message=1
sudo rmmod t2sep_probe
```

If BAR4 is inert, the status-only aperture comparison reads the same PongoOS
status offsets in each PCI BAR. It does not read a payload:

```bash
sudo insmod ./t2sep_probe.ko scan_apertures=1
sudo rmmod t2sep_probe
```

Do not install this in the initramfs or configure it for automatic loading.
The PCI address may differ on another boot or machine; the device ID and DMI
allowlist, not the example address, are the safety checks.

`decode-message.py` is an offline decoder for four 32-bit FIFO words. It never
opens a device or accesses MMIO. In addition to the common SEP header, it
decodes the two passive discovery records used by Intel macOS on endpoint
`0xfd`: opcode 0 advertises an endpoint ID/name and opcode 1 supplies its four
OOL page limits. Run its tests with:

```bash
python -m unittest test_decode_message.py
```

`generic-transfer.py` is a separate offline encoder/decoder for the recovered
28-byte AppleSEPGenericTransfer framing and its 64-bit mailbox notification.
It is not connected to the kernel prototype and cannot issue SEP commands.
Its parser rejects bad versions, reserved bits, inconsistent lengths, and
out-of-range chunks. Its coupled inbound state machine additionally binds the
16-bit sequence, mailbox and packet commands, message type, bounded
reassembly, completion state, and remote-error record; it rejects every record
after completion. Its duplex transaction session also couples request upload,
packetless continuation pulls, response reassembly, and the shared per-direction
sequence streams; request-upload completion alone is never reported as a
completed transaction.

The Intel mailbox envelope is modeled separately. KDK disassembly proves that
the x86_64 manager copies three payload words and replaces the first word's low
byte with the endpoint ID, while GenericTransfer constructs the adjacent
64-bit sequence/command/type notification. The available evidence does not
prove the source or value of the third payload word for Intel `sbio`.
`envelope_endpoint_notification()` therefore requires that word explicitly and
has no zero-valued default. It cannot silently turn the two-word notification
into a guessed live FIFO record.

The only SBIO-specific helper is the recovered initialization fixture:
command `0x73`, flags zero, four-byte little-endian value `3`, and a strictly
empty response transaction. No pairing, key-exchange, sequence-state,
enrollment, or matching command encoder is present, and nothing connects this
fixture to the kernel module.

`intel-fifo.py` independently models the x86_64 driver's exact MMIO action
order without opening or mapping a device. A receive plan is four ordered reads
at `0x810..0x81c`. A post plan checks outbox-full, writes payload words 0..2,
commits with a literal zero at `0x82c`, and finishes with the driver's status
read at `0x10c`. It rejects host metadata in word 3 and received error/fatal
flags. The model also names the exact MSI sources: vector 0 is inbox-nonempty
and vector 1 is outbox-empty.

`endpoint-lifecycle.py` separately tracks the OOL ownership contract without
allocating memory. It commits mappings only after a successful control
response, retains replaced mappings because Intel exposes no unregister
opcode, balances active operations and sleep holds, and permits release only
after transport stop plus explicit scrub. Run the offline suites with:

`endpoint-router.py` models the later normal doorbell callback. It strips the
fourth transport word, routes only registered endpoint IDs `0..31`, and uses
the recovered 32-index/31-message circular queue bound. Unknown or fixed-range
records are dropped, disabled queues retain messages, transport errors fail,
and a full queue never overwrites data.

```bash
python -m unittest test_decode_message.py test_generic_transfer.py \
  test_intel_fifo.py test_endpoint_lifecycle.py \
  test_endpoint_router.py \
  test_bridge_protocol.py test_bridge_query.py test_rsd_protocol.py \
  test_rsd_query.py test_verify_discovery_log.py test_kernel_ool_safety.py \
  test_sbio_bootstrap.py test_verify_ool_log.py
```

`bridge-protocol.py` models the separate Intel host-to-bridgeOS route first
recovered from Catalina and now cross-checked in the installed macOS 26.6.2
x86_64 biometric daemon and BridgeXPC 39 framework. It encodes the verified
method-3 array, the daemon's eight-byte inner BiometricKit header, and the
current 16-byte BridgeXPC socket record plus normal-message binary plist.
Current method 0 and 1 query/reply shapes are also validated offline.
It validates integer widths, both magic values, types, arity, and
caller-supplied size limits. It refuses to guess the private `BTNil`
serialization and does not connect to BridgeXPC, USB, PCI, or SEP.

`biometric-command.py` adds the exact Catalina 19H15 operation layer without
adding any I/O. The ordinary match request is command `4`, version `1`, value
zero, a 68-byte input, and zero output capacity. Its public encoder permits
only zero processed flags and an all-zero 60-byte special-mode union; therefore
credential-set, enrollment-extension, capture-only, payment, and biometric
lockout-bypass requests cannot be represented. The default user ID is Apple's
initialized value `0xffffffff`. Presence detection (`0x26`) and cancellation
(`0x0c`) are retained as offline field tuples. None of these commands is wired
into `bridge-query.py` or any live runner.
The separately named current-format enrollment constructor accepts only a
mutable 16-byte ACM external form from the successful credential lifecycle,
consumes and zeros that input, and produces only command 3/version 2 for the
live-proven built-in device group. Its 68-byte mutable request owns the sole
remaining credential copy and must be explicitly closed to scrub it; ordinary
token-free APIs remain unable to express privileged variants.
The same module has a deliberately partial Catalina async-result decoder for
the proven user ID, 16-byte UUID, and bounded lockout-list IDs. It requires an
exact self-consistent length and explicitly does not treat parsing as proof of
authentication; event/request correlation, terminal status, and trusted
identity enumeration are still mandatory.

`authentication-result.py` supplies that final offline authorization boundary.
It arms exactly one match operation for one Unix user, consumes only the proven
terminal match event/version, treats result user ID `0xffffffff` as no-match,
and requires every successful user-ID/UUID pair to exist in a separately
enumerated trusted snapshot. Unknown identities, cross-user results, activity
events, malformed data, duplicate completion, and incomplete operations all
fail closed. A rejected event cannot be followed by a retry on the same
operation, and callers can permanently abort after timeout, cancellation, or
transport loss. It has no PAM, fprintd, socket, USB, PCI, or SEP entry point.

`linux-auth-broker.py` defines—but does not open—the narrow local protocol for
eventually placing that decision behind PAM. The fixed 24-byte request carries
only a nonzero random correlation ID, root-selected target UID, and bounded
timeout. A server-side state machine accepts only kernel-derived root peer
credentials, one request, one fresh deadline, and the exact trusted
`AuthenticationDecision`; its fixed response authenticates only status zero.
Wrong users, stale/cross-request replies, explicit no-match, timeout, malformed
framing, unprivileged peers, and reuse all fail closed. It is an offline model,
not a daemon, PAM module, socket, or system configuration change.

`read-only-biometric-plan.py` composes the eventual post-handshake inspection
sequence entirely offline from a strictly validated RSD transcript. It emits
Bridge methods 0 and 1 followed only by Catalina's maximum-identity-count
(`0x0f`), free-identity-count (`0x41`), and identity-list (`0x42`) requests.
The module exposes no socket API and cannot construct enrollment, match,
presence, cancellation, or identity removal. This is preparation rather than
live authorization: the current macOS wire comparison and current bridgeOS
command compatibility must both succeed before any method-3 frame is sent.
`read-only-biometric-result.py` provides the matching socket-free receive state
machine. It accepts exactly three successful method-3 replies in plan order,
requires bounded NSData output, validates both counts and the identity records,
rejects identities for another user or more listed identities than occupied
sensor slots, and cannot finish on a partial or repeated sequence.

`bridge-query.py` is a separately gated runner for the first passive bridge
query. With no arguments it only prints deterministic HELO and method-0 frame
fixtures. Its live code has no method-3 or SBIO encoder: it verifies the
interface is USB `05ac:8233`, has carrier, and descends from PCI `04:00.1`;
then it uses a timeout of at most five seconds, caps bodies at 64 KiB, accepts
at most four frames, and validates the exact bridge-version reply. Live mode
requires both `--live` and a long confirmation token. Do not run it until the
T2 interface has a scoped link-local configuration and a live passive query is
explicitly intended. Its connection path is additionally hard-disabled in
source until port `52032`, currently proven only from Catalina 19H15, is
verified against the newer bridgeOS installed on this machine. The separate
`captured-bridge-query.py` removes that stale fixed-port assumption: it accepts
only a private, mode-0600, checksum-valid transcript, independently replays the
strict directory parser, and derives the service port from that transcript.
A supervised Linux attempt reached the advertised TCP listener but received no
BridgeXPC reply within three seconds, even with the exact current 119-byte HELO.
Its source gate was restored to false; the result points to an activation or
pre-BridgeXPC transport step still to recover.

The alternative of waiting for the server HELO before sending the historical
raw logical method 0 was
also tested. The T2 ACKed the complete request but emitted no reply or reset.
Catalina disassembly confirms native BridgeXPC instead sends its HELO and queued
method 0 back-to-back, so the runner preserves that ordering. The unresolved
boundary appeared to be remote-service activation/handoff rather than packet
delivery. Exact-current `bkremoted` later showed the actual cause: the logical
array had not been wrapped in `BiometricKitBridgeTransport`'s four-object
request envelope.

`coupled-bridge-query.py` tests whether the advertised service lifetime is
scoped to its Multiverse directory connection. It discovers the dynamic port
and opens BridgeXPC method 0 while the same directory socket remains open. It
has a separate false-by-default source gate and no method-3/SBIO path. A
supervised raw-inner run again received the peer HELO but no method reply,
ruling out premature directory teardown as the missing activation step. The
corrected runner now sends `[1, false, UUID, [0]]`, strictly correlates
`[1, true, UUID, [status, version]]`, and has returned `(0, 3)` from the live
T2. The successful request and reply frames were 113 and 132 bytes.
The same envelope around read-only method 1 subsequently returned
`(status=0, opened=true)`; its request and reply frames were 110 and 131 bytes.
The transport then carried capped read-only biometric commands successfully:
maximum identities returned 5; UID 1000 enumerated zero identities; UID 501
enumerated one. UUID bytes are intentionally omitted. Current bridgeOS's
private `BTNil` output is the exact lower-case reserved UUID string and is
accepted only in that form by the method-3 decoder.

`sensor-context-probe.py` is a separately gated, bounded read-only extension
of that working session. It sends only the current readiness `0x53`,
provisioning-state `0x10`, and sensor-info `0x35` requests, validates their
exact one-, four-, and 12-byte success shapes, and never prints sensor-info
bytes. Its first live run returned status zero for all three, readiness 1,
provisioning state 5, and a 12-byte sensor-info result. The companion reset
`0x02` version-2 codec is tested offline but is intentionally absent from this
runner. Patch, MSRk, calibration, and catacomb-load commands are also absent.

The live accessory result was status zero with exactly one 44-byte record and
one built-in accessory/group classification. `external-catacomb-load-probe.py`
now reproduces and validates this complete non-secret read sequence on the
same session before its already-gated general-then-user load. It fails closed
unless readiness is 1, sensor-info declares size 12, and the device list is
exactly one built-in record; it never exposes record UUIDs or bytes.

The ordered load comparison still returned status 257 on the general
component after all four reads succeeded. A separate, confirmation-gated
`sensor-reset-probe.py` then initially attempted misdecoded reset `0x02` v2
and sensor-info reads with a maximum of three attempts. The live T2 returned
`0xe00002c2` (`kIOReturnBadArgument`) on all three, so the runner stopped before
sensor-info and device-list readback. This is preserved as evidence of a
missing reset-envelope evidence; it is not treated as permission to guess MSRk
or calibration inputs. Catalina's symbolized call subsequently proved the
same current byte pattern is compatibility-wrapper version 1 with `inValue=2`.
The corrected live request succeeded on its first attempt, followed by valid
sensor-info and exactly one built-in device record on the same session.

The next missing normal read was recovered locally from the checksum-known
Catalina daemon: command `0x28` v1/value 0 returns exactly 23 packed bytes, and
byte 22 is the calibration-present boolean. The current T2 returned status
zero with `calibration_present=True`. `sensor-reset-probe.py` now reports only
that boolean and lengths/counts; `external-catacomb-load-probe.py` inserts the
read between sensor info and `0x52` and refuses any load when the flag is false.
Catalina startup also issues the already-decoded `0x0c` v1/value-0 cancel
immediately after a successful reset. The external loader now requires that
same no-output cancellation before continuing to sensor-info reads.
The bounded live retry returned cancellation status zero but the retained
general component still returned status 257, so cancellation alone is not the
missing catacomb-load prerequisite.
BiometricSupport's cold-state branch was then reproduced explicitly: command
`0x31` initialized general UID `0xffffffff` with status zero before the load.
The following retained general component still returned 257. Missing host-side
catacomb-map bookkeeping and the cold `NoCatacomb(-1)` transition therefore do
not explain the rejection.

The native enrollment transaction now also performs the proven reset, cancel,
sensor-info, calibration-present, and one-built-in-accessory sequence on the
same Bridge connection before initializing either empty catacomb. Earlier
enrollment attempts performed only a separate connectivity preflight, so they
did not establish this per-connection sensor context before command `0x03`.
Current command `0x4c` version 1 also reports xART available with a canonical
one-byte true result after that sequence; versions 0 and 2 return
`kIOReturnBadArgument`. Enrollment now requires the same read on its live
session before it initializes either empty catacomb.

`BridgeSession` keeps one HELO-active socket, correlates multiple replies, and
queues server-initiated envelopes that race a synchronous call. The gated
`presence-event-probe.py` verified a status-zero presence start, method-9
service event (`0xe3ff8001`, version 1, ordinal 59, no data), and status-zero
same-session cancellation. It caps and structurally decodes the 40-byte service
record, collects at most two events, but never prints raw data. The first
five-second physical-touch window produced only the initial status, so a
coordinated retry is still required.

`match-authentication-probe.py` is the source-disabled next stage. It takes a
fresh, UID-scoped identity snapshot on the same session, starts only the
ordinary match form, permits only the statically/live-proven ready and activity
events before the terminal match event, and delegates the final decision to
the fail-closed trusted-identity model. Exact trusted match, explicit no-match,
unknown UUID, unexpected event, timeout, and mandatory-cancel paths are tested.
Its result intentionally omits identity UUIDs.

`enrollment-probe.py` is the corresponding source-disabled Linux-native
enrollment state machine. It permits only Catalina's statically mapped,
size-bounded progress statuses, requires the exact terminal enrollment event,
and then proves an independent before/after identity-list delta of exactly one.
The terminal identity and newly enumerated identity must be identical. Tests
cover success, missing list mutation, terminal/list mismatch, cancellation,
and the closed live gate; no UUID is returned or logged.
Because the directory marks BiometricKit `UsesRemoteXPC: false`, a subsequent
bounded experiment prefixed the public `RSDCheckin` plist used for non-RemoteXPC
services. The T2 then immediately supplied a valid HELO (`bkremoted`, `23P6068`,
version 39) rather than the generic two-plist check-in response. It reset as
soon as Linux sent a client HELO, even when that HELO mirrored the peer. The
check-in-shaped write is therefore retained only as evidence of a missing
activation/framing boundary, not treated as a proven BiometricKit handshake.
The source gate must be an exact port plus nonempty evidence tuple. Peer HELO
JSON must have the recovered four keys and valid types; invalid interface names
and nonfinite/out-of-range timeouts are rejected before sysfs or socket access.

`rsd-protocol.py` models the newer `remoted` directory route offline. A macOS
26.6.2 boot capture proves
that the host asks RemoteServiceDiscovery for `com.apple.eos.BiometricKit`,
constructs a `BridgeXPCConnection` with `initForRemoteService:`, and activates
it. The live directory used boot-dynamic T2 port `59602`, then advertised
boot-dynamic BiometricKit port `49165`; fixed port `58783` belongs to a
different `remoted` role. Independent implementations agree on HTTP/2 plus
RemoteXPC framing, and the local encoder has been checked byte-for-byte against
one of them. The module can encode the passive directory handshake and
strictly decode the named advertised service port, but contains no socket
calls or fixed directory port.

`rsd-mdns.py` models the missing same-boot bootstrap without sockets. Installed
`remoted` proves the named endpoint `ncm._remoted._tcp.local.`; the module emits
its exact SRV query (including a strictly typed QU variant) and also retains a
generic PTR fixture. It incrementally validates at most
16 T2-sourced mDNS datagrams / 64 records / 64 KiB. Its DNS decoder bounds
compression traversal, detects pointer cycles, enforces record boundaries,
requires the exact named SRV (with a consistent PTR when present), rejects conflicting ports and non-T2 sources, and
optionally checks the target AAAA against the wire-proven T2 address. The
transcript-to-endpoint handoff derives the TCP port only from that validated
SRV record; it has no caller-controlled port parameter. Live multicast remains
disabled pending a supervised run from the corrected host address.

`t2ncm-flags-probe.c` reproduces only AppleUSBNCM's four-byte device-to-host
interface-flags read for USB `05ac:8233`. It verifies the exact T2 PCI/USB
ancestry, control interface, and standard device descriptor before issuing
`a1/a0/0000/0000/0004`; it requires an exact confirmation, a fresh private
output file, and a source kill switch. `run-t2ncm-flags-probe.sh` temporarily
unbinds only `7-1:1.0` and always rebinds it through an exit trap. The supervised
result was `00 00 00 00`, and neither multicast nor direct RSD discovery woke
afterward, so this read is now retained as disproven activation evidence.
The companion `run-t2ncm-apple-config.sh` also reproduces the four exact
AppleUSBNCM `configureData` class operations while the function is unbound and
restores Linux's driver through the same trap. That sequence completed, but
both discovery paths remained silent, ruling out ordinary NCM configuration
values as the service wake trigger.

`rsd-mdns-query.py` stages that supervised boundary. Its fake-socket-tested
engine sends one exact named SRV/QU query and accepts only UDP/5353 datagrams from the
wire-proven T2 address with the expected IPv6 interface scope. It carries the
complete bounded datagram transcript into the endpoint evidence. The live
branch additionally verifies exact T2 USB/PCI ancestry, carrier, finite
five-second timeout, multicast interface, and host bind address, but its source
kill switch remains false and is checked before sysfs or socket access.

The supervised SRV/QU query, a multicast SRV query, a generic PTR query, and an
independent Avahi browse all produced no T2 DNS response despite healthy ICMPv6
and advancing error-free TX. This establishes that the bridgeOS DNS-SD
responder is dormant under Linux, rather than that Linux lacks the query codec.

`discovered-rsd-query.py` is the final socket-constructor-free composition. It
accepts an mDNS socket and a connector callback, derives the callback's sole
endpoint argument from validated DNS-SD evidence, then runs the bounded passive
directory capture. Its result retains both the complete mDNS datagrams and RSD
server transcript. There is deliberately no directory-port argument and no
real socket import or constructor in this handoff layer.

Its `PassiveRSDTranscript` state machine validates a complete server transcript
from fragmented offline bytes. It caps bytes, frames, controls, and XPC sizes;
requires peer settings before data; accepts only streams 1 and 3; refuses
cross-stream XPC reconstruction, flooding, unsupported HTTP/2 records, partial
termination, and trailing traffic; and returns only the strictly validated
named service port. Tests exercise byte-at-a-time input, multi-frame XPC
fragmentation, malformed settings/window updates, wrong streams, truncation,
interleaving, surplus frames, resource caps, and deterministic garbage.

`rsd-query.py` is the staged passive-directory runner. Default execution only
prints deterministic fixtures. Its fake-socket-tested engine sends transport
setup, waits for validated peer SETTINGS, then sends the SETTINGS ACK and
device handshake; it never constructs a service-open message. The engine now
returns an immutable capture containing both the strictly decoded advertised
port and the exact bounded server transcript, so a supervised result can be
revalidated by the socket-free handoff instead of trusting a copied number.
The compatibility wrapper still returns only the port. The live branch
is checked before sysfs or socket access and remains mechanically disabled by
`LIVE_DIRECTORY_CAPTURE_ENABLED = False`. The macOS boot trace proved host
address `fe80::aede:48ff:fe00:1122` on `en6`, while a supervised Linux rebind
capture proved
this T2 transmits as `ac:de:48:33:44:55` /
`fe80::aede:48ff:fe33:4455`. The host address agrees with the Linux CDC
descriptor MAC `ac:de:48:00:11:22`; the earlier `...:44aa` inference was
wrong. No same-boot directory-port verifier exists yet. Even if the kill
switch is deliberately changed, the source gates, two CLI gates, exact internal
T2 USB/PCI ancestry, carrier, a maximum five-second deadline, and the
transcript validator's byte/frame limits must all pass.

The initial supervised attempt exposed a prerequisite below this runner: after
a T2BCE stateful sleep/resume, CDC-NCM reported zero successful TX packets,
increasing TX errors, `NETDEV WATCHDOG`, and a VHCI output-pause timeout. No
RSD frame left Linux. Connection-profile cycling did not clear the stale USB
request; rebind the T2 NCM interface or reboot and confirm TX advances before
repeating the passive capture. The live kill switch remains disabled in source.

`discovered-bridge-plan.py` is the socket-free handoff between those layers.
Its preferred entry point consumes the complete bounded passive RSD transcript
itself, requires that the strict state machine prove the named BiometricKit
service, and passes the resulting port directly into the plan without exposing
a caller-controlled value. It combines that result with a validated interface
index to build the current link-local endpoint and bounded BridgeXPC HELO plus
read-only method-0 and method-1 frames. It deliberately uses the current
wire-observed T2 address, which agrees with the Catalina address in the legacy
fixed-port runner, and contains no socket API. Its tests also caught and closed
an encoder asymmetry: locally generated HELO strings now obey the same NUL and
byte-length rules as received HELO strings.

`decode-message.py` also contains an offline Intel OOL-registration encoder.
It models control opcodes 2/3 and validates endpoint range, 4 KiB alignment,
the full DMA range's 32-bit page-frame fit, and a well-formed endpoint's
advertised send/receive page limits.

The same module models AppleSEPControl's nonzero byte tags and strict reply
status. The known NOP acknowledgement is fixed to its observed opcode/target.
OOL reply opcode and target remain unobserved, so the reply validator requires
those values as explicit independently verified inputs; there is no permissive
default that could turn an arbitrary endpoint-zero message into registration
success.

The next gated probe collects only passive discovery advertisements emitted
after the validated NOP. It sends no discovery request. Collection is capped
at 64 records and one second, requires endpoint `0xfd` opcode 0/1 records in
KDK order, validates transport flags and uniqueness, and stops on the first
unexpected message. Identity must be immediately followed by limits; endpoint
IDs and printable names are range checked; inverted limits fail; and success
requires `sbio` at `0x08` with ranges covering the recovered 4-page/75-page
buffers. `run-discovery.sh` also requires the exact model/device, an unbound
SEP, two MSI vectors, verified NOP output, module cleanup, and the exact final
`sbio=yes limits=yes result=0` result:

```bash
pkexec ./run-discovery.sh I_UNDERSTAND_PASSIVE_SEP_DISCOVERY
```

The wrapper no longer accepts those conditions through independent grep
matches. It passes only its cursor-bounded journal text to
`verify-discovery-log.py`, an offline verifier that requires one ordered NOP,
contiguous zero-based candidate indices, one matching identity/OOL detail per
candidate, a kernel summary whose counts match an independent replay through
`DiscoveryTable`, usable `sbio`, and one later CPU-stop record. It rejects
failure words, stale/mixed sessions, truncation, reordered or altered details,
zero/missing MSI observations, incomplete PCI restoration/release, and missing
probe removal. Both the NOP and discovery wrappers require a freshly built
module, an exact human confirmation, and a fresh journal cursor; neither can
fall back to older recent log lines.

`run-control-nop.sh` no longer treats a clean module unload as proof that the
NOP succeeded. It feeds only the fresh cursor-bounded lines to
`verify-control-nop-log.py`, which requires the exact `00010100/0/0` response,
no transport error/fatal flags, the kernel's strict-validation record, nonzero
counts on both MSI vectors, stop, PCI restoration/release, and removal in one
ordered device-qualified session. It rejects discovery, OOL registration, or
AKS capability records so a broader probe cannot masquerade as the NOP-only
run.
summary disagreement, and transport-error candidate bits.

The first privileged run was performed after a true cold boot on 2026-08-28.
CPU start succeeded, both MSI vectors fired once, and the control NOP returned
the exact validated acknowledgement in 10 ms. The following one-second passive
window contained zero endpoint advertisements, so the kernel reported
`records=0 identities=0 sbio=no limits=no result=-11`, stopped the CPU, freed
both vectors, restored PCI state, and unloaded. This clean negative result
means OOL capture remains gated off. It also corrects the earlier expectation
that a NOP necessarily triggers discovery: the recovered x86_64 code defines
the `0xfd` receiver but does not show the NOP as a discovery request.

The offline verifier ignores the kernel's module-wide unsigned-module warning
(`module verification failed`) because it occurs before the device probe and
does not describe transport failure. Device-scoped failures and unsuccessful
discovery summaries remain fatal.

The kernel prototype now contains a separate, default-off acknowledgement
capture stage for control opcodes 2 and 3. It is deliberately not exposed by
an automatic runner. Entry requires the complete CPU-start, two-MSI, validated
NOP, and successful passive-discovery chain plus the independent 64-bit
`ool_ack_confirmation` value documented by `modinfo`. Only then does it set a
32-bit coherent DMA mask, allocate the recovered 16 KiB/300 KiB `sbio`
buffers, and send one tagged registration per direction. Each response wait
is capped at five seconds and accepts only endpoint zero, the matching tag,
zero remote status, and no transport error flags; opcode and target are logged
as observations rather than guessed validation constants. On success or any
failure, both mappings remain pinned until the exact CPU-stop write completes,
then are explicitly scrubbed and freed. This path has been compiled and tested
offline but has not been loaded or executed against hardware.

`test_kernel_ool_safety.py` guards the confirmation/discovery gate, bounded
waits, tag/status checks, and stop-before-scrub-before-free ordering.

`verify-ool-log.py` is the corresponding offline journal verifier. Given only
a cursor-bounded capture on standard input, it requires successful `sbio`
discovery, exact ordered opcode-2/3 request words and sizes, raw/decoded field
agreement, endpoint-zero matching tags, zero status and transport flags, then
CPU stop followed by successful cleanup. It outputs the independently observed
reply opcode/target profile consumed by `sbio-bootstrap.py`; it never accesses
the module or hardware.

`sbio-bootstrap.py` composes the independently tested offline pieces into one
ordered state machine. It refuses OOL planning before finalized usable `sbio`
discovery, requires distinct nonzero control tags, requires a caller-supplied
reply opcode/target profile from an independent capture, validates both replies
before committing either mapping, and exposes the exact command-`0x73`/value-3
initialization session only after both directions are owned. It performs no
allocation, DMA, MMIO, or device access.
