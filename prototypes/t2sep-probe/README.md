# T2 SEP read-only PCI probe

This is milestone zero of the Touch ID bring-up plan. It binds only to Apple
PCI device `106b:1802`, permits `MacBookPro16,1` by default, and reports the
PCI configuration and BAR resources already enumerated by the kernel.

By default it does **not** call `pci_enable_device()`, request or map BARs,
register interrupts, configure DMA, or write PCI/MMIO state. It cannot yet
communicate with the SEP or authenticate a fingerprint.

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
out-of-range chunks. Run both offline suites with:

```bash
python -m unittest test_decode_message.py test_generic_transfer.py \
  test_bridge_protocol.py test_bridge_query.py test_rsd_protocol.py
```

`bridge-protocol.py` models the separate Intel host-to-bridgeOS route recovered
from the x86_64 Catalina biometric daemon. It encodes the verified logical
BridgeXPC method-3 array and the daemon's eight-byte inner BiometricKit header,
plus BridgeXPC's 16-byte socket record header and normal-message binary plist.
It validates integer widths, both magic values, types, arity, and
caller-supplied size limits. It refuses to guess the private `BTNil`
serialization and does not connect to BridgeXPC, USB, PCI, or SEP.

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
verified against the newer bridgeOS installed on this machine.

`rsd-protocol.py` models the newer `remoted` directory route as an offline
candidate only. Independent implementations agree on HTTP/2 plus RemoteXPC
framing and candidate RSD port `58783`; the local encoder has been checked
byte-for-byte against one of them. The module can encode the passive directory
handshake and strictly decode a named advertised service port, but contains no
socket calls. Port `58783` and the presence of `com.apple.eos.BiometricKit`
remain unverified for this T2 bridgeOS, so this codec is not wired into
`bridge-query.py` and does not weaken its hard live gate.

`decode-message.py` also contains an offline Intel OOL-registration encoder.
It models control opcodes 2/3 and validates endpoint range, 4 KiB alignment,
32-bit page-frame fit, and the endpoint's advertised send/receive page limits.
Nothing calls the encoder from the kernel module; it cannot allocate or
register DMA memory.

The next gated probe collects only passive discovery advertisements emitted
after the validated NOP. It sends no discovery request. Collection is capped
at 64 records and one second, requires endpoint `0xfd` opcode 0/1 records in
KDK order, validates transport flags and uniqueness, and stops on the first
unexpected message. `run-discovery.sh` also requires the exact model/device,
an unbound SEP, two MSI vectors, verified NOP output, module cleanup, and a
clean collector result:

```bash
pkexec ./run-discovery.sh
```

Build and review this runner without executing it until a privileged hardware
test is explicitly intended.
