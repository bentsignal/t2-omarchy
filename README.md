# MacBookPro16,1 T2 Linux setup notes

Practical, tested notes and recovery tools for Shawn's 2019 16-inch Intel
MacBook Pro (`MacBookPro16,1`) running Omarchy/Arch Linux with `linux-t2`.

The repository began as a reproducible internal-speaker setup. It now also
records model-specific power-management findings, including how to choose
between AMD performance mode and an Intel-only battery mode at boot.

## Guides

- [Power management and dual boot modes](docs/power-management.md)
- [Touch ID / T2 Secure Enclave research](docs/touch-id.md)
- [Touch ID cold-boot checkpoint](docs/touch-id-cold-boot.md)
- [macOS 26.6.2 Touch ID capture findings](docs/macos-touch-id-findings.md)
- [macOS Codex handoff for Touch ID capture](docs/macos-touch-id-handoff.md)
- [Backup and temporary macOS dual boot](docs/macos-dual-boot.md)
- [Audio recovery](#audio-recovery)

## Power-management summary

The reliable solution on this model is two boot entries:

- **AMD/default:** full Radeon performance for games and GPU-heavy work, with
  substantially higher idle draw.
- **Intel battery:** boot with `apple_gmux.force_igd=1`, then power off the AMD
  GPU with `vgaswitcheroo`. This machine measured about **16 W** at a controlled
  screen-on baseline versus roughly **33--37 W** before the change.

Live switching without rebooting is not recommended on this hardware. The
internal panel changes ownership through Apple's gmux, the current AMD driver
reports that runtime PM is unavailable, and applications may retain DRM
clients. A reboot into the desired entry is slower but predictable and leaves
the normal AMD entry available as recovery if Intel display initialization
fails.

## Audio recovery

This profile provides measured six-speaker FIR correction, virtual bass,
gentle compression, peak limiting, and pause/resume zero-ramping. It also hides
the unsafe raw speaker sink and prevents idle suspension pops.

## Install

Prerequisites: a working T2 kernel/audio driver, internet access, `yay`, and
interactive `sudo` access.

```bash
git clone https://github.com/bentsignal/t2-mbp16-audio-recovery.git
cd t2-mbp16-audio-recovery
./install.sh
./verify.sh
```

The installer refuses to run on any model except `MacBookPro16,1`. It installs
the required Arch/AUR plugins, downloads the upstream measurement assets from a
pinned commit, backs up any existing profile, installs this tuned graph, and
selects the protected DSP sink at 50% volume.

Never select or route audio directly to `Raw Speaker Device`; doing so bypasses
the DSP protection and can damage the speakers.

## Tuning in this snapshot

- Model-specific tweeter and woofer FIRs from `t2-apple-audio-dsp`
- Bankstown virtual bass unchanged from upstream
- Compressor softened from 3:1 to 1.5:1
- Compressor makeup gain reduced from 4 dB to 1 dB
- Attack/release changed to 35/350 ms
- PipeWire idle suspension disabled for the internal DSP path
- 5 ms stereo zero-ramp added for pause/resume transitions
- SWH fast lookahead limiter retained at -1 dB

## Undo

```bash
./uninstall.sh
```

Backups are kept under `~/.local/state/t2-mbp16-audio-recovery/backups/`.

## Provenance

The installer downloads FIRs and the force-unmute helper from
[lemmyg/t2-apple-audio-dsp](https://github.com/lemmyg/t2-apple-audio-dsp),
pinned to commit `b5c5a1368f4eed5e1339a913a5c2d813374dd1c1`. Those upstream
assets are not duplicated in this repository.
