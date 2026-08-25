# MacBookPro16,1 T2 Linux audio recovery

Reproduces the tuned internal-speaker setup from Shawn's 2019 16-inch Intel
MacBook Pro (`MacBookPro16,1`) running Omarchy/Arch Linux with `linux-t2`.

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

