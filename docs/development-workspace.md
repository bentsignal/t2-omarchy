# One project workspace

Open `/home/shawn/dev/t2-omarchy` in an editor or AI coding product. That folder
is the Git root for `https://github.com/bentsignal/t2-omarchy.git`. There is no
requirement to launch a CLI from `/home/shawn` or to open all of `~/dev`.

```text
~/dev/t2-omarchy/
  AGENTS.md                 project-wide guidance for coding assistants
  README.md
  docs/                     findings, current roadmap, cross-OS handoffs
  tools/                    our implementation and tests
  prototypes/               our reverse-engineering prototypes
  .local/                   ignored, machine-local support; NEVER upload
    references/             upstream source checkouts, separate Git histories
    research/               Apple images/extractions and private captures
```

The old `~/t2-mbp16-audio-recovery` compatibility symlink was removed at Shawn's
request after verifying its target. No project data was deleted. Use the
canonical folder above; old commands using the home-directory path need updating.
Old notes retain their original paths as
historical evidence; translate `~/dev/<reference>` to
`<project>/.local/references/<reference>` and `~/dev/t2-touchid-research` to
`<project>/.local/research` before reusing a research command.

## Start here

Latest September 11 state: the user completed shutdown and updated to kernel
7.2.4. Its missing custom SEP module has been rebuilt and registered with DKMS.
The original mailbox timeout still blocks fprintd. Start with
[the current repair/diagnostic checkpoint](touch-id-sep-dkms.md); do not repeat
an already-completed shutdown or initiate a fingerprint/sleep test yet.

September 11: fprintd is blocked by SEP mailbox startup timeouts, independently
reproduced by a read-only capability query. See [current recovery checkpoint](touch-id-sep-startup-timeout.md)
before starting any sleep or fingerprint test. A supervised shutdown/power-on
is pending; no live reset was attempted.

Current work: [Touch ID roadmap](touch-id-roadmap.md). At the September 6
workspace cleanup checkpoint, working macOS-enrolled-finger authentication is
retained. Latest measured resume-to-ready was 4.982 seconds (previous 8.382 and 5.240). The
pre-sleep UI preparation passed Shawn’s visual check. The 19:04 control failed
on a cleanup regression; its single-cancel correction is deployed and awaits
acceptance (see `touch-id-client-disconnect.md`). **Do not start a sleep or finger test
without Shawn ready.** Native Linux enrollment remains outstanding; Touch Bar
work is deferred. See [UI checkpoint](touch-id-readiness-ui.md) and
[latency evidence](touch-id-prearm-latency.md).

This is one dual-boot physical Mac, not two concurrently accessible machines.
The macOS and Linux threads are separate and exchange committed, pushed
handoffs through this repository. Rebooting ends access to the current OS.
Read the latest applicable handoff and Git history before requesting a switch;
do not assume another agent's uncommitted state is visible.

## Why there are supporting checkouts

These are dependencies/reference implementations used for APFS access, image
extraction, Apple protocols, kernel research, and Touch ID comparison—not
additional repositories where our project code should be developed. The three
`t2-touchid-*` source views have different pinned revisions; two are linked Git
worktrees. They are not interchangeable duplicates.

The main project was approximately 25 MB at cleanup; Apple research artifacts
were approximately 117 GB. `.local/` is ignored by Git, and VS Code-compatible
search/watch exclusions prevent indexing the large support tree. Other editors
must also respect `.gitignore` or explicitly exclude `.local/`. An ignore file
is not a security sandbox: never send private captures to an external service
or use `git add -f` to bypass these exclusions.

Research code that requires a local source pin must fail rather than silently
substitute another revision. In particular, the enrollment overlay now resolves
`.local/references/t2-touchid-linux-latest` relative to this repository, preserving
its commit and file-hash checks. On a fresh clone, that external source is not
automatically downloaded. See [local inventory](local-support-inventory.md).

Some archived build outputs can contain old absolute paths. Their source/data
is preserved, but they may require rebuilding at the new location before reuse.
Do not rewrite upstream sources or treat archived vendor installers as our code.

## Installed runtime is separate, deliberately

The working service uses root-owned installed code under `/opt/t2-touchid` and
`/usr/local/libexec`, units under `/etc/systemd` and user systemd configuration,
and private state under `/var/lib/t2-touchid` and `/run/t2-touchid*`. These are
not removed or relocated during workspace cleanup. Never collect credentials,
keybags, calibration payloads, or biometric state into a public Git repository.

Moving a development checkout does not reinstall the fingerprint service. To
change an installed overlay, edit the repo source, test, deliberately deploy
the named file, and verify it as described in its feature document. The top-level
`install.sh` is the speaker/audio installer, not a complete Touch ID installer.

## Verification without a finger or reboot

From this repository:

```bash
git status --short
tools/research/run-bounded.sh python -m unittest discover -s tools/research -p 'test_*.py'
systemctl is-active fprintd.service
```

Some research tests require the local reference checkout and some runtime
integration tests require the installed `/opt/t2-touchid/.venv` environment.
Do not invoke backup, enrollment, reset, or disk-layout scripts merely as a
workspace smoke test.

Cleanup preserves data; it does not claim 117 GB is all needed. Large extracted
installers are candidates for a separate, backed-up deletion review. Keep
unique captures, local source changes, provenance, and required pinned binaries
until their replacement or recovery path is established.
