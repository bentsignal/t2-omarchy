# Local support inventory — September 6, 2026

These directories were preserved during workspace consolidation, not deleted
or merged into our Git history. Paths below are relative to `.local/references/`.
Source edits that predated cleanup remain uncommitted in their original upstream
checkouts; preserve them. Cleanup only relocates directories and repairs linked
Git worktree administrative paths.

| Directory | Upstream / pinned HEAD | Existing local state |
|---|---|---|
| `apfs-fuse` | sgan81/apfs-fuse, `66b86bd` | Modified `ApfsContainer.cpp`, `PList.h`; preserve |
| `apfsprogs` | linux-apfs/apfsprogs, `3721463` | Clean tracked state |
| `dmg2img` | Lekensteyn/dmg2img, `a3e4134` | Clean tracked state |
| `gibMacOS` | corpnewt/gibMacOS, `bf8f2ab` | Untracked product cache; preserve |
| `go-ios` | danielpaulus/go-ios, `ced7e53` | Clean tracked state |
| `hfsfuse` | 0x09/hfsfuse, `055147b` | Clean tracked state |
| `ipsw-bin` | Downloaded ipsw executable/archive | Not a Git checkout; preserve |
| `ipsw-src` | blacktop/ipsw, `cd24c18` | Untracked `cmd/yaaextract/`; preserve |
| `pymobiledevice3` | doronz88/pymobiledevice3, `a6bd794` | Clean tracked state |
| `t2-touchid-linux` | jmurth1234/t2-touchid-linux, `a3c0f11` | Modified `src/t2_acm_protocol.py`; owns linked worktrees |
| `t2-touchid-linux-latest` | same upstream, `826a86e` | Linked worktree; pinned enrollment overlay dependency |
| `t2-touchid-upstream-current` | same upstream, `624bebe` | Linked worktree, detached HEAD |
| `tools` | 7zip, acpica, ipsw, PBZX utilities | Mixed downloaded/built tools; preserve |
| `upstream-pongoos` | checkra1n/PongoOS, `4c9b754` | Clean tracked state |
| `upstream-t2bce` | deqrocks/t2bce, `a973d53` | Clean tracked state; kernel reference only |
| `xnu` | apple-oss-distributions/xnu, `f6217f8` | Clean tracked state |

"Clean tracked state" does not mean no ignored binaries/build outputs. Whole
directories are retained. Existing build files may embed prior paths and can
require rebuilding before reuse.

`.local/research/` was formerly `~/dev/t2-touchid-research`. Approximate sizes:

| Material | Size | Cleanup decision |
|---|---:|---|
| Catalina `apple-installer-19H15` | 44 GB | Keep pending separate deletion review |
| Sonoma `apple-installer-23J631` | 66 GB | Keep pending separate deletion review |
| KDK `kdk-23F79` | 6.7 GB | Preserve analysis and symbols |
| bridgeOS `bridgeos-23P6068` | 1.6 GB | Preserve version-specific reverse-engineering evidence |
| `apple-t2-xpc-duo` | <1 MB | duo-labs/apple-t2-xpc reference checkout; clean |
| `private-captures`, DSDT files, helper | <1 MB | Preserve; do not upload capture contents |

The unrelated `~/dev/lakecraft`, `~/dev/omarchy`, and `~/dev/voice-dictation`
projects were left alone. The working installed T2 runtime was not relocated.
No files were deleted and no space reclamation is claimed by this reorganization.

Verification: all 17 moved directory device/inode identities were unchanged.
For each top-level reference Git checkout, HEAD, porcelain status, and the hash
of its tracked diff matched before/after relocation. Both Touch ID linked
worktrees were repaired and recognized at their new paths; the APFS submodule
still resolves correctly. The research suite ran 193 tests with two expected
environment skips, and all 26 installed-runtime overlay tests passed. Both
modified backup wrappers passed shell syntax checks without execution.
`fprintd.service` and the pre-sleep UI monitor remained active; no biometric
test, service restart, sleep, or device reset was needed for the cleanup.

Recovery from this reorganization is a directory move back to the old names,
followed by `git worktree repair` on the Touch ID reference repository if its
linked worktrees move again. The temporary home-directory project symlink was
subsequently removed at Shawn's request; the canonical repo and all support
material remain intact. Do not overwrite an existing directory while undoing.
