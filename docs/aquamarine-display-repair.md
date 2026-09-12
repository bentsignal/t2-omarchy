# Aquamarine display cleanup repair candidate

September 12, 2026. This investigation found a concrete library defect matching
Shawn's logout crashes and a separate cleanup failure matching the dock logs.
A patched package has been built, tested offline and installed. Physical hotplug and
login-screen artifact acceptance remain pending. The working Intel desktop,
normal-profile AMD browser launcher and power policy are preserved.

## Evidence and attribution

Aquamarine upgraded from 0.14.0-2 to 0.15.0-2 at 09:35:53 on September 11.
Hyprland and Mesa also updated that morning. Changing the renderer topology
exposed these failures; it does not establish that every symptom was caused by
our settings or by the package update alone.

The 11:51 and 16:51 logout records both show SIGSEGV in
`CDRMBackend::flushAsyncCommitEvents`, followed by `cancelAsyncOutput`,
`SDRMConnector::disconnect`, backend destruction and process exit. The greeter
also crashes with the same stack (UID 962). This exactly matches
[upstream issue 383](https://github.com/hyprwm/aquamarine/issues/383): cleanup
clears a connector slot, then a subsequent event flush dereferences that slot.
The candidate adds the missing null guard. No deliberate crash reproduction
was needed; existing symbolic core records and source establish the match.

The recorded dock log contains two `Cannot commit a disconnected output`
rejections during connector removal. Later, the Dell remains connected but
kernel-disabled even though Hyprland retains its resolution. Reload and the
phantom-panel experiment did not repair it; logout/login did. In 0.15.0,
`disconnect()` marks the connector disconnected and releases scanout buffer
references before notifying the compositor. Subsequent disable requests are
rejected by two connected-state checks. That is a concrete cleanup gap.

[Upstream PR 399](https://github.com/hyprwm/aquamarine/pull/399) moves buffer
release after the destroy notification and permits explicit disable commits
for disconnected outputs, while still rejecting rendering or enabling them.
Its author reports a hotplug recovery benefit. The PR was automatically closed
by the contributor-vouch gate, not after a recorded technical rejection. It
remains unmerged and is a candidate for this machine, not an upstream release.

Other proposals were reviewed but not included:
[PR 395](https://github.com/hyprwm/aquamarine/pull/395) directly disables KMS in
the backend; [PR 397](https://github.com/hyprwm/aquamarine/pull/397) changes
page-flip events, multi-GPU fences and implicit modifiers. Combining all three
would obscure which change fixes hotplug. The present candidate is limited to
the null guard and PR 399's cleanup ordering/disable permission.

## Login-screen square remains a separate acceptance item

SDDM uses `start-hyprland -- --config /usr/share/sddm/hyprland.lua`, according
to `/etc/sddm.conf.d/10-wayland.conf`. The packaged greeter config is minimal
and does not load Shawn's desktop cursor workaround. Both greeter and desktop
use Aquamarine, so a library repair reaches both. However, a teardown crash does
not prove the cause of an artifact drawn before teardown. Neither the black
square nor its resolution is explained conclusively by this patch. No greeter
settings were changed and no additional cursor workaround was installed.

## Reproducible candidate

Source and patches live in `tools/graphics/aquamarine/`:

- `PKGBUILD`: upstream v0.15.0, local package release 2.1, SONAME 14 retained.
- `0001-null-connector-on-exit.patch`: issue 383's null guard.
- `0002-disconnected-output-disable.patch`: upstream commit
  `e69f71c744d979de51a8dda7775ba6700e09505c` (PR 399).

The tarball and both patches have pinned SHA-256 values in PKGBUILD. Source
verification passed and patches applied with zero fuzz. Builds use disposable
extracted source under /tmp, not an external Git checkout or project reference.
No upstream repository was modified or published to.

To rebuild, copy the recipe and patches into an empty build directory and run
`makepkg`. The actual candidate reused the already-configured source/build via
`makepkg --noextract` after source verification; build and check stages ran.

Validation:

- CMake/C++ build completed against installed dependencies.
- Upstream `attachments`, `output`, and `commitThread` tests: 3/3 passed.
- `simpleWindow` is an interactive backend demo and was not run.
- Dynamic relocation check of installed Hyprland against the candidate library
  reported no unresolved symbols. One incidental standard-library export
  differs (`std::ranges::any_of`); no Aquamarine export was removed.
- Package is recognized by pacman as aquamarine 0.15.0-2.1 with SONAME 14.

Artifact:
`/tmp/t2-aquamarine-review/package/aquamarine-0.15.0-2.1-x86_64.pkg.tar.zst`

SHA-256:
`def1a1959f702c0a421d8a58f4cadbe6fcd68bb76e8a02819d20bcf4a950e168`

## Activation and rollback

Installed successfully through pacman as aquamarine 0.15.0-2.1, keeping
package ownership and normal upgrade behavior. Pacman reports 38 files and
none missing. Installed library SHA-256 matches the packaged library:
`615c937692dd6b2cf7897e714efb86fd67449857bf5ae816f2f1a77bd0626c60`.
Candidate build ID: `f6c07bc4372a1f826599652c82c8010fdda61afe`.
The current compositor PID 1183663 still maps the old, now-unlinked library;
Hyprland config validation remains clean. The current compositor keeps the old mapped library until
exit. Do not claim hardware repair based on installing the file. The next
user-initiated logout/login activates the candidate for new compositor
processes; the old outgoing session may still exhibit its old teardown crash.
Do not restart SDDM or force a logout while Shawn has active work.

Rollback uses the existing signed stock package:

```sh
sudo pacman -U /var/cache/pacman/pkg/aquamarine-0.15.0-2-x86_64.pkg.tar.zst
```

Then log out/in when ready. No package pin or IgnorePkg rule is added. Future
updates can supersede this local candidate; check whether the fixes are included
rather than blindly keeping or removing a pin.

## Acceptance sequence

1. Confirm the new session maps the candidate library/build ID.
2. Confirm the Dell is visibly active and kernel-enabled after login.
3. Unplug/reconnect the dock with the same session running; confirm the Dell
   returns without logout, and inspect logs for disable/commit failures.
4. Check the next exit of a patched compositor for the previously repeated
   teardown crash. Distinguish old-process crashes from new-build failures.
5. Record whether the intermittent black square recurs; one clean crossing or
   login does not prove it is fixed.
6. Recheck normal-browser gaming and unplugged browsing power for regressions.
