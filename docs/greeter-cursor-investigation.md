# Login-screen black-square investigation

September 12, 2026. The dock cleanup patch passed Shawn's first physical
unplug/reconnect test. The login-screen black square remains unresolved.
This follow-up isolates the cursor rendering path without changing the working
power/browser setup, dock patch, or authentication logic.

## Evidence

The phone photo IMG_5772.jpg shows a solid square overlapping the logo and
password entry, rather than a rectangle confined to the text field. Earlier,
Shawn explicitly saw the mouse pointer turn into a square on the Dell and then
recover after crossing monitors. The desktop now uses software cursors; the
separate SDDM greeter does not load that user configuration.

The installed `/usr/share/sddm/themes/omarchy/Main.qml` uses image assets for the
logo, lock and entry border. The password TextInput is transparent and specifies
`cursorDelegate: Item {}`; it does not define a large black caret or overlay.
This supports investigating the pointer path, but source inspection alone
cannot rule out Qt rendering corruption.

[Omarchy issue 4934](https://github.com/basecamp/omarchy/issues/4934) describes
a similar large black hardware cursor on a multi-GPU desktop. Its comments
report software cursors as a workaround. This is corroboration, not proof that
Shawn's login artifact has the same cause.

Aquamarine's multi-GPU cursor code also uses its blit path; it checks the blit's
success but does not use the returned explicit fence there. That is a potential
synchronization question for future driver investigation, not a confirmed bug
or justification to add an untested synchronization patch. The current work
does not modify that code or the previously tested library candidate.

## Scoped mitigation and diagnostic

`tools/graphics/sddm-hybrid.lua` loads the packaged greeter configuration and
sets `cursor.no_hardware_cursors = 1` only for the `t2.graphics=hybrid` boot.
`tools/graphics/99-t2-greeter.conf` points SDDM at that root-owned wrapper.
The installer refuses existing destinations and checks this machine model.
Packaged files, theme assets and authentication configuration are untouched.

This extends the desktop's existing cursor mitigation to the login greeter.
It is explicitly a mitigation/test, not a root-cause repair. If the square
persists while the greeter has confirmed software cursors, the hardware-cursor
hypothesis is weakened and the next investigation should examine Qt rendering.
Do not stack another workaround on top without that evidence.

Hyprland's `--verify-config` reports `config ok` for the complete wrapper plus
packaged configuration. The option is documented in
[Hyprland cursor settings](https://wiki.hypr.land/configuring/core/config-options/#cursor).
SDDM 0.21.0's
[Seat::createDisplay](https://github.com/sddm/sddm/blob/v0.21.0/src/daemon/Seat.cpp)
reloads configuration when creating a display, so the next logout-created
greeter should pick up the override. Confirm its command/config path in the
journal before interpreting a visual test. SDDM is not restarted by the installer.

Acceptance: at a convenient next logout, check for the square and move the
pointer across the entry/logo and both displays. On return, inspect the greeter
startup command to verify `/etc/sddm/hyprland-t2.lua` was loaded. No immediate
logout is required just to install this change. One clean login is encouraging
but does not establish an intermittent fault is eliminated.

Rollback: remove `/etc/sddm.conf.d/99-t2-greeter.conf` and
`/etc/sddm/hyprland-t2.lua`. The next greeter returns to the packaged command.
Neither reboot nor display-manager restart is performed by the installer.

Installation confirmed September 13: both root-owned /etc files were written
on September 12 at 18:13, and the installed Lua matches repository source.
Verification of the installed complete config passes. The latest available
greeter startup is still 18:01 using /usr/share/sddm/hyprland.lua, before the
installation. Thus the mitigation is installed but has not yet been observed
in a new greeter session; no repeat authentication is needed.

Shawn further correlated the earlier pink rectangle with the pointer position
in T3's thread list and the black square with movement onto the external
display. He suspects the square over the login password field is an invisible
or stationary corrupted pointer. This strengthens the cursor hypothesis,
without proving it. The supplied photo is of the Omarchy SDDM login greeter;
the user-session lock screen and pre-login disk-unlock screen are distinct.
Next acceptance: one convenient logout/login with the dock connected, move
the pointer around the password area, and inspect the greeter's startup config
on return. No reboot or additional configuration change is needed.
