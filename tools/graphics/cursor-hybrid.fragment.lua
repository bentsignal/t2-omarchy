-- Work around transient black-square cursors across Intel/AMD displays.
-- This is a mitigation pending visual confirmation, not a driver repair.
local t2_cursor_cmdline = io.open("/proc/cmdline", "r")
if t2_cursor_cmdline then
  local options = " " .. t2_cursor_cmdline:read("*a"):gsub("%s+", " ") .. " "
  t2_cursor_cmdline:close()
  if options:find(" t2.graphics=hybrid ", 1, true) then
    hl.config({ cursor = { no_hardware_cursors = 1 } })
  end
end
