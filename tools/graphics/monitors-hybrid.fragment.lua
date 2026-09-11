-- The Intel-primary T2 topology exposes a nonexistent AMD internal panel.
local t2_cmdline = io.open("/proc/cmdline", "r")
if t2_cmdline then
  local boot_options = " " .. t2_cmdline:read("*a"):gsub("%s+", " ") .. " "
  t2_cmdline:close()
  if boot_options:find(" t2.graphics=hybrid ", 1, true) then
    hl.monitor({ output = "eDP-2", disabled = true })
  end
end
