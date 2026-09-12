-- Keep the packaged greeter settings; apply only the hybrid cursor mitigation.
dofile('/usr/share/sddm/hyprland.lua')
local cmdline = io.open('/proc/cmdline', 'r')
if cmdline then
  local options = ' ' .. cmdline:read('*a'):gsub('%s+', ' ') .. ' '
  cmdline:close()
  if options:find(' t2.graphics=hybrid ', 1, true) then
    hl.config({ cursor = { no_hardware_cursors = 1 } })
  end
end
