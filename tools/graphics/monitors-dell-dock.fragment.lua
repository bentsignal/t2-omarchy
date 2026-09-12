-- Match monitor identity because dock hotplug changes DP connector numbers.
-- Place the Dell above the internal 3072x1920 panel at 2x scale.
-- 60 Hz is a conservative recovery setting; live activation is not yet verified.
hl.monitor({ output = "desc:Dell Inc. DELL S2721DS 6RW0VY3", mode = "2560x1440@59.95", position = "0x0", scale = 1 })
hl.monitor({ output = "eDP-1", mode = "3072x1920@60", position = "512x1440", scale = 2 })
