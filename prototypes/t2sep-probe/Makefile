obj-m += t2sep_probe.o

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all clean flags-probe

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

flags-probe: t2ncm-flags-probe

t2ncm-flags-probe: t2ncm-flags-probe.c
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) t2ncm-flags-probe
