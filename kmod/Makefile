# Build the cau_guard out-of-tree module against the running kernel's headers.
#
#   make                 # build cau_guard.ko (needs linux-headers-$(uname -r))
#   make clean
#
# CI installs linux-headers and runs this to prove the module compiles. Loading
# needs root and (for Secure Boot) a signed module; see README.md.

KVERSION ?= $(shell uname -r)
KDIR     ?= /lib/modules/$(KVERSION)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
