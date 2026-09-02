# portfwd - plain make, no autotools, no cmake.
#
#   make                       optimized build
#   make DEBUG=1               -O0 + ASan/UBSan
#   make test                  build and run the unit tests
#   make STD=c2x               for compilers that do not know -std=c23 yet
#   make CC=aarch64-openwrt-linux-musl-gcc    cross build

CC       ?= cc
STD      ?= c23
PREFIX   ?= /usr
SBINDIR  ?= $(PREFIX)/sbin
STRIP    ?= strip

BIN      := portfwd
BUILD    := build

WARNINGS := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes \
            -Wmissing-prototypes -Wwrite-strings -Wformat=2 -Wundef \
            -Wvla

BASE_CFLAGS := -std=$(STD) $(WARNINGS) -D_GNU_SOURCE -MMD -MP

ifeq ($(DEBUG),1)
  OPT_CFLAGS  := -O0 -g3 -fno-omit-frame-pointer \
                 -fsanitize=address,undefined -fno-sanitize-recover=all
  OPT_LDFLAGS := -fsanitize=address,undefined
else
  OPT_CFLAGS  := -O2 -g -ffunction-sections -fdata-sections
  OPT_LDFLAGS := -Wl,--gc-sections
endif

ALL_CFLAGS  := $(BASE_CFLAGS) $(OPT_CFLAGS) $(CFLAGS)
ALL_LDFLAGS := $(OPT_LDFLAGS) $(LDFLAGS)
LIBS        :=

SRCS := src/main.c \
        src/config.c \
        src/addr.c \
        src/log.c \
        src/sig.c \
        src/probe.c \
        src/util/hash.c \
        src/us/us_backend.c

ifeq ($(ENABLE_NFTABLES),1)
  $(error the nftables backend is not implemented yet (milestone M3))
endif

OBJS := $(SRCS:%.c=$(BUILD)/%.o)
DEPS := $(OBJS:.o=.d)

# Unit tests: one binary per tests/t_*.c, linked against the modules it needs.
TEST_SRCS := tests/t_addr.c
TEST_BINS := $(TEST_SRCS:tests/%.c=$(BUILD)/tests/%)
TEST_DEPS := $(BUILD)/src/addr.o $(BUILD)/src/util/hash.o

.PHONY: all clean test tests install strip

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(BUILD)/tests/%: tests/%.c $(TEST_DEPS)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(ALL_LDFLAGS) -o $@ $< $(TEST_DEPS) $(LIBS)

tests: $(TEST_BINS)

test: tests
	@for t in $(TEST_BINS); do \
		echo "== $$t"; \
		$$t || exit 1; \
	done

strip: $(BIN)
	$(STRIP) $(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(SBINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(SBINDIR)/$(BIN)

clean:
	rm -rf $(BUILD) $(BIN)

-include $(DEPS)
