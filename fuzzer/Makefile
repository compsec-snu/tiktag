# Tools setup
CC = clang
AR = aarch64-none-linux-gnu-ar
LD = aarch64-none-linux-gnu-ld 

# Toolchain and sysroot setup
SYSROOT=$(GCC_TOOLCHAIN)/aarch64-none-linux-gnu/libc

# Compilation and linking flags
CFLAGS = --target=aarch64-linux-gnu -march=armv8a+memtag+pauth -std=gnu99 -O2 -Wall -Wextra -I./ -Iinclude -Ibinutils/include --sysroot=$(SYSROOT) -g -DPMU
LDFLAGS = -lpthread -lm -fuse-ld=lld -static --gcc-toolchain=$(GCC_TOOLCHAIN) -L$(GCC_TOOLCHAIN)/aarch64-none-linux-gnu/libc/lib/aarch64-linux-gnu/

# Source files and objects
SHARED_OBJECTS = lib/mte.o lib/scheduler.o lib/timer.o

SRCS = mte-fuzz.c fuzz-utils.c mutate.c
SRCS += $(wildcard binutils/opcodes/*.c)

OBJS = $(SRCS:.c=.o)

# All target
all: mte-fuzz

# Build rules
mte-fuzz: $(SHARED_OBJECTS) $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SHARED_OBJECTS) $(OBJS) -o $@

# Pattern rule for binutils object files
binutils/opcodes/%.o: binutils/opcodes/%.c
	$(CC) --target=aarch64-linux-gnu --sysroot=$(SYSROOT) -march=armv8-a -std=gnu11 -w -O2 -Ibinutils/include \
		  -DHAVE_STRING_H -DARCH_arm -DARCH_aarch64 -c $< -o $@

$(SHARED_OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f mte-fuzz $(OBJS) $(SHARED_OBJECTS) binutils/opcodes/*.o

.PHONY: all clean
