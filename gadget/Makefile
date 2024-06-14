# Toolchain setup
CC = clang
AR = aarch64-none-linux-gnu-ar
LD = aarch64-none-linux-gnu-ld 

# gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/aarch64-none-linux-gnu/libc 
SYSROOT = ${GCC_TOOLCHAIN}/aarch64-none-linux-gnu/libc
# Compilation and linking flags
CFLAGS = --target=aarch64-linux-gnu -march=armv8a+memtag+pauth -std=gnu99 -O2 -Wall -Wextra -I./ --sysroot=$(SYSROOT) -DTIMER=$(TIMER)
LDFLAGS = -lpthread -lm -fuse-ld=lld -static --gcc-toolchain=$(GCC_TOOLCHAIN) -L$(GCC_TOOLCHAIN)/aarch64-none-linux-gnu/libc/lib/aarch64-linux-gnu/

# Source files and objects
SHARED_OBJECTS = lib/mte.o lib/perf_counters.o lib/scheduler.o lib/timer.o

SRCS = poc.c
OBJS = $(SRCS:.c=.o)

# All target
all: poc

# Build rules

$(SHARED_OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

poc: poc.o $(SHARED_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) poc.o $(SHARED_OBJECTS) -o $@

clean:
	rm -f poc $(OBJS) $(SHARED_OBJECTS) *.o

