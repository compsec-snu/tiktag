#ifndef FUZZ_H_
#define FUZZ_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
// #include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/uio.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <assert.h>
#include <malloc.h>
#include <sys/stat.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/file.h>
#include <elf.h>
#include <sys/types.h>
#include <inttypes.h>

#include "config.h"
#include "lib/aarch64.h"
#include "lib/mte.h"
#include "lib/scheduler.h"
#include "lib/timer.h"
#define PACKAGE
#define PACKAGE_VERSION
#include <dis-asm.h>

typedef struct {
  char *buffer;
  bool reenter;
} stream_state;

// DECLARATIONS
int disas_sprintf(void*, const char*, ...);
int libopcodes_disassemble(uint32_t, char*, size_t);
unsigned int random_32bit();
void print_registers(struct user_regs_struct *regs);
int util_main(int argc, char *argv[]);
void debug(const char *fmt, ...);
#define CMD_FUZZ 0
#define CMD_UTIL_HEX_TO_BIN 1
#define CMD_UTIL_BIN_TO_HEX 2
#define CMD_UTIL_BIN_TO_ASM 3
#define CMD_UTIL_REPRO 4
#define CMD_UTIL_VERIFY 5

// Fuzzer
#define INPUT "input"
#define QUEUE "queue"
#define OUTPUT "output"
#define LOG "log"
#define SCORE_THRESHOLD 3
#define MUTATE_FILES 10
#define MAX_INPUT_FILES 10
#define REGS_MODE_BENIGN 0
#define REGS_MODE_FAULT 1
#define REGS_MODE_RAND 2


#define CODE_INSTRUCTIONS ((size_t)0x400)
#define CODE_SIZE (CODE_INSTRUCTIONS * sizeof(uint32_t))
#define GADGET_INSTRUCTIONS ((size_t)0x100)
#define GADGET_SIZE (GADGET_INSTRUCTIONS * sizeof(uint32_t))

extern uint64_t *slow_ptr1;
extern uint64_t *slow_ptr2;
extern uint64_t *other_ptr2;
extern uint64_t *target_ptr;
extern uint64_t *wrong_ptr;
extern uint64_t *other_ptr;
extern uint64_t *test_ptr;
extern pid_t slave_pid;
int verify_gadget(uint32_t *insn, size_t code_size, int dbg);
void init_gadget();
int test_gadget(char *, int);
pid_t spawn_slave(int cpu);

// Gadget Test
#define TEST 10
#define ITERATIONS 100
#define HIT_THRESHOLD THRESHOLD
#define DIFF_THRESHOLD 10




#endif // 
