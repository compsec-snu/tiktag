#define _GNU_SOURCE


#include "mte-fuzz.h"


#include "mutate.h"


#include "filter.h"
#include "logging.h"
#include "reg_const.h"
#include "util.h"
#include <dirent.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

__attribute__((noinline))
void* map_and_zero(size_t size, bool tagged) {
  int prot = PROT_READ|PROT_WRITE;
  if (tagged) {
    prot |= PROT_MTE;
  }
  uint64_t* ptr = (uint64_t*)mmap(NULL, size, prot,
    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (tagged) {
    ptr = mte_tag_and_zero(ptr, size);
  } else {
    memset(ptr, 0, size);
  }
  return ptr;
}


uint64_t *slow_ptr1;
uint64_t *slow_ptr2;
uint64_t *other_ptr2;
uint64_t *target_ptr;
uint64_t *wrong_ptr;
uint64_t *other_ptr;
uint64_t *test_ptr;
int probe_idx = -1;

pid_t slave_pid = 0;

uint32_t mutate_counter[MAX_INPUT_FILES] = {0};
uint32_t exec_counter[MAX_INPUT_FILES] = {0};
char input_names[MAX_INPUT_FILES][100] = {0};
int num_input_files = 0;
int num_output_files = 0;

#define CODE_INSTRUCTIONS ((size_t)0x400)
#define CODE_SIZE (CODE_INSTRUCTIONS * sizeof(uint32_t))
#define GADGET_INSTRUCTIONS ((size_t)0x100)
#define GADGET_SIZE (GADGET_INSTRUCTIONS * sizeof(uint32_t))

__attribute__((aligned(0x1000)))
uint32_t test_code[CODE_INSTRUCTIONS];
__attribute__((aligned(0x1000)))
uint32_t verify_code[CODE_INSTRUCTIONS];

typedef void (*function0)(void);
typedef uint64_t (*function4)(void*, void*, void*, void*);
typedef uint64_t (*function5)(void*, void*, void*, void*, void*);
typedef uint64_t (*function6)(void*, void*, void*, void*, void*, void*);
const function6 test_function = (function6)(test_code);
const function0 verify_function = (void(*)(void))(verify_code);
uint32_t* code_ptr;

__attribute__((noinline))
void code_start(uint32_t nop_instruction, uint32_t *code) {
  mprotect(code, CODE_SIZE, PROT_READ|PROT_WRITE);
  for (size_t i = 0; i < CODE_INSTRUCTIONS; ++i) {
    code[i] = nop_instruction;
  }
  code_ptr = code;
}

__attribute__((noinline))
void code_emit(uint32_t instruction) {
  *code_ptr = instruction;
  code_ptr += 1;
}

__attribute__((noinline))
void code_skip(size_t count) {
  code_ptr += count;
}

__attribute__((noinline))
void code_finish(uint32_t *code) {
  mprotect(code, CODE_SIZE, PROT_READ|PROT_EXEC);
  flush_instruction_cache(code, CODE_SIZE);
}

const uint32_t cbz_x0_100   = 0xb4002000;
const uint32_t ldr_x0_x0    = 0xf9400000;
const uint32_t ret          = 0xd65f03c0;
const uint32_t isb          = 0xd5033fdf;
const uint32_t nop          = 0xd503201f;
const uint32_t breakpoint   = 0xd4200000;
const uint32_t b_minus_102  = 0x17fffefe;

int get_max_freq(int cpu) {
  char path[100];
  sprintf(path, "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    printf("Error: %s\n", strerror(errno));
    return -1;
  }
  int max_freq;
  fscanf(fp, "%d", &max_freq);
  fclose(fp);
  return max_freq;
}
int get_cur_freq(int cpu) {
  char path[100];
  sprintf(path, "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_cur_freq", cpu);
  FILE *fp = fopen(path, "r");
  if (fp == NULL) {
    printf("Error: %s\n", strerror(errno));
    return -1;
  }
  int max_freq;
  fscanf(fp, "%d", &max_freq);
  fclose(fp);
  return max_freq;
}

// 32bit random instruction generation
unsigned int random_32bit() {
    unsigned int high = (unsigned int) rand() & 0xFFFF;
    unsigned int low = (unsigned int) rand() & 0xFFFF;
    return (high << 16) | low;
}

__attribute__((noinline)) 
void slave_loop(void)
{
    asm volatile(
            "1:         \n"
            "   brk #0  \n"
            "   nop     \n"
            "   b 1b    \n"
            );

}

pid_t spawn_slave(int cpu)
{
    pid_t slave_pid = fork();
    if (slave_pid == 0) {
        cpu_pin_to(cpu);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        mte_enable(true, DEFAULT_TAG_MASK);
        set_max_priority();
        // debug("Slave pinned to CPU %d\n", cpu);

        // slave_loop();

        verify_function();
    }
    int status;
    waitpid(slave_pid, &status, 0);
    return slave_pid;
}

int custom_ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
    struct iovec iovec = { regs, sizeof(*regs) };
    int val = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iovec);
    assert(val != -1);
    return val;
}

int custom_ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
    struct iovec iovec = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iovec);
}

int custom_ptrace_getvfpregs(pid_t pid, struct USER_VFPREGS_TYPE *regs)
{
    struct iovec iovec = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iovec);
}

int custom_ptrace_setvfpregs(pid_t pid, struct USER_VFPREGS_TYPE *regs)
{
    struct iovec iovec = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRFPREG, &iovec);
}

#define DISTANCE 128

void initialize_mem() {
  memset(slow_ptr1, 0, ENTRY_SIZE);
  memset(slow_ptr2, 0, ENTRY_SIZE);
  memset(other_ptr2, 0, ENTRY_SIZE);
  memset(target_ptr, 0, ENTRY_SIZE);
  memset(other_ptr, 0, ENTRY_SIZE);
  memset(test_ptr, 0, ENTRY_SIZE * 4);
  memcpy(test_ptr, random_memory, sizeof(random_memory));
}

int run_gadget(uint64_t *slow_ptr, uint64_t *target_ptr, uint64_t *test_ptr, 
               uint64_t *other_ptr, uint64_t *probe_ptr, int dbg) {
  uint64_t mask = 0x0f00000000000000;
  uint64_t latency = 0; 
  uint64_t correct_tag = ((uint64_t)target_ptr & mask) >> 56;
  uintptr_t stripped_ptr = (uint64_t)target_ptr & ~mask;
  uint64_t wrong_tag = correct_tag ^ 0xf;
  uint64_t hit[2] = {0};
  uint64_t lats[2] = {0};
  uint64_t res=0;
  uint64_t tag;

  for (int is_correct = 1; is_correct >=0; is_correct--) {
  for (uint64_t i = 0; i < ITERATIONS; ++i) {
      for (uint64_t j = 0; j < BRANCH_PREDICTOR_ITERATIONS; ++j) {
        #ifdef FUZZ_STORE
          // Invalidate memory changes caused by store instructions during each gadget execution
          initialize_mem();
        #endif
        
        uint64_t is_warmup = ((j + 1) ^ BRANCH_PREDICTOR_ITERATIONS) != 0;
        tag = !is_correct * wrong_tag + is_correct * correct_tag;
        uintptr_t guess_tag = is_warmup * correct_tag + !is_warmup * tag;
        uint64_t *guess_ptr = (uint64_t*)(stripped_ptr | (guess_tag << 56));
        
        *slow_ptr = is_warmup;

        asm volatile (
          "ldr xzr, [%0]\n\t"
          : :"r"(target_ptr)
          :
        );

        local_memory_barrier();
        instruction_barrier();
        flush_data_cache((char*)probe_ptr); // TODO: flush more blocks?
        flush_data_cache(slow_ptr);
        local_memory_barrier();
        instruction_barrier();

        /*
          Only x0 ~ x5 are initialized for each purpose to find gadgets faster
        */ 
        res += test_function ((char*)slow_ptr, guess_ptr, test_ptr, 
                              /* x3 */ other_ptr, 
                              /* x4 */ test_ptr , 
                              /* x5 */(void*)0);
      }

      latency = read_latency((char*)probe_ptr);
      if (latency <= HIT_THRESHOLD)
        hit[is_correct]++;
      lats[is_correct] += latency;
    } // tag
  } // iterations

  instruction_barrier();

  int diff = 0;
  if (hit[1] > hit[0])
    diff = (hit[1]-hit[0])*100/ITERATIONS;
  else
    diff = (hit[0]-hit[1])*100/ITERATIONS * (-1);

  // debug("Correct: %d, Wrong: %d, Diff: %d\n", 
  //         hit[1]*100/ITERATIONS, hit[0]*100/ITERATIONS, diff);
  // debug("Correct: %ld, Wrong: %ld\n", lats[1]/ITERATIONS, lats[0]/ITERATIONS);
  return diff;
}


void execute_insn_slave(pid_t *slave_pid_ptr, uint8_t *insn_bytes,
                        size_t insn_length, int regs_mode,
                        execution_result *result)
{
    int status;

    pid_t slave_pid = *slave_pid_ptr;

    struct USER_REGS_TYPE regs;
    if (custom_ptrace_getregs(slave_pid, &regs) == -1) {
        perror("getregs failed");
    }

    // initialize slave's memorys using POKEDATA
    for (int i = 0; i < ENTRY_SIZE / 8; i++) {
      if (ptrace(PTRACE_POKEDATA, slave_pid, &slow_ptr1[i], slow_ptr1[i]) == -1)
        perror("PTRACE_POKEDATA failed");
      if (ptrace(PTRACE_POKEDATA, slave_pid, &slow_ptr2[i], slow_ptr2[i]) == -1)
        perror("PTRACE_POKEDATA failed");
      if (ptrace(PTRACE_POKEDATA, slave_pid, &other_ptr2[i], other_ptr2[i]) == -1)
        perror("PTRACE_POKEDATA failed");
      if (ptrace(PTRACE_POKEDATA, slave_pid, &target_ptr[i], target_ptr[i]) == -1)
        perror("PTRACE_POKEDATA failed");
      if (ptrace(PTRACE_POKEDATA, slave_pid, &other_ptr[i], other_ptr[i]) == -1)
        perror("PTRACE_POKEDATA failed");
    }

    for (int i = 0; i < SBX_SIZE / 8; i++) {
      if (ptrace(PTRACE_POKEDATA, slave_pid, &test_ptr[i], test_ptr[i]) == -1)
        perror("PTRACE_POKEDATA failed");
    }

    static uint64_t insn_loc = 0;
    uint64_t *pc_reg = &regs.pc;
    uint64_t insn_loc_iter;

    if (insn_loc == 0) {
        insn_loc = *pc_reg + 8;
    }
    insn_loc_iter = insn_loc;

    for (size_t i=0; i < GADGET_INSTRUCTIONS; i+=2) {
      uint64_t insn;
      uint64_t next_insn;

      if (i >= insn_length) {
        insn = (uint64_t)nop;
        next_insn = (uint64_t)nop;
      } else {
        insn = insn_bytes[i*4+0]
              | (insn_bytes[i*4+1] << 8)
              | (insn_bytes[i*4+2] << 16)
              | (insn_bytes[i*4+3] << 24);
        if (i == insn_length-1) {
          next_insn = (uint64_t)nop;
        } else {
          next_insn = insn_bytes[(i+1)*4+0]
                    | (insn_bytes[(i+1)*4+1] << 8)
                    | (insn_bytes[(i+1)*4+2] << 16)
                    | (insn_bytes[(i+1)*4+3] << 24);
        }
      }
      
      // /*
      // * PTRACE_POKETEXT can only write a word at a time, which is 8 bytes in
      // * AArch64. Since every instruction is 4 bytes, this will result in the
      // * instruction after being overwritten. We therefore need to combine the
      // * two into a single word before writing.
      // */

      uint64_t insn_word = (insn & 0xffffffff) | (next_insn << 32);

      if (ptrace(PTRACE_POKETEXT, slave_pid, insn_loc_iter, insn_word) == -1) {
          perror("poketext failed");
      }

      insn_loc_iter += 8;
    }

    // initialize registers to 0
    for (uint32_t i=0; i < UREG_COUNT; i++) {
      regs.regs[i] = 0;
    }

    // REGS_MODE_BENIGN: Benign execution
    //  - x0=slow_ptr1, x1=target_ptr, x2=test_ptr, x3=other_ptr
    // REGS_MODE_FAULT: MTE fault execution
    //  - x0=slow_ptr1, x1=target_ptr, x2=wrong_ptr, x3=other_ptr
    // REGS_MODE_RAND: Random register values to observe register changes
    //  - x0-x30=random values
    /*
      Only x0 ~ x5 are initialized for each purpose to find gadgets faster
    */ 
    if (regs_mode == REGS_MODE_BENIGN) {
      regs.regs[0] = (uint64_t) 1;
      regs.regs[1] = (uint64_t) target_ptr;
      regs.regs[2] = (uint64_t) test_ptr;
      regs.regs[3] = (uint64_t) other_ptr;
      regs.regs[4] = (uint64_t) test_ptr;
      regs.regs[5] = (uint64_t) 0;
    } else if (regs_mode == REGS_MODE_FAULT) {
      regs.regs[0] = (uint64_t) 1;
      regs.regs[1] = (uint64_t) wrong_ptr;
      regs.regs[2] = (uint64_t) test_ptr;
      regs.regs[3] = (uint64_t) other_ptr;
      regs.regs[4] = (uint64_t) test_ptr;
      regs.regs[5] = (uint64_t) 0;
    }
    
    if (regs_mode == REGS_MODE_RAND) {
      for (uint32_t i = 0; i < UREG_COUNT; ++i) {
          uint64_t rand_val = ((uint64_t)rand() << 32) | rand();
          regs.regs[i] = rand_val;
      }
    } else {
      for (uint32_t i=6; i < UREG_COUNT; ++i) {
          uint64_t rand_val = ((uint64_t)rand() << 32) | rand();
          regs.regs[i] = rand_val;
      }
    }

    *pc_reg = insn_loc;

    regs.pstate = 0;

    if (custom_ptrace_setregs(slave_pid, &regs) == -1) {
        perror("setregs failed");
    }

    memcpy(&result->regs_before, &regs, sizeof(regs));

    int signo = 0;
    do {
        // Execute the instruction
        ptrace(PTRACE_CONT, slave_pid, NULL, NULL);
        waitpid(slave_pid, &status, 0);

        if (WIFEXITED(status)) {
            // TODO: Refork slave if it died
            result->died = true;
            return;
        }

        result->died = false;

        // Store results
        if (custom_ptrace_getregs(slave_pid, &regs) == -1) {
            perror("getregs failed");
        }
        memcpy(&result->regs_after, &regs, sizeof(regs));

        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, slave_pid, NULL, &siginfo) == -1) {
            perror("getsiginfo failed");
        }

        signo = siginfo.si_signo;
        result->signal = (signo == SIGTRAP) ? 0 : signo;
        result->code = siginfo.si_code;
        result->addr = siginfo.si_addr;
        /*
         * If the terminal window is resized while executing, the slave
         * might raise a SIGWINCH signal before executing the instruction.
         * In such cases the execution must be repeated.
         */
    } while (signo == SIGWINCH && *pc_reg == insn_loc);

    // Fix the pc if the exception prevented the pc from advancing
    if (*pc_reg != &verify_code) {
        // Check whether a trap signal was caused by the executed instruction
        // (as opposed to the bkpt)
        if (signo == SIGTRAP) {
            result->signal = signo;
        }

        *pc_reg = insn_loc - 4;

        if (custom_ptrace_setregs(slave_pid, &regs) == -1) {
            perror("setregs failed");
        }
        ptrace(PTRACE_CONT, slave_pid, NULL, NULL);
        waitpid(slave_pid, &status, 0);
    }
}

int copy_file(char *src, char *dst) {
  int src_fd = open(src, O_RDONLY);
  if (src_fd == -1) {
    fprintf(stderr, "Error opening file %s (%s)\n", src, strerror(errno));
    return -1;
  }

  int dst_fd = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0777);
  if (dst_fd == -1) {
    fprintf(stderr, "Error opening file %s (%s)\n", dst, strerror(errno));
    return -1;
  }

  char buffer[GADGET_SIZE];
  ssize_t bytes_read = read(src_fd, buffer, sizeof(buffer));

  if (bytes_read > 0) {
    ssize_t bytes_written = write(dst_fd, buffer, bytes_read);
    if (bytes_written != bytes_read) {
      fprintf(stderr, "Error writing file %s (%s)\n", dst, strerror(errno));
      return -1;
    }
  } else {
    fprintf(stderr, "Error reading file %s (%s)\n", src, strerror(errno));
    return -1;
  }

  close(src_fd);
  close(dst_fd);
  return 0;
}

void init_fuzz() {

  // Create data directory
  if (mkdir(QUEUE, 0777) == -1) {
    if (errno != EEXIST) {
      fprintf(stderr, "Error mkdir queue (%s)\n", strerror(errno));
      exit(1);
    } 
  }

  // If input directory exists, copy all files to queue
  if (stat(INPUT, NULL) != 0) {
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(INPUT)) != NULL) {
      while ((ent = readdir(dir)) != NULL) {
        char *filename = ent->d_name;
        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
          continue;
        }
        char queue_name[100];

        char src[100];
        sprintf(src, "%s/%s", INPUT, filename);
        FILE *file = fopen(src, "r");
        if (file == NULL) {
          fprintf(stderr, "Error opening file %s (%s)\n", src, strerror(errno));
          exit(1);
        }

        char src_code[GADGET_SIZE]= {0};
        size_t src_size = fread(src_code, 1, GADGET_SIZE, file);
        size_t src_code_size = src_size/sizeof(uint32_t);
        
        if (verify_gadget(src_code, src_code_size, 0) == -1) {
          continue;
        }
        debug("Verified file %s code_size: %d\n", filename, src_code_size);

        strncpy(input_names[num_input_files], filename, 100);
        mutate_counter[num_input_files] = 0;
        num_input_files++;

        sprintf(queue_name, "%s:%08d", filename, 0);
        char dst[100];
        sprintf(dst, "%s/%s", QUEUE, queue_name);
        if (copy_file(src, dst) == -1) {
          fprintf(stderr, "Error copying file %s to %s\n", src, dst);
          exit(1);
        }
      }
      closedir(dir);
    } else {
      fprintf(stderr, "Error opening directory %s\n", INPUT);
      exit(1);
    }
  }

  if (num_input_files == 0) {
    fprintf(stderr, "No input files found\n");
    exit(1);
  }

  // Create output directory
  if (mkdir(OUTPUT, 0777) == -1) {
    if (errno != EEXIST) {
      fprintf(stderr, "Error mkdir output (%s)\n", strerror(errno));
      exit(1);
    }
  }

  // Create log file
  FILE *log_file = fopen(LOG, "w");
  if (log_file == NULL) {
    fprintf(stderr, "Error creating log file (%s)\n", strerror(errno));
    exit(1);
  }
  fclose(log_file);
}

void init_gadget() {
    // Init gadget testing environment
  char *page = (char*)map_and_zero(ENTRY_SIZE*32, true);
  char *page2 = (char*)map_and_zero(SBX_SIZE, true);
  slow_ptr1 = (uint64_t*)mte_set_tag(page, ENTRY_SIZE, 0x1);
  slow_ptr2 = (uint64_t*)mte_set_tag(page+ENTRY_SIZE, ENTRY_SIZE, 0x2);
  other_ptr2 = (uint64_t*)mte_set_tag(page+ENTRY_SIZE*2, ENTRY_SIZE, 0x3);
  target_ptr = (uint64_t*)mte_set_tag(page+ENTRY_SIZE*3, ENTRY_SIZE, 0x4);
  other_ptr = (uint64_t*)mte_set_tag(page+ENTRY_SIZE*4, ENTRY_SIZE, 0x5);
  test_ptr = (uint64_t*)mte_set_tag(page2, SBX_SIZE, 0x6);

  uint64_t mask = 0x0f00000000000000;
  uint64_t correct_tag = ((uint64_t)target_ptr & mask) >> 56;
  uintptr_t stripped_ptr = (uint64_t)target_ptr & ~mask;
  uint64_t wrong_tag = correct_tag ^ 0xf;
  wrong_ptr = (uint64_t*)(stripped_ptr | (wrong_tag << 56));

    // slave code
  code_start(nop, verify_code);
  code_emit(breakpoint);
  code_emit(nop); // Align to 8 bytes
  code_skip(0x100);
  code_emit(b_minus_102);
  code_finish(verify_code);

  initialize_mem();
}

int get_next_queue(char *queue, char *filename) {
  // Get the next file from dir. Return NULL if no files left.
  // exec_counter is used to keep track of the number of executions.
  // return a file that has not been executed yet.
  for (int i=0; i < num_input_files; i++) {
    if (exec_counter[i] > mutate_counter[i]) {
      continue;
    }
    sprintf(filename, "%s/%s:%08d", queue, input_names[i], exec_counter[i]);
    if (stat(filename, NULL) != 0) {
      exec_counter[i]++;
      return 1;
    }
  }

  return 0;
}

#define FROM_INPUT 1
#define FROM_QUEUE 2
#define FROM_OUTPUT 3
int get_random_src(char *filename) {
  if (num_input_files == 0) {
    return 0;
  }

  if (num_output_files == 0) {
    // Find a random file from input
    int filenum = rand() % num_input_files;
    int exec_cnt = exec_counter[filenum];
    if (exec_cnt == 0) {
      sprintf(filename, "%s:%08d", input_names[filenum], 0);
      return FROM_INPUT;
    }
    
    int execnum = rand() % (exec_counter[filenum]);
    sprintf(filename, "%s:%08d", input_names[filenum], execnum);
    return FROM_QUEUE;
  }

  int filenum = rand() % num_output_files;
  
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir(OUTPUT)) != NULL) {
    int i = 0;
    while ((ent = readdir(dir)) != NULL) {
      char *name = ent->d_name;
      if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        continue;
      }
      if (i == filenum) {
        sprintf(filename, "%s", name);
        closedir(dir);
        return FROM_OUTPUT;
      }
      i++;
    }
    closedir(dir);
  } else {
    fprintf(stderr, "Error opening directory %s\n", OUTPUT);
    exit(1);
  }

  return 0;
}

int verify_gadget(uint32_t *insn, size_t code_size, int dbg) {
  // Verify code

  // 1: Verify if code can be disassembled
  for (int i = 0; i < code_size; i++) {
    char disas_str[100];
    libopcodes_disassemble(insn[i], disas_str, sizeof(disas_str));
    if (strstr(disas_str, "undefined") != NULL) {
      // debug("  Disassembly failed (undefined)\n");
      return -1;
    }
    if (strstr(disas_str, "cbz") != NULL 
    || strstr(disas_str, "cbnz") != NULL
    || strstr(disas_str, "tbz") != NULL 
    || strstr(disas_str, "tbnz") != NULL
    || strstr(disas_str, "b.") != NULL) {
      // debug("  Disassembly failed (cbz/cbnz)\n");
      return -1;
    }

    // ignore sp usage
    if (strstr(disas_str, "[sp") != NULL 
    || strstr(disas_str, "sp,") != NULL) {
      // debug("  Disassembly failed (sp)\n");
      return -1;
    }
  } 
  
  // Dump disassembly
  if (dbg) {
    for (int i = 0; i < code_size; i++) {
      char disas_str[100];
      libopcodes_disassemble(insn[i], disas_str, sizeof(disas_str));
      debug("  Disassembly (%d): %s\n", i, disas_str);
    }
  }
  // debug("  1. Disassembly passed\n");

  // 2: Verify if code can be executed on benign execution
  execution_result exec_result;
  execute_insn_slave(&slave_pid, (uint8_t*)insn, code_size, REGS_MODE_BENIGN, &exec_result);
  if (exec_result.died) {
    // debug("  Benign execution failed (died)\n");
    return -1;
  }
  // Check any fault
  if (exec_result.signal != 0) {
    if (dbg) {
      debug("  2. Benign execution failed (signal: %d, %s, %p)\n", 
            exec_result.signal, strsignal(exec_result.signal),
            exec_result.addr);
      
      struct USER_REGS_TYPE regs;
      if (custom_ptrace_getregs(slave_pid, &regs) == -1) {
        perror("getregs failed");
      }
      uint64_t pc = regs.pc;
      uint32_t insn = (uint32_t)ptrace(PTRACE_PEEKTEXT, slave_pid, pc, 0);
      char disas_str[100];
      libopcodes_disassemble(insn, disas_str, sizeof(disas_str));
      debug("  Disassembly (%llx): %s\n", pc, disas_str);
    }
    return -1;
  }
  // Check if Callee-saved registers are preserved
  for (int i=19; i < UREG_COUNT; i++) {
    if (exec_result.regs_before.regs[i] != exec_result.regs_after.regs[i]) {
      if (dbg)
        debug("  2. Benign execution failed (register x%d changed: %llx -> %llx)\n", 
            i, exec_result.regs_before.regs[i], exec_result.regs_after.regs[i]);
      return -1;
    }
  }

  // debug("  2. Benign execution passed\n");
  // 3. Verify if code raises MTE fault with a wrong MTE tag
  execute_insn_slave(&slave_pid, (uint8_t*)insn, code_size, REGS_MODE_FAULT, &exec_result);
  if (exec_result.died) {
    if (dbg)
      debug("  Wrong execution failed (died)\n");
    return -1;
  }

  if (exec_result.signal != SIGSEGV) {
    if (dbg)
      debug("  Wrong execution failed (signal: %d, %s)\n", 
            exec_result.signal, strsignal(exec_result.signal));
    return -1;
  }


  if (exec_result.code != SEGV_MTEAERR && exec_result.code != SEGV_MTESERR) {
    if (dbg)
      debug("  Wrong execution passed (no MTE fault)\n");
    return -1;
  }

  if (dbg)
    debug("  3. Wrong execution MTE fault detected\n");

  return 0;
}

int populate_queue(char *queue, char *output, int num_files) {
  // Populate num_files files to queue, based on input files.

  // Choose one file from input
  char src[100];
  int res = get_random_src(src);
  if (!res) {
    fprintf(stderr, "Error: random file not found\n");
    exit(1);
  }
  if (res == FROM_INPUT) {
    debug("Chose a random file from input: %s\n", src);
  } else if (res == FROM_QUEUE) {
    debug("Chose a random file from queue: %s\n", src);
  } else {
    debug("Chose a random file from output: %s\n", src);
  }

  // parse original file name from src
  // orig_name: ORIGINAL_INPUT_NAME:xxxxxxxx
  char orig[100];
  for (int i = 0; i < strlen(src); i++) {
    if (src[i] == ':') {
      strncpy(orig, src, i);
      orig[i] = '\0';
      break;
    }
  }
  int input_idx = -1;
  for (int i = 0; i < num_input_files; i++) {
    if (strcmp(input_names[i], orig) == 0) {
      input_idx = i;
      break;
    }
  }
  if (input_idx == -1) {
    fprintf(stderr, "Error: input file not found\n");
    exit(1);
  }
  

  // Read file
  char path[100];
  if (res == FROM_INPUT)
    sprintf(path, "%s/%s", INPUT, orig);
  else if (res == FROM_QUEUE)
    sprintf(path, "%s/%s", QUEUE, src);
  else
    sprintf(path, "%s/%s", OUTPUT, src);

  FILE *file = fopen(path, "r");
  if (file == NULL) {
    fprintf(stderr, "Error opening file %s (%s)\n", path, strerror(errno));
    exit(1);
  }

  char src_code[GADGET_SIZE]= {0};
  char new_code[GADGET_SIZE]= {0};
  size_t src_size = fread(src_code, 1, GADGET_SIZE, file);
  size_t src_code_size = src_size/sizeof(uint32_t);
  if (src_size == 0) {
    fprintf(stderr, "Error reading file %s (%s)\n", path, strerror(errno));
    exit(1);
  }
  fclose(file);

  // Mutate code
  for (int i=0; i < num_files; i++) {
    // debug("Mutate %s #%d\n", src, i);
    while (1) {
      size_t new_code_size = mutate_code(src_code, src_code_size, new_code);
      size_t new_size = new_code_size * sizeof(uint32_t);

      // Verify code
      // disassemble, MTE fault?, etc. 
      if (verify_gadget(new_code, new_code_size, 1) == -1) {
        continue;
      }

      // Found a valid code
      char new_filename[100];
      char path[100];
      sprintf(new_filename, "%s:%08d", orig, ++mutate_counter[input_idx]);
      sprintf(path, "%s/%s", queue, new_filename);
      FILE *file = fopen(path, "w");
      if (file == NULL) {
        fprintf(stderr, "Error opening file %s (%s)\n", path, strerror(errno));
        exit(1);
      }
      fwrite(new_code, 1, new_size, file);
      fclose(file);

      debug("Create a new file %s\n", path);
      break;
    }
  }
  return 1;
}

int test_gadget(char *src, int dbg) {
    // Read file ("queue/input:xxxxxxxx")
    
    // if 'src' ends with "probe:{%d}", then it is already tested
    char *probe = strstr(src, "probe:");
    if (dbg && probe != NULL) {
      probe_idx = atoi(&probe[6]);
    }
    else {
      // int idx_pool[] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,5,6,7};
      // probe_idx = choice(idx_pool, ARR_LEN(idx_pool));
      probe_idx = randrange(0, 32);
    }

    // probe_idx = 3;

    // probe_idx = 0; // core 4 ~ 7 test
    char *probe_ptr = (char*)test_ptr + probe_idx*DISTANCE;

    debug("Testing file %s with probe index of [%d]\n", src, probe_idx);
    FILE *file = fopen(src, "r");
    if (file == NULL) {
      fprintf(stderr, "Error opening file %s (%s)\n", src, strerror(errno));
      exit(1);
    }

    // Copy file to code
    code_start(nop, test_code);
    code_emit(isb);
    code_emit(ldr_x0_x0);
    uint32_t *ret_ptr = code_ptr+0x100;
    code_emit(cbz_x0_100);
    size_t bytes_read = fread((uint32_t*)test_code+3, 1, GADGET_SIZE, file);
    if (bytes_read == 0) {
      fprintf(stderr, "Error reading file %s (%s)\n", src, strerror(errno));
      exit(1);
    }
    // debug("Read %d bytes\n", bytes_read);

    code_ptr = ret_ptr;
    code_emit(ret);
    code_finish(test_code);
    fclose(file);

    // Execute code multiple times
    int score=0;
    start_timer();

    for (int i = 0; i < TEST; i++) {
      int res = run_gadget(slow_ptr1, target_ptr, test_ptr, other_ptr, probe_ptr, dbg);
      if (dbg)
        debug("res: %d\n", res);
      if (res > DIFF_THRESHOLD) {
        score++;
      } else if (res < -DIFF_THRESHOLD) {
        score--;
      }
    }
    if (score < 0) {
      score = (-1)*score;
    }
    return score;
}

void fuzzer() {


  // Fuzz loop
  while (1) {

    // Get next file from queue
    char src[100];
    int res = get_next_queue(QUEUE, src);
    if (!res) {
      // No more files in queue
      populate_queue(QUEUE, OUTPUT, MUTATE_FILES);
      res = get_next_queue(QUEUE, src);
    }
    if (!res) {
      // No more files in queue
      debug("No more files in queue\n");
      break;
    }

    int score = test_gadget(src, 0);

    if (score > SCORE_THRESHOLD) {
      debug("%s Success\n", basename(src));
      // Copy file to output
      char dst[100];
      sprintf(dst, "%s/%s_probe:%d", OUTPUT, basename(src), probe_idx);
      if (copy_file(src, dst) == -1) {
        fprintf(stderr, "Error copying file %s to %s\n", src, dst);
        exit(1);
      }
      num_output_files++;
    }
    sleep(1);
  }
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    printf("Commands:\n");
    printf("  %d: fuzz test_cpu verify_cpu cmd\n", CMD_FUZZ);
    printf("  %d: hex_to_bin input_path\n", CMD_UTIL_HEX_TO_BIN);
    printf("  %d: bin_to_hex input_path\n", CMD_UTIL_BIN_TO_HEX);
    printf("  %d: bin_to_asm input_path\n", CMD_UTIL_BIN_TO_ASM);
    printf("  %d: reproduce cpu input_path\n", CMD_UTIL_REPRO);
    printf("  %d: verify cpu input_path\n", CMD_UTIL_VERIFY);
    return 1;
  }

  srand(time(NULL));

  int test_cpu = atoi(argv[1]);
  int verify_cpu = atoi(argv[2]);
  int cmd = atoi(argv[3]);

  if (test_cpu < 0 || test_cpu > 8) {
    printf("Invalid CPU: %d\n", test_cpu);
    return 1;
  }
  
  if (verify_cpu < 0 || verify_cpu > 8) {
    printf("Invalid CPU: %d\n", verify_cpu);
    return 1;
  }

  cpu_pin_to(test_cpu);
  set_max_priority();
  // debug("Pinned to CPU %d\n", test_cpu);

  mte_enable(true, DEFAULT_TAG_MASK);
  // debug("MTE SYNC\n");

  init_gadget();
  
  slave_pid = spawn_slave(verify_cpu);

  if (cmd == 0) {
    init_fuzz();
    fuzzer();
  } else {
    util_main(argc-3, &argv[3]);
  }

  return 0;
}
