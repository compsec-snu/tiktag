#include "mutate.h"
#include "binutils/opcodes/aarch64-dis.h"

int fd_urandom = -1;

static const uint32_t cbnz_x0_3    = 0xb5000060;
static const uint32_t cbnz_x0_2    = 0xb5000040;

static const uint32_t cbz_x0_100   = 0xb4002000;
static const uint32_t ldr_x4_x0    = 0xf9400004;

static const uint32_t add_x3_x3_x0 = 0x8b000063;
static const uint32_t ret          = 0xd65f03c0;
static const uint32_t bkpt         = 0xd4200000;
static const uint32_t dsb_ish      = 0xd5033b9f;
static const uint32_t isb          = 0xd5033fdf;

static const uint32_t ldr_x4_x1 = 0xf9400024;

// Base instructions
static const uint32_t nop          = 0xd503201f;
static const uint32_t fadd_d0_d0_d0 = 0x1e602800;
static const uint32_t fadd_d1_d0_d1 = 0x1e602821;
static const uint32_t mul_x3_x2_x0 = 0x9b007c43;
static const uint32_t mul_x4_x4_x4 = 0x9b027c84;
static const uint32_t orr_x4_x1_x2 = 0xaa020024; // gap0 <

static const uint32_t orr_x4_x4_x4 = 0xaa040084;
static const uint32_t orr_x4_x4_ff0 = 0x927c1c84;
static const uint32_t orr_x4_x4_ff8 = 0x927d2084;

static const uint32_t ldr_x4_x3    = 0xf9400064;
static const uint32_t ldr_x0_x3_x0 = 0xf8606860;

static const uint32_t eor_x0_x0_x0 = 0xca000000;
static const uint32_t eor_x0_x0_x1 = 0xca010000;
static const uint32_t eor_x0_x0_x2 = 0xca020000;
static const uint32_t eor_x0_x0_x3 = 0xca030000;
static const uint32_t eor_x0_x1_x0 = 0xca000020;
static const uint32_t eor_x0_x1_x1 = 0xca010020;
static const uint32_t eor_x0_x1_x2 = 0xca020020;
static const uint32_t eor_x0_x1_x3 = 0xca030020;
static const uint32_t eor_x0_x2_x0 = 0xca000040;
static const uint32_t eor_x0_x2_x1 = 0xca010040;
static const uint32_t eor_x0_x2_x2 = 0xca020040;
static const uint32_t eor_x0_x2_x3 = 0xca030040;
static const uint32_t eor_x0_x3_x0 = 0xca000060;
static const uint32_t eor_x0_x3_x1 = 0xca010060;
static const uint32_t eor_x0_x3_x2 = 0xca020060;
static const uint32_t eor_x0_x3_x3 = 0xca030060;
static const uint32_t eor_x1_x0_x0 = 0xca000001;
static const uint32_t eor_x1_x0_x1 = 0xca010001;
static const uint32_t eor_x1_x0_x2 = 0xca020001;
static const uint32_t eor_x1_x0_x3 = 0xca030001;
static const uint32_t eor_x1_x1_x0 = 0xca000021;
static const uint32_t eor_x1_x1_x1 = 0xca010021;
static const uint32_t eor_x1_x1_x2 = 0xca020021;
static const uint32_t eor_x1_x1_x3 = 0xca030021;
static const uint32_t eor_x1_x2_x0 = 0xca000041;
static const uint32_t eor_x1_x2_x1 = 0xca010041;
static const uint32_t eor_x1_x2_x2 = 0xca020041;
static const uint32_t eor_x1_x2_x3 = 0xca030041;
static const uint32_t eor_x1_x3_x0 = 0xca000061;
static const uint32_t eor_x1_x3_x1 = 0xca010061;
static const uint32_t eor_x1_x3_x2 = 0xca020061;
static const uint32_t eor_x1_x3_x3 = 0xca030061;
static const uint32_t eor_x2_x0_x0 = 0xca000002;
static const uint32_t eor_x2_x0_x1 = 0xca010002;
static const uint32_t eor_x2_x0_x2 = 0xca020002;
static const uint32_t eor_x2_x0_x3 = 0xca030002;
static const uint32_t eor_x2_x1_x0 = 0xca000022;
static const uint32_t eor_x2_x1_x1 = 0xca010022;
static const uint32_t eor_x2_x1_x2 = 0xca020022;
static const uint32_t eor_x2_x1_x3 = 0xca030022;
static const uint32_t eor_x2_x2_x0 = 0xca000042;
static const uint32_t eor_x2_x2_x1 = 0xca010042;
static const uint32_t eor_x2_x2_x2 = 0xca020042;
static const uint32_t eor_x2_x2_x3 = 0xca030042;
static const uint32_t eor_x2_x3_x0 = 0xca000062;
static const uint32_t eor_x2_x3_x1 = 0xca010062;
static const uint32_t eor_x2_x3_x2 = 0xca020062;
static const uint32_t eor_x2_x3_x3 = 0xca030062;
static const uint32_t eor_x3_x0_x0 = 0xca000003;
static const uint32_t eor_x3_x0_x1 = 0xca010003;
static const uint32_t eor_x3_x0_x2 = 0xca020003;
static const uint32_t eor_x3_x0_x3 = 0xca030003;
static const uint32_t eor_x3_x1_x0 = 0xca000023;
static const uint32_t eor_x3_x1_x1 = 0xca010023;
static const uint32_t eor_x3_x1_x2 = 0xca020023;
static const uint32_t eor_x3_x1_x3 = 0xca030023;
static const uint32_t eor_x3_x2_x0 = 0xca000043;
static const uint32_t eor_x3_x2_x1 = 0xca010043;
static const uint32_t eor_x3_x2_x2 = 0xca020043;
static const uint32_t eor_x3_x2_x3 = 0xca030043;
static const uint32_t eor_x3_x3_x0 = 0xca000063;
static const uint32_t eor_x3_x3_x1 = 0xca010063;
static const uint32_t eor_x3_x3_x2 = 0xca020063;
static const uint32_t eor_x3_x3_x3 = 0xca030063;
static const uint32_t orr_x0_x0_x0 = 0xaa000000;
static const uint32_t orr_x0_x0_x1 = 0xaa010000;
static const uint32_t orr_x0_x0_x2 = 0xaa020000;
static const uint32_t orr_x0_x0_x3 = 0xaa030000;
static const uint32_t orr_x0_x1_x0 = 0xaa000020;
static const uint32_t orr_x0_x1_x1 = 0xaa010020;
static const uint32_t orr_x0_x1_x2 = 0xaa020020;
static const uint32_t orr_x0_x1_x3 = 0xaa030020;
static const uint32_t orr_x0_x2_x0 = 0xaa000040;
static const uint32_t orr_x0_x2_x1 = 0xaa010040;
static const uint32_t orr_x0_x2_x2 = 0xaa020040;
static const uint32_t orr_x0_x2_x3 = 0xaa030040;
static const uint32_t orr_x0_x3_x0 = 0xaa000060;
static const uint32_t orr_x0_x3_x1 = 0xaa010060;
static const uint32_t orr_x0_x3_x2 = 0xaa020060;
static const uint32_t orr_x0_x3_x3 = 0xaa030060;
static const uint32_t orr_x1_x0_x0 = 0xaa000001;
static const uint32_t orr_x1_x0_x1 = 0xaa010001;
static const uint32_t orr_x1_x0_x2 = 0xaa020001;
static const uint32_t orr_x1_x0_x3 = 0xaa030001;
static const uint32_t orr_x1_x1_x0 = 0xaa000021;
static const uint32_t orr_x1_x1_x1 = 0xaa010021;
static const uint32_t orr_x1_x1_x2 = 0xaa020021;
static const uint32_t orr_x1_x1_x3 = 0xaa030021;
static const uint32_t orr_x1_x2_x0 = 0xaa000041;
static const uint32_t orr_x1_x2_x1 = 0xaa010041;
static const uint32_t orr_x1_x2_x2 = 0xaa020041;
static const uint32_t orr_x1_x2_x3 = 0xaa030041;
static const uint32_t orr_x1_x3_x0 = 0xaa000061;
static const uint32_t orr_x1_x3_x1 = 0xaa010061;
static const uint32_t orr_x1_x3_x2 = 0xaa020061;
static const uint32_t orr_x1_x3_x3 = 0xaa030061;
static const uint32_t orr_x2_x0_x0 = 0xaa000002;
static const uint32_t orr_x2_x0_x1 = 0xaa010002;
static const uint32_t orr_x2_x0_x2 = 0xaa020002;
static const uint32_t orr_x2_x0_x3 = 0xaa030002;
static const uint32_t orr_x2_x1_x0 = 0xaa000022;
static const uint32_t orr_x2_x1_x1 = 0xaa010022;
static const uint32_t orr_x2_x1_x2 = 0xaa020022;
static const uint32_t orr_x2_x1_x3 = 0xaa030022;
static const uint32_t orr_x2_x2_x0 = 0xaa000042;
static const uint32_t orr_x2_x2_x1 = 0xaa010042;
static const uint32_t orr_x2_x2_x2 = 0xaa020042;
static const uint32_t orr_x2_x2_x3 = 0xaa030042;
static const uint32_t orr_x2_x3_x0 = 0xaa000062;
static const uint32_t orr_x2_x3_x1 = 0xaa010062;
static const uint32_t orr_x2_x3_x2 = 0xaa020062;
static const uint32_t orr_x2_x3_x3 = 0xaa030062;
static const uint32_t orr_x3_x0_x0 = 0xaa000003;
static const uint32_t orr_x3_x0_x1 = 0xaa010003;
static const uint32_t orr_x3_x0_x2 = 0xaa020003;
static const uint32_t orr_x3_x0_x3 = 0xaa030003;
static const uint32_t orr_x3_x1_x0 = 0xaa000023;
static const uint32_t orr_x3_x1_x1 = 0xaa010023;
static const uint32_t orr_x3_x1_x2 = 0xaa020023;
static const uint32_t orr_x3_x1_x3 = 0xaa030023;
static const uint32_t orr_x3_x2_x0 = 0xaa000043;
static const uint32_t orr_x3_x2_x1 = 0xaa010043;
static const uint32_t orr_x3_x2_x2 = 0xaa020043;
static const uint32_t orr_x3_x2_x3 = 0xaa030043;
static const uint32_t orr_x3_x3_x0 = 0xaa000063;
static const uint32_t orr_x3_x3_x1 = 0xaa010063;
static const uint32_t orr_x3_x3_x2 = 0xaa020063;
static const uint32_t orr_x3_x3_x3 = 0xaa030063;
static const uint32_t ldr_x0_x0 = 0xf9400000;
static const uint32_t ldr_x0_x1 = 0xf9400020;
static const uint32_t ldr_x0_x2 = 0xf9400040;
static const uint32_t ldr_x0_x3 = 0xf9400060;
static const uint32_t ldr_x1_x0 = 0xf9400001;
static const uint32_t ldr_x1_x1 = 0xf9400021;
static const uint32_t ldr_x1_x2 = 0xf9400041;
static const uint32_t ldr_x1_x3 = 0xf9400061;
static const uint32_t ldr_x2_x0 = 0xf9400002;
static const uint32_t ldr_x2_x1 = 0xf9400022;
static const uint32_t ldr_x2_x2 = 0xf9400042;
static const uint32_t ldr_x2_x3 = 0xf9400062;
static const uint32_t ldr_x3_x0 = 0xf9400003;
static const uint32_t ldr_x3_x1 = 0xf9400023;
static const uint32_t ldr_x3_x2 = 0xf9400043;
static const uint32_t ldr_x3_x3 = 0xf9400063;
static const uint32_t str_x0_x0 = 0xf9000000;
static const uint32_t str_x0_x1 = 0xf9000020;
static const uint32_t str_x0_x2 = 0xf9000040;
static const uint32_t str_x0_x3 = 0xf9000060;
static const uint32_t str_x1_x0 = 0xf9000001;
static const uint32_t str_x1_x1 = 0xf9000021;
static const uint32_t str_x1_x2 = 0xf9000041;
static const uint32_t str_x1_x3 = 0xf9000061;
static const uint32_t str_x2_x0 = 0xf9000002;
static const uint32_t str_x2_x1 = 0xf9000022;
static const uint32_t str_x2_x2 = 0xf9000042;
static const uint32_t str_x2_x3 = 0xf9000062;
static const uint32_t str_x3_x0 = 0xf9000003;
static const uint32_t str_x3_x1 = 0xf9000023;
static const uint32_t str_x3_x2 = 0xf9000043;
static const uint32_t str_x3_x3 = 0xf9000063;

static const uint32_t ldr_x5_x4_x5 = 0xf8656885;
static const uint32_t ldrb_w5_x4_x5 = 0x38656885;
static const uint32_t lsl_x5_x5_4 = 0xd37ceca5;

typedef struct {
  uint32_t inst;
  int sandboxed_size;
  uint32_t sandboxed_inst[SANDBOX_MAX_INST_SIZE];
} sbx_instruction;

/*
  Operand registers are limited to x0 ~ x3 for fast gadget discovery.
  To support memory access within the sandboxed region, we use x4 as the base address and x5 for offsets.
*/ 
static sbx_instruction sbx_known_instructions[] = {
  {.inst = ldrb_w5_x4_x5, .sandboxed_size = 1, .sandboxed_inst = {lsl_x5_x5_4}},
};

static uint32_t known_instructions[] = {
/*
  x0: slow_ptr
  x1: guess_ptr
  x2: test_ptr
  x3: other_ptr
*/
  isb, isb, isb, isb, 
  nop, nop, nop, nop, nop, nop, nop, nop,

  // eor_x0_x0_x0, 
  // eor_x0_x0_x1, 
  // eor_x0_x0_x2, 
  // eor_x0_x0_x3, 
  // eor_x0_x1_x0, 
  // eor_x0_x1_x1, 
  // eor_x0_x1_x2, 
  // eor_x0_x1_x3, 
  // eor_x0_x2_x0, 
  // eor_x0_x2_x1, 
  // eor_x0_x2_x2, 
  // eor_x0_x2_x3, 
  // eor_x0_x3_x0, 
  // eor_x0_x3_x1, 
  // eor_x0_x3_x2, 
  // eor_x0_x3_x3, 
  // eor_x1_x0_x0, 
  // eor_x1_x0_x1, 
  // eor_x1_x0_x2, 
  // eor_x1_x0_x3, 
  // eor_x1_x1_x0, 
  // eor_x1_x1_x1, 
  // eor_x1_x1_x2, 
  // eor_x1_x1_x3, 
  // eor_x1_x2_x0, 
  // eor_x1_x2_x1, 
  // eor_x1_x2_x2, 
  // eor_x1_x2_x3, 
  // eor_x1_x3_x0, 
  // eor_x1_x3_x1, 
  // eor_x1_x3_x2, 
  // eor_x1_x3_x3, 
  // eor_x2_x0_x0, 
  // eor_x2_x0_x1, 
  // eor_x2_x0_x2, 
  // eor_x2_x0_x3, 
  // eor_x2_x1_x0, 
  // eor_x2_x1_x1, 
  // eor_x2_x1_x2, 
  // eor_x2_x1_x3, 
  // eor_x2_x2_x0, 
  // eor_x2_x2_x1, 
  // eor_x2_x2_x2, 
  // eor_x2_x2_x3, 
  // eor_x2_x3_x0, 
  // eor_x2_x3_x1, 
  // eor_x2_x3_x2, 
  // eor_x2_x3_x3, 
  // eor_x3_x0_x0, 
  // eor_x3_x0_x1, 
  // eor_x3_x0_x2, 
  // eor_x3_x0_x3, 
  // eor_x3_x1_x0, 
  // eor_x3_x1_x1, 
  // eor_x3_x1_x2, 
  // eor_x3_x1_x3, 
  // eor_x3_x2_x0, 
  // eor_x3_x2_x1, 
  // eor_x3_x2_x2, 
  // eor_x3_x2_x3, 
  // eor_x3_x3_x0, 
  // eor_x3_x3_x1, 
  // eor_x3_x3_x2, 
  // eor_x3_x3_x3, 
  orr_x0_x0_x0, 
  orr_x0_x0_x1, 
  orr_x0_x0_x2, 
  orr_x0_x0_x3, 
  orr_x0_x1_x0, 
  orr_x0_x1_x1, 
  orr_x0_x1_x2, 
  orr_x0_x1_x3, 
  orr_x0_x2_x0, 
  orr_x0_x2_x1, 
  orr_x0_x2_x2, 
  orr_x0_x2_x3, 
  orr_x0_x3_x0, 
  orr_x0_x3_x1, 
  orr_x0_x3_x2, 
  orr_x0_x3_x3, 
  orr_x1_x0_x0, 
  orr_x1_x0_x1, 
  orr_x1_x0_x2, 
  orr_x1_x0_x3, 
  orr_x1_x1_x0, 
  orr_x1_x1_x1, 
  orr_x1_x1_x2, 
  orr_x1_x1_x3, 
  orr_x1_x2_x0, 
  orr_x1_x2_x1, 
  orr_x1_x2_x2, 
  orr_x1_x2_x3, 
  orr_x1_x3_x0, 
  orr_x1_x3_x1, 
  orr_x1_x3_x2, 
  orr_x1_x3_x3, 
  orr_x2_x0_x0, 
  orr_x2_x0_x1, 
  orr_x2_x0_x2, 
  orr_x2_x0_x3, 
  orr_x2_x1_x0, 
  orr_x2_x1_x1, 
  orr_x2_x1_x2, 
  orr_x2_x1_x3, 
  orr_x2_x2_x0, 
  orr_x2_x2_x1, 
  orr_x2_x2_x2, 
  orr_x2_x2_x3, 
  orr_x2_x3_x0, 
  orr_x2_x3_x1, 
  orr_x2_x3_x2, 
  orr_x2_x3_x3, 
  orr_x3_x0_x0, 
  orr_x3_x0_x1, 
  orr_x3_x0_x2, 
  orr_x3_x0_x3, 
  orr_x3_x1_x0, 
  orr_x3_x1_x1, 
  orr_x3_x1_x2, 
  orr_x3_x1_x3, 
  orr_x3_x2_x0, 
  orr_x3_x2_x1, 
  orr_x3_x2_x2, 
  orr_x3_x2_x3, 
  orr_x3_x3_x0, 
  orr_x3_x3_x1, 
  orr_x3_x3_x2, 
  orr_x3_x3_x3, 
  ldr_x0_x0, ldr_x0_x0, 
  ldr_x0_x1, ldr_x0_x1, 
  ldr_x0_x2, ldr_x0_x2, 
  ldr_x0_x3, ldr_x0_x3, 
  ldr_x1_x0, ldr_x1_x0, 
  ldr_x1_x1, ldr_x1_x1, 
  ldr_x1_x2, ldr_x1_x2, 
  ldr_x1_x3, ldr_x1_x3, 
  ldr_x2_x0, ldr_x2_x0, 
  ldr_x2_x1, ldr_x2_x1, 
  ldr_x2_x2, ldr_x2_x2, 
  ldr_x2_x3, ldr_x2_x3, 
  ldr_x3_x0, ldr_x3_x0, 
  ldr_x3_x1, ldr_x3_x1, 
  ldr_x3_x2, ldr_x3_x2, 
  ldr_x3_x3, ldr_x3_x3,

#ifdef FUZZ_STORE
  str_x0_x0, str_x0_x0, 
  str_x0_x1, str_x0_x1, 
  str_x0_x2, str_x0_x2, 
  str_x0_x3, str_x0_x3, 
  str_x1_x0, str_x1_x0, 
  str_x1_x1, str_x1_x1, 
  str_x1_x2, str_x1_x2, 
  str_x1_x3, str_x1_x3, 
  str_x2_x0, str_x2_x0, 
  str_x2_x1, str_x2_x1, 
  str_x2_x2, str_x2_x2, 
  str_x2_x3, str_x2_x3, 
  str_x3_x0, str_x3_x0, 
  str_x3_x1, str_x3_x1, 
  str_x3_x2, str_x3_x2, 
  str_x3_x3, str_x3_x3, 
#endif
};

int sandboxing_instruction(uint32_t, uint32_t *);

uint32_t dev_rand() {
  uint32_t val;
  if (fd_urandom == -1) 
    fd_urandom = open("/dev/urandom", O_RDONLY);
  assert(read(fd_urandom, &val, sizeof(val)) == sizeof(val));
  return val;
}

// [begin, end)
uint32_t randrange(uint32_t begin, uint32_t end) {
  if (begin >= end)
    return begin;
  
  uint32_t range = end - begin;
  uint32_t result = (dev_rand() % range) + begin;
  
  return result;
}

uint32_t choice(uint32_t *pool, size_t length) {
  uint32_t idx = randrange(0, length);
  return pool[idx];
}

// prob: [1, 100]%
#define MUT(mut_function, prob) do { \
    uint32_t r = randrange(0, 100); \
    if (r >= prob)  \
        break;  \
    code_idx = !code_idx; \
    tmp_size = mut_function(codes[!code_idx], tmp_size, codes[code_idx]); \
} while (0)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
  mutation functions

  output_size mut_STRATEGY(input[], input-size, output[]);
*/
uint32_t mut_repeat_specific_pattern(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  if (input_code_size == 0) {
    return 0;
  }
  uint32_t idx_mut = 0;
  uint32_t rand_begin = randrange(0, input_code_size);
  uint32_t rand_length = randrange(1, input_code_size - rand_begin); 
  
  uint32_t repeat_pool[] = {1, 1, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8};
  int repeat_cnt = choice(repeat_pool, ARR_LEN(repeat_pool));
  if (input_code_size + repeat_cnt * rand_length > MAX_CODE_SIZE)
    repeat_cnt = (MAX_CODE_SIZE - input_code_size) / rand_length;
  
  int idx = 0;
  memcpy(output_code, input_code, (rand_begin) * sizeof(uint32_t));
  idx_mut = rand_begin;
  
  for (int i = 0; i < repeat_cnt; i++) {
    memcpy(&output_code[idx_mut], &input_code[rand_begin], rand_length * sizeof(uint32_t));
    idx_mut += rand_length;
  }

  // remaining instructions
  int remain_cnt = (input_code_size - (rand_begin + rand_length));

  // output code size should not exceed MAX_CODE_SIZE
  memcpy(&output_code[idx_mut], &input_code[rand_begin + rand_length], remain_cnt * sizeof(uint32_t));
  
  idx_mut += remain_cnt;
  return idx_mut;
}

uint32_t remove_sbx_instructions(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  if (input_code_size == 0) {
    return 0;
  }

  uint32_t input_idx;
  uint32_t mut_idx;

  for (uint32_t i = 0; i < input_code_size; i++) {
    int flag = 0;
    for (int idx = 0; idx < ARR_LEN(sbx_known_instructions); idx++) {
      if (input_code[i] == sbx_known_instructions[idx].inst) {
        flag = 1;
        goto FIN;
      }
      for (int sdx = 0; sdx < sbx_known_instructions[idx].sandboxed_size; sdx++) {
        if (input_code[i] == sbx_known_instructions[idx].sandboxed_inst[sdx]) {
          flag = 1;
          goto FIN;
        }
      }
    }
    FIN:
    if (!flag)
      output_code[mut_idx++] = input_code[i];
  }

  return mut_idx;
}


uint32_t mut_trim_sequence(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  if (input_code_size == 0) {
    return 0;
  }

  uint32_t idx_mut = 0;
  uint32_t rand_begin = randrange(0, input_code_size);
  uint32_t rand_length = randrange(1, input_code_size - rand_begin); 

  memcpy(&output_code[0], &input_code[0], rand_begin * sizeof(uint32_t));
  idx_mut = rand_begin;

  uint32_t remain_cnt = input_code_size - (rand_begin + rand_length);
  memcpy(&output_code[idx_mut], &input_code[input_code_size - remain_cnt], remain_cnt * sizeof(uint32_t));
  idx_mut += remain_cnt;
  
  return idx_mut;
}

// swap two instruction
uint32_t mut_swap(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  uint32_t idx1 = randrange(0, input_code_size);
  uint32_t idx2 = randrange(0, input_code_size);
  
  memcpy(&output_code[0], &input_code[0], input_code_size * sizeof(uint32_t));
  uint32_t i1 = output_code[idx1];
  uint32_t i2 = output_code[idx2];
  output_code[idx1] = i2;
  output_code[idx2] = i1;

  return input_code_size;
}

uint32_t gen_defined_instruction() {
  uint32_t inst;
  char disasm[256];

  while (1) {
    inst = dev_rand();
    int libopcode_ret = libopcodes_disassemble(inst, disasm, sizeof(disasm));
    if (libopcode_ret == 0) { 
      // fail
      continue;
    }

    bool libopcodes_undefined =
        (strstr(disasm, "undefined") != NULL
      || strstr(disasm, "NYI") != NULL
      || strstr(disasm, "UNDEFINED") != NULL
      || strstr(disasm, "cbz") != NULL
      || strstr(disasm, "cbnz") != NULL
      || strstr(disasm, "tbz") != NULL
      || strstr(disasm, "tbnz") != NULL
      || strstr(disasm, "b.") != NULL
      || strstr(disasm, "[sp") != NULL
      || strstr(disasm, "sp,") != NULL
      );

    if (libopcodes_undefined) {
      continue;
    }

    break;    
  }

  return inst;
}

uint32_t mut_insert_random_insts(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  uint32_t insert_idx = randrange(0, input_code_size);
  uint32_t remain_cnt = input_code_size - insert_idx;
  uint32_t mut_idx = 0;

  uint32_t pool[] = {1, 1, 1, 2, 2, 3};
  uint32_t repeat_cnt = choice(pool, ARR_LEN(pool));
  repeat_cnt = MIN(repeat_cnt * SANDBOX_MAX_INST_SIZE, MAX_CODE_SIZE - input_code_size);
  
  memcpy(&output_code[0], &input_code[0], insert_idx * sizeof(uint32_t));
  mut_idx = insert_idx;
  for (uint32_t i = 0; i < repeat_cnt; i++) {    
    // some instruction causes crash not on verify, but on test_gadget
    // case 1. PC relative instructions (e.g. "ldr x0, 0xfffffffffff75280")
    uint32_t new_inst;
    uint32_t sandboxed_inst[SANDBOX_MAX_INST_SIZE] = {0, };
    int sandboxed_size;
    while (1) {
      new_inst = gen_defined_instruction();
      sandboxed_size = sandboxing_instruction(new_inst, sandboxed_inst);
      if (sandboxed_size == -1) {
        continue;
      }
      break;
    }
    
    memcpy(&output_code[mut_idx], sandboxed_inst, sandboxed_size * sizeof(uint32_t));
    mut_idx += sandboxed_size;
  }

  memcpy(&output_code[mut_idx], &input_code[insert_idx], remain_cnt * sizeof(uint32_t));
  mut_idx += remain_cnt;

  return mut_idx;
}

uint32_t mut_add_known_instructions(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  uint32_t insert_idx = randrange(0, input_code_size);
  uint32_t remain_cnt = input_code_size - insert_idx;
  uint32_t mut_idx = 0;

  uint32_t pool[] = {1, 1, 1, 2, 2, 3, 4};
  uint32_t repeat_cnt = choice(pool, ARR_LEN(pool));
  repeat_cnt = MIN(repeat_cnt, MAX_CODE_SIZE - input_code_size);

  memcpy(&output_code[0], &input_code[0], insert_idx * sizeof(uint32_t));
  mut_idx = insert_idx;
  for (uint32_t i = 0; i < repeat_cnt; i++) {
    // Select from known instructions with a 90% probability
    uint32_t new_inst = choice(known_instructions, ARR_LEN(known_instructions));
    output_code[mut_idx++] = new_inst;
  }

  memcpy(&output_code[mut_idx], &input_code[insert_idx], remain_cnt * sizeof(uint32_t));  
  mut_idx += remain_cnt;

  return mut_idx;  
}

int cmpfunc (const void * a, const void * b) {
   return ( *(int*)a - *(int*)b );
}

uint32_t mut_add_known_sbx_instructions(uint32_t* input_code, uint32_t input_code_size, uint32_t *output_code) {
  uint32_t mut_idx = 0;

  uint32_t pool[] = {1, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8};
  uint32_t insert_cnt = choice(pool, ARR_LEN(pool));
  insert_cnt = MIN(insert_cnt * (SANDBOX_MAX_INST_SIZE+1), MAX_CODE_SIZE - input_code_size) / (SANDBOX_MAX_INST_SIZE+1);

  int insert_point[MAX_INSERTION_CNT], insert_idx = 0;
  for (int i = 0; i < insert_cnt; i++) {
    insert_point[i] = randrange(0, input_code_size);
  }

  qsort(insert_point, insert_cnt, sizeof(int), cmpfunc);

  for (uint32_t i = 0; i < input_code_size; i++) {
    for (int j = insert_idx; j < insert_cnt; j++) {
      if (insert_point[j] > i)
        break;
      else if (insert_point[j] == i) {
        int sbx_inst_idx = randrange(0, ARR_LEN(sbx_known_instructions));
        for (int j = 0; j < sbx_known_instructions[sbx_inst_idx].sandboxed_size; j++)
          output_code[mut_idx++] = sbx_known_instructions[sbx_inst_idx].sandboxed_inst[j];
        output_code[mut_idx++] = sbx_known_instructions[sbx_inst_idx].inst;

        insert_idx++;
      }
    }

    output_code[mut_idx++] = input_code[i];
  }

  return mut_idx;  
}

/*
  x0: slow_ptr
  x1: guess_ptr
  x2: test_ptr

  < template >
  ...
  ldr x0, [x0]
  cbnz x0, 100*4
  
-- mutate begin --
SPECULATIVE:
    ...
    TAG_GUESS {
      ldr ?, [x1]
      str ?, [x1]
    } * N
    ...
    ldr x2, [x2]

-- mutate end --

  ret 
  Assume: `mutated_code` is fixed array of uint32_t[MAX_CODE_SIZE]
*/
uint32_t mutate_code(uint32_t *origin_code, int origin_code_count, uint32_t *mutated_code) {

#ifdef _TEST
  uint32_t src[] = {
    0xf9400020, 
    0xf9400020, 
    0xd37ceca5, 
    0x38656885, 
    0xd37ceca5, 
    0x38656885, 
    0xd37ceca5, 
    0x38656885, 
    0xd37ceca5, 
    0x38656885, 
  };
  /*
    eor     x3, x2, x1
    orr     x3, x0, x3
    eor     x2, x1, x3
    ldr     x3, [x1]
    orr     x1, x1, x2
    orr     x3, x2, x0
    ldr     x0, [x1]
    orr     x1, x2, x3
    ldr     x3, [x1]
    orr     x1, x2, x3
    ldr    x3, [x1]
    ldr    x3, [x1]
    orr    x1, x2, x3
    eor    x1, x3, x1
    eor    x3, x3, x1
    orr    x1, x1, x0
    orr    x1, x1, x2c
    orr    x3, x2, x0
    ldr    x0, [x1]
    str    x3, [x1]
    str    x3, [x2]
  */
  memcpy(mutated_code, src, sizeof(src));
  return ARR_LEN(src);
#endif

  debug("[mutate] begin\n");
  int idx_load_test_ptr = -1;
  int idx_branch = -1;
  int idx_mut = 0;

  // code analyzer
  // char disasm[256];
  // for (int i = 0; i < origin_code_count; i++) {
  //   uint32_t cur_code = origin_code[i];
  //   int libopcode_ret = libopcodes_disassemble(cur_code, disasm, sizeof(disasm));
  // }

  uint32_t tmp_code_A[MAX_CODE_SIZE];
  uint32_t tmp_code_B[MAX_CODE_SIZE];
  uint32_t *codes[] = {tmp_code_A, tmp_code_B};
  uint32_t tmp_size;
  int code_idx = 0;
  
  uint32_t (*first_mut)(uint32_t*, uint32_t, uint32_t*) = remove_sbx_instructions;
  tmp_size = first_mut(origin_code, origin_code_count, codes[code_idx]);

  MUT(mut_add_known_instructions, 100);
  MUT(mut_trim_sequence, 70);
  MUT(mut_repeat_specific_pattern, 100);
  MUT(mut_trim_sequence, 30);
  MUT(mut_swap, 70);
  MUT(mut_repeat_specific_pattern, 30);
  MUT(mut_add_known_sbx_instructions, 20);
  // MUT(mut_insert_random_insts, 50);

  // apply various mutation functions
  // MUT(mut_repeat_specific_pattern, 100);
  // MUT(mut_swap, 10);
  // MUT(mut_swap, 10);
  // MUT(mut_trim_sequence, 50);
  
  // printf("final mutation: %p\n", codes[code_idx]);
  memcpy(mutated_code, codes[code_idx], tmp_size * sizeof(uint32_t));
  debug("[mutate] end\n");
  return tmp_size;
}


void randomize_memory(char *mem_addr, size_t mem_size) {
  int res = read(fd_urandom, mem_addr, mem_size);
  assert(res == mem_size);
}

void TEST_mutate() {
    /*
  x0: slow_ptr
  x1: guess_ptr
  x2: test_ptr
*/
  srand(time(NULL));
  uint32_t code[] = {
    // ldr_x0_x0,
    // cbnz_x0_100,

    ldr_x1_x1,
    ldr_x1_x1,

    orr_x3_x1_x2,
    orr_x3_x1_x2,

    ldr_x2_x2,
    ldr_x2_x2,
    // ret
  };

  uint32_t mutated_code[MAX_CODE_SIZE];

  char disasm[256];
  uint32_t mut_size = mutate_code(code, ARR_LEN(code), mutated_code);
  for (uint32_t i = 0; i < mut_size; i++) {
    libopcodes_disassemble(mutated_code[i], disasm, sizeof(disasm));
    printf("[%2d] %s\n", i, disasm);
  }
}

void analyze_instruction(uint32_t code) {
  char disasm[256];
  int libopcode_ret = libopcodes_disassemble(code, disasm, sizeof(disasm));
  printf("Inst: %s\n", disasm);
  printf("=== Analyze %p ===\n", code);
  aarch64_opcode* opcode = aarch64_opcode_lookup(code);
  aarch64_inst inst, new_inst;
  aarch64_decode_insn(code, &inst, false, NULL);

  uint32_t new_code = 0;

  // add x1, x2, x3
  // add x1, x2, 100
  // ldr x1, [x2]
  // ldr w1, [x2]
  for (int i = 0; i < AARCH64_MAX_OPND_NUM; i++) {
    enum aarch64_opnd opnd_type = inst.operands[i].type;
    aarch64_operand operand_base = aarch64_operands[opnd_type];

//   AARCH64_OPND_CLASS_INT_REG,
//   AARCH64_OPND_CLASS_MODIFIED_REG,
//   AARCH64_OPND_CLASS_FP_REG,
//   AARCH64_OPND_CLASS_SIMD_REG,
//   AARCH64_OPND_CLASS_SIMD_ELEMENT,
//   AARCH64_OPND_CLASS_SISD_REG,
//   AARCH64_OPND_CLASS_SIMD_REGLIST,
//   AARCH64_OPND_CLASS_SVE_REG,
//   AARCH64_OPND_CLASS_PRED_REG,
//   AARCH64_OPND_CLASS_ADDRESS,
//   AARCH64_OPND_CLASS_IMMEDIATE,
//   AARCH64_OPND_CLASS_SYSTEM,
//   AARCH64_OPND_CLASS_COND,
    enum aarch64_operand_class op_class = operand_base.op_class;
    
    if (opnd_type == AARCH64_OPND_NIL)
      break;
    
    printf("Analyze %dth Operand of type %d\n", i, opnd_type);
    if (op_class == AARCH64_OPND_CLASS_INT_REG) {
      printf("regno: %d\n", inst.operands[i].reg.regno);

    }
    else if (op_class == AARCH64_OPND_CLASS_MODIFIED_REG) {
      printf("mod regno: %d\n", inst.operands[i].reglane.regno);
      printf("mod index: %d\n", inst.operands[i].reglane.index);
      if (inst.operands[i].shifter.kind == AARCH64_MOD_NONE)
        printf("shifter: none\n");
      // else if (inst.operands[i].shifter.amount_present)
      if (inst.operands[i].shifter.operator_present)
        printf("shifter amount: %d\n", inst.operands[i].shifter.amount);
      // inst.operands[i].shifter.amount = 1;
    }

    else if (op_class == AARCH64_OPND_CLASS_ADDRESS) {
      printf("addr.base_regno: %d\n", inst.operands[i].addr.base_regno);
      printf("addr.offset.is_reg: %d\n", inst.operands[i].addr.offset.is_reg);
      if (inst.operands[i].addr.offset.is_reg)
        printf("addr.offset.regno: %d\n", inst.operands[i].addr.offset.regno);
      else
        printf("addr.offset.imm: %d\n", inst.operands[i].addr.offset.imm);

      printf("addr.offset: %d\n", inst.operands[i].addr.offset);
    }
    else if (op_class == AARCH64_OPND_CLASS_IMMEDIATE) {
      printf("immediate: %d\n", inst.operands[i].imm);

    }
    else {
      printf("op_class not implemented: %d\n", op_class);
    }
  }

  printf("Conversion %d\n", _aarch64_opcode_encode(inst.opcode, &inst, &new_code, NULL, NULL));
  printf("New: %p\n", new_code);

  
}

// Assume CODE is not 'undefined' instruction
// return size of sandboxed instruction
// if failed, return -1
int sandboxing_instruction(uint32_t code, uint32_t *sandboxed_code) {
  aarch64_inst inst;
  uint32_t *sandboxed_code_ptr = sandboxed_code;
  int code_idx = 0;
  aarch64_decode_insn(code, &inst, false, NULL);
  analyze_instruction(code);

  for (int i = 0; i < AARCH64_MAX_OPND_NUM; i++) {
    enum aarch64_opnd opnd_type = inst.operands[i].type;
    aarch64_operand operand_base = aarch64_operands[opnd_type];

    enum aarch64_operand_class op_class = operand_base.op_class;
    if (opnd_type == AARCH64_OPND_NIL)
      break;

    if (op_class == AARCH64_OPND_CLASS_INT_REG) {
      uint32_t reg_pool[] = {0, 1, 2, 3, 4};
      int rand_regno = choice(reg_pool, ARR_LEN(reg_pool));
      inst.operands[i].reg.regno = rand_regno;
    }
    else if (op_class == AARCH64_OPND_CLASS_MODIFIED_REG) {
      goto fail;
    }
    else if (op_class == AARCH64_OPND_CLASS_ADDRESS) {
      if (opnd_type == AARCH64_OPND_ADDR_ADRP 
        || opnd_type == AARCH64_OPND_ADDR_PCREL14
        || opnd_type == AARCH64_OPND_ADDR_PCREL19
        || opnd_type == AARCH64_OPND_ADDR_PCREL21
        || opnd_type == AARCH64_OPND_ADDR_PCREL26
      ) {
        goto fail;
      }

      //     struct
      // {
      //   unsigned base_regno;
      //   struct
      //     {
      //       union
      //   {
      //     int imm;
      //     unsigned regno;
      //   };
      //       unsigned is_reg;
      //     } offset;
      //   unsigned pcrel : 1;		/* PC-relative.  */
      //   unsigned writeback : 1;
      //   unsigned preind : 1;		/* Pre-indexed.  */
      //   unsigned postind : 1;		/* Post-indexed.  */
      // } addr;

      if (opnd_type == AARCH64_OPND_ADDR_SIMPLE) {
        uint32_t reg_pool[] = {1, 2};
        int rand_regno = choice(reg_pool, ARR_LEN(reg_pool));
        inst.operands[i].addr.base_regno = rand_regno; // force to use x5
      }
      else if (opnd_type == AARCH64_OPND_ADDR_REGOFF) {
        // And mask register with 0xff8
        uint32_t reg_pool[] = {1, 2};
        int rand_regno = choice(reg_pool, ARR_LEN(reg_pool));
        inst.operands[i].addr.base_regno = rand_regno;
        inst.operands[i].addr.offset.regno = 6; // offset register
        sandboxed_code_ptr[code_idx] = 0xdeadbeef;
        code_idx++;
      }
      else {
        // ldr x?, [x?, #??] => ldr x?, [x5, #0]
        inst.operands[i].addr.base_regno = 5;
        inst.operands[i].addr.offset.imm = 0;
      }

    }
    else if (op_class == AARCH64_OPND_CLASS_IMMEDIATE) {

    }
    else {
      goto fail;
    }
  }

  if (!_aarch64_opcode_encode(inst.opcode, &inst, &sandboxed_code[code_idx], NULL, NULL)) {
    goto fail;
  }
  
  return code_idx+1;

fail:
  *sandboxed_code = -1;
  return -1;

}

void TEST_disas() {
  uint32_t new_inst[SANDBOX_MAX_INST_SIZE] = {0};
  int res = sandboxing_instruction(0x58ba9400, new_inst);
  printf("Sandboxing result: %d\n", res);
  char disasm[256];
  int libopcode_ret;

  for (int i = 0; i < res; i++) {
    libopcode_ret = libopcodes_disassemble(new_inst[i], disasm, sizeof(disasm));
    printf("New: %s\n", disasm);
  }

  return;
  while (1) {
    uint32_t inst = gen_defined_instruction();
    inst = 0xf86168f8;
    bool result = sandboxing_instruction(inst, new_inst);
    if (result)
     break;
  }


  libopcode_ret = libopcodes_disassemble(new_inst[0], disasm, sizeof(disasm));
  printf("New: %s\n", disasm);
}
