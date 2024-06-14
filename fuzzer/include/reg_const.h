#pragma once
#include <sys/user.h>

#define VFPREG_COUNT 32

#ifdef __aarch64__

/*
 * The structs should look like this:
 *

   struct user_regs_struct
   {
       unsigned long long regs[31];
       unsigned long long sp;
       unsigned long long pc;
       unsigned long long pstate;
   };

   struct user_fpsimd_struct
   {
        __uint128_t  vregs[32];
        unsigned int fpsr;
        unsigned int fpcr;
   };

 */
#define USER_REGS_TYPE user_regs_struct
#define USER_VFPREGS_TYPE user_fpsimd_struct
#define UREG_COUNT 31

#else

/*
 * user_vfp is defined in linux's user.h, but not in glibc's user.h
 * as far as I can tell. Defining the struct directly here avoids
 * having to include kernel headers, but it does risk breakage if
 * sys/user.h already defines the struct.
 *
 * So remove this if compilation fails because of redeclaration.
 */
struct user_vfp {
    unsigned long long fpregs[32];
    unsigned long fpscr;
};

/*
 * user_regs should look like this:
 *
   struct user_regs
   {
        unsigned long int uregs[18];
   };
 */
#define USER_REGS_TYPE user_regs
#define USER_VFPREGS_TYPE user_vfp
#define UREG_COUNT  18

#define A32_r0      0
#define A32_r1      1
#define A32_r2      2
#define A32_r3      3
#define A32_r4      4
#define A32_r5      5
#define A32_r6      6
#define A32_r7      7
#define A32_r8      8
#define A32_r9      9
#define A32_r10     10
#define A32_fp      11
#define A32_ip      12
#define A32_sp      13
#define A32_lr      14
#define A32_pc      15
#define A32_cpsr    16
#define A32_ORIG_r0 17

#endif
