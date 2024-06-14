// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MTE_H_
#define MTE_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>

// From linux/include/uapi/linux/prctl.h
/* Tagged user address controls for arm64 */
#define PR_SET_TAGGED_ADDR_CTRL		55
#define PR_GET_TAGGED_ADDR_CTRL		56
# define PR_TAGGED_ADDR_ENABLE		(1UL << 0)
/* MTE tag check fault modes */
# define PR_MTE_TCF_NONE		0
# define PR_MTE_TCF_SYNC		(1UL << 1)
# define PR_MTE_TCF_ASYNC		(1UL << 2)
# define PR_MTE_TCF_MASK		(PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC)
/* MTE tag inclusion mask */
# define PR_MTE_TAG_SHIFT		3
# define PR_MTE_TAG_MASK		(0xffffUL << PR_MTE_TAG_SHIFT)
/* Unused; kept only for source compatibility */
# define PR_MTE_TCF_SHIFT		1

// From linux/arch/arm64/include/uapi/mman.h
#define PROT_MTE	0x20		/* Memory Tagging Extension */

#define DEFAULT_TAG_MASK ((uint16_t)0xfffe)

void mte_enable(bool sync, uint16_t tag_mask);
void mte_disable();

// from scudo allocator (memtag.h)
__attribute__((always_inline))
inline void *store_tag(void *Begin, void *End) {
  uint64_t LineSize, Next, Tmp;
  asm volatile(
    // Compute the cache line size in bytes (DCZID_EL0 stores it as the log2
    // of the number of 4-byte words) and bail out to the slow path if DCZID_EL0
    // indicates that the DC instructions are unavailable.
    "DCZID .req %[Tmp]\n\t"
    "mrs DCZID, dczid_el0\n\t"
    "tbnz DCZID, #4, 3f\n\t"
    "and DCZID, DCZID, #15\n\t"
    "mov %[LineSize], #4\n\t"
    "lsl %[LineSize], %[LineSize], DCZID\n\t"
    ".unreq DCZID\n\t"

    // Our main loop doesn't handle the case where we don't need to perform any
    // DC GZVA operations. If the size of our tagged region is less than
    // twice the cache line size, bail out to the slow path since it's not
    // guaranteed that we'll be able to do a DC GZVA.
    "Size .req %[Tmp]\n\t"
    "sub Size, %[End], %[Cur]\n\t"
    "cmp Size, %[LineSize], lsl #1\n\t"
    "b.lt 3f\n\t"
    ".unreq Size\n\t"

    "LineMask .req %[Tmp]\n\t"
    "sub LineMask, %[LineSize], #1\n\t"

    // STZG until the start of the next cache line.
    "orr %[Next], %[Cur], LineMask\n\t"
  "1:\n\t"
    "stzg %[Cur], [%[Cur]], #16\n\t"
    "cmp %[Cur], %[Next]\n\t"
    "b.lt 1b\n\t"

    // DC GZVA cache lines until we have no more full cache lines.
    "bic %[Next], %[End], LineMask\n\t"
    ".unreq LineMask\n\t"
  "2:\n\t"
    "dc gzva, %[Cur]\n\t"
    "add %[Cur], %[Cur], %[LineSize]\n\t"
    "cmp %[Cur], %[Next]\n\t"
    "b.lt 2b\n\t"

    // STZG until the end of the tagged region. This loop is also used to handle
    // slow path cases.
  "3:\n\t"
    "cmp %[Cur], %[End]\n\t"
    "b.ge 4f\n\t"
    "stzg %[Cur], [%[Cur]], #16\n\t"
    "b 3b\n\t"

  "4:\n\t"
      : [Cur] "+&r"(Begin), [LineSize] "=&r"(LineSize), [Next] "=&r"(Next),
        [Tmp] "=&r"(Tmp)
      : [End] "r"(End)
      : "memory");
}

__attribute__((always_inline))
inline void* mte_tag_and_zero(void* ptr, size_t len) {
  asm volatile ("irg %0, %0\n" : "+r"(ptr));
  void* end_ptr = ptr;

  //for (size_t i = 0; i < len; i += 16) {
  //  asm volatile ("stzg %0, [%0], #16\n" : "+r"(end_ptr));
  //}

  store_tag(ptr, (char*)ptr+len);
  return ptr;
}

__attribute__((always_inline))
inline void* mte_set_tag(void* ptr, size_t len, uint16_t tag) {
    
  ptr = (uint64_t*)((uintptr_t)ptr & 0xfffffffffffffful);
  ptr = (uint64_t*)((uintptr_t)ptr | ((uintptr_t)tag << 56));

  store_tag(ptr, (char*)ptr+len);
  return ptr;
}

__attribute__((always_inline))
inline void* mte_tag(void* ptr, size_t len) {
  asm volatile ("irg %0, %0\n" : "+r"(ptr));
  void* end_ptr = ptr;
  for (size_t i = 0; i < len; i += 16) {
    asm volatile ("stg %0, [%0], #16\n" : "+r"(end_ptr));
  }
  return ptr;
}

__attribute__((always_inline))
inline void* mte_strip_tag(void* ptr) {
  return (uint64_t*)((uintptr_t)ptr & 0xfffffffffffffful);
}

#endif // MTE_H_
