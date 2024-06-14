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

#ifndef TIMER_H_
#define TIMER_H_

#include "aarch64.h"
#include "config.h"

void start_timer();

#if TIMER == VIRTUAL_TIMER
__attribute__((always_inline))
static inline uint64_t read_latency(const void* ptr) {
  const volatile uint64_t* read_ptr = (const volatile uint64_t*)ptr;
  uint64_t start, end;

  local_memory_barrier();
  instruction_barrier();
  start = virtual_count();
  read_ptr = (const volatile uint64_t*)*read_ptr;
  local_memory_barrier();
  instruction_barrier();
  end = virtual_count();

  return end - start;
}
#elif TIMER == CYCLE_COUNTER
static inline int read_pmccntr() {
  int value;
  asm volatile("mrs %0, pmccntr_el0" : "=r" (value));
  return value;
}
__attribute__((always_inline))
static inline uint64_t read_latency(const void* ptr) {
  const volatile uint64_t* read_ptr = (const volatile uint64_t*)ptr;
  uint64_t start, end;

  local_memory_barrier();
  instruction_barrier();
  start = read_pmccntr();

  read_ptr = (const volatile uint64_t*)*read_ptr;
  local_memory_barrier();
  instruction_barrier();
  end = read_pmccntr();
  
  return end - start;
}
#endif

#endif // TIMER_H_
