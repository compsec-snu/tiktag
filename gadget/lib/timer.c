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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include "scheduler.h"
#include "timer.h"
volatile uint64_t shared_counter = 0;

#if TIMER == VIRTUAL_TIMER
void start_timer() {
}
#elif TIMER == CYCLE_COUNTER
void init_pmu() {
  int tag_control_fd = open("/proc/enable-pmu", O_RDWR);

  if (tag_control_fd < 0) {
      perror("/proc/enable-pmu\n");
      exit(1);
  }
}

void start_timer() {
  init_pmu();
}
#endif
