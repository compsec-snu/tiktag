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

#ifndef CONFIG_H_
#define CONFIG_H_

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Timing configuration
#define VIRTUAL_TIMER 0
#define CYCLE_COUNTER 1

#ifndef TIMER
#define TIMER VIRTUAL_TIMER
#endif

// This may need adjusting depending on the branch predictor behaviour of the
// CPU you are using.
#define BRANCH_PREDICTOR_ITERATIONS (512)


// #define ENTRY_SIZE (64)
#define ENTRY_SIZE (128)

#if TIMER == VIRTUAL_TIMER
    #define THRESHOLD 1
#elif TIMER == CYCLE_COUNTER
    #define THRESHOLD 70
#endif

#endif // CONFIG_H_
