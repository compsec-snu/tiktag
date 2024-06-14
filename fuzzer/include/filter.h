#pragma once
#include <stdint.h>
#include <stdbool.h>

bool filter_instruction(uint32_t insn, bool thumb, uint32_t filter_level);
