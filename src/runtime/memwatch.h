#pragma once

#include <stdint.h>

void memwatch_init(void);
uint32_t memwatch_watch(uint64_t addr, uint64_t size);
int memwatch_written(uint64_t addr, uint64_t size, uint32_t since);

void memwatch_touch(uint64_t addr, uint64_t size);
