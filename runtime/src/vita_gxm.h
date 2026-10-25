#pragma once

#include <stdint.h>

void vita_display_init(void);

void vita_display_present(const uint16_t* pixels, int width, int height);
