#pragma once

#include <stddef.h>
#include <stdint.h>

int tile_is_tiled(uint32_t tile_mode);
size_t tile_size(uint32_t tile_mode, uint32_t pitch, uint32_t height, uint32_t bpp);
int tile_detile(uint32_t tile_mode, const uint8_t* in, uint8_t* out, uint32_t width, uint32_t height, uint32_t pitch,
                uint32_t bpp);
