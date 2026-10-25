#include "tiling.h"

#include <string.h>

enum { MICRO_DISPLAY, MICRO_THIN, MICRO_DEPTH };

typedef struct Mode {
    int micro;
    int macro;
    int known;
} Mode;

static Mode mode_of(uint32_t m) {
    switch (m) {
    case 9: return (Mode){MICRO_DISPLAY, 0, 1};
    case 13: return (Mode){MICRO_THIN, 0, 1};
    case 5: return (Mode){MICRO_DEPTH, 0, 1};
    case 10: return (Mode){MICRO_DISPLAY, 1, 1};
    case 14: return (Mode){MICRO_THIN, 1, 1};
    case 0: case 1: case 2: case 3: case 4: return (Mode){MICRO_DEPTH, 1, 1};
    default: return (Mode){0, 0, 0};
    }
}

int tile_is_tiled(uint32_t m) {
    return m != 8 && m != 31;
}

static uint32_t bit(uint32_t v, int b) {
    return v >> b & 1;
}

static uint32_t pixel_index(int micro, uint32_t x, uint32_t y, uint32_t bits) {
    const uint32_t x0 = bit(x, 0), x1 = bit(x, 1), x2 = bit(x, 2), y0 = bit(y, 0), y1 = bit(y, 1), y2 = bit(y, 2);
    uint32_t p[6];
    if (micro == MICRO_DISPLAY) {
        switch (bits) {
        case 8: p[0] = x0, p[1] = x1, p[2] = x2, p[3] = y1, p[4] = y0, p[5] = y2; break;
        case 16: p[0] = x0, p[1] = x1, p[2] = x2, p[3] = y0, p[4] = y1, p[5] = y2; break;
        case 32: p[0] = x0, p[1] = x1, p[2] = y0, p[3] = x2, p[4] = y1, p[5] = y2; break;
        case 64: p[0] = x0, p[1] = y0, p[2] = x1, p[3] = x2, p[4] = y1, p[5] = y2; break;
        default: p[0] = x0, p[1] = y0, p[2] = x1, p[3] = y1, p[4] = x2, p[5] = y2; break;
        }
    } else {
        p[0] = x0, p[1] = y0, p[2] = x1, p[3] = y1, p[4] = x2, p[5] = y2;
    }
    return p[0] | p[1] << 1 | p[2] << 2 | p[3] << 3 | p[4] << 4 | p[5] << 5;
}

typedef struct Macro {
    uint32_t banks, bank_bits, bank_w, bank_h, aspect, split;
} Macro;

static Macro macro_of(uint32_t m, int micro, uint32_t bits) {
    const uint32_t tile_bytes_1x = bits * 64 / 8;
    const uint32_t sample_split = (m == 10 || m == 14) ? 2 : 1;
    uint32_t split;
    if (micro == MICRO_DEPTH) {
        split = m == 0 ? 64 : m == 1 ? 128 : m == 2 ? 256 : m == 3 ? 512 : 1024;
    } else {
        split = sample_split * tile_bytes_1x > 256 ? sample_split * tile_bytes_1x : 256;
    }
    if (split > 1024) {
        split = 1024;
    }
    const uint32_t tile_bytes = split < tile_bytes_1x ? split : tile_bytes_1x;
    uint32_t idx = 0;
    while ((64u << (idx + 1)) <= tile_bytes) {
        idx++;
    }
    static const Macro modes[] = {
        {16, 4, 1, 4, 4, 0},
        {16, 4, 1, 2, 2, 0},
        {16, 4, 1, 1, 2, 0},
        {16, 4, 1, 1, 2, 0},
        {8, 3, 1, 1, 1, 0},
    };
    Macro r = modes[idx < 4 ? idx : 4];
    r.split = split;
    return r;
}

#define PIPES 8
#define PIPE_BITS 3
#define INTERLEAVE_BITS 8

static uint32_t pipe_of(uint32_t x, uint32_t y) {
    const uint32_t tx = x / 8, ty = y / 8;
    const uint32_t x3 = bit(tx, 0), x4 = bit(tx, 1), x5 = bit(tx, 2), y3 = bit(ty, 0), y4 = bit(ty, 1), y5 = bit(ty, 2);
    return (x3 ^ y3 ^ x4) | (x4 ^ y4) << 1 | (x5 ^ y5) << 2;
}

static uint32_t bank_of(const Macro* m, uint32_t x, uint32_t y, uint32_t split_slice) {
    const uint32_t tx = x / 8 / (m->bank_w * PIPES), ty = y / 8 / m->bank_h;
    const uint32_t x3 = bit(tx, 0), x4 = bit(tx, 1), x5 = bit(tx, 2), x6 = bit(tx, 3);
    const uint32_t y3 = bit(ty, 0), y4 = bit(ty, 1), y5 = bit(ty, 2), y6 = bit(ty, 3);
    uint32_t b;
    if (m->banks == 16) {
        b = (x3 ^ y6) | (x4 ^ y5 ^ y6) << 1 | (x5 ^ y4) << 2 | (x6 ^ y3) << 3;
    } else if (m->banks == 8) {
        b = (x3 ^ y5) | (x4 ^ y4 ^ y5) << 1 | (x5 ^ y3) << 2;
    } else if (m->banks == 4) {
        b = (x3 ^ y4) | (x4 ^ y3) << 1;
    } else {
        b = x3 ^ y3;
    }
    b ^= ((m->banks / 2) + 1) * split_slice;
    return b & (m->banks - 1);
}

static void macro_dims(const Macro* m, uint32_t* tw, uint32_t* th) {
    *tw = 8 * m->bank_w * PIPES * m->aspect;
    *th = 8 * m->bank_h * m->banks / m->aspect;
}

size_t tile_size(uint32_t mode, uint32_t pitch, uint32_t height, uint32_t bpp) {
    const Mode md = mode_of(mode);
    if (!tile_is_tiled(mode) || !md.known) {
        return (size_t)pitch * height * bpp;
    }
    if (!md.macro) {
        return (size_t)((pitch + 7) & ~7u) * ((height + 7) & ~7u) * bpp;
    }
    const Macro m = macro_of(mode, md.micro, bpp * 8);
    uint32_t tw, th;
    macro_dims(&m, &tw, &th);
    return (size_t)((pitch + tw - 1) / tw * tw) * ((height + th - 1) / th * th) * bpp;
}

int tile_detile(uint32_t mode, const uint8_t* in, uint8_t* out, uint32_t width, uint32_t height, uint32_t pitch,
                uint32_t bpp) {
    const Mode md = mode_of(mode);
    if (!md.known) {
        return 0;
    }
    const uint32_t bits = bpp * 8;
    if (!md.macro) {
        const uint32_t tiles_per_row = (pitch + 7) / 8;
        for (uint32_t y = 0; y < height; y++) {
            for (uint32_t x = 0; x < width; x++) {
                const size_t tile = ((size_t)(y / 8) * tiles_per_row + x / 8) * 64 * bpp;
                const size_t off = tile + (size_t)pixel_index(md.micro, x, y, bits) * bpp;
                memcpy(out + ((size_t)y * width + x) * bpp, in + off, bpp);
            }
        }
        return 1;
    }
    const Macro m = macro_of(mode, md.micro, bits);
    uint32_t tw, th;
    macro_dims(&m, &tw, &th);
    const uint32_t padded_pitch = (pitch + tw - 1) / tw * tw;
    const uint32_t micro_bytes_full = 64 * bpp;
    const uint32_t micro_bytes = micro_bytes_full > m.split ? m.split : micro_bytes_full;
    const uint32_t macro_bytes = micro_bytes * (tw / 8) * (th / 8) / (PIPES * m.banks);
    const uint32_t per_row = padded_pitch / tw;
    const uint32_t padded_h = (height + th - 1) / th * th;
    const uint32_t slice_bytes = per_row * (padded_h / th) * macro_bytes;
    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < width; x++) {
            uint32_t elem = pixel_index(md.micro, x, y, bits) * bpp;
            uint32_t split_slice = 0;
            if (micro_bytes_full > m.split) {
                split_slice = elem / m.split;
                elem %= m.split;
            }
            const uint32_t macro_off = ((y / th) * per_row + x / tw) * macro_bytes;
            const uint32_t tile_row = (y / 8) % m.bank_h, tile_col = ((x / 8) / PIPES) % m.bank_w;
            const uint32_t total = slice_bytes * split_slice + macro_off + elem + (tile_row * m.bank_w + tile_col) * micro_bytes;
            const uint32_t pipe = pipe_of(x, y), bank = bank_of(&m, x, y, split_slice);
            const uint64_t addr = (total & ((1u << INTERLEAVE_BITS) - 1)) | (uint64_t)pipe << INTERLEAVE_BITS |
                                  (uint64_t)bank << (INTERLEAVE_BITS + PIPE_BITS) |
                                  (uint64_t)(total >> INTERLEAVE_BITS) << (INTERLEAVE_BITS + PIPE_BITS + m.bank_bits);
            memcpy(out + ((size_t)y * width + x) * bpp, in + addr, bpp);
        }
    }
    return 1;
}
