#pragma once

#include <stdint.h>

typedef struct GpuVertex {
    float pos[4];
    float param[4];
} GpuVertex;

enum {
    PS_NONE,
    PS_ZERO,
    PS_TEX_MUL,
    PS_TEX_XFORM,
    PS_CONST,
    PS_COPY,
    PS_TEX_COORD,
    PS_COUNT
};

typedef struct GpuImage {
    uint64_t addr;
    uint32_t width, height, pitch;
    uint32_t dfmt, nfmt, tiling;
    uint32_t swizzle;
    uint32_t sampler[4];
} GpuImage;

typedef struct GpuTarget {
    uint64_t addr;
    uint32_t width, height;
    uint32_t format, number_type, comp_swap, tiling;
} GpuTarget;

typedef struct GpuDrawState {
    int ps;
    float k[12];
    GpuImage image;
    int has_image;
    GpuTarget target;
    int vp_x, vp_y, vp_w, vp_h, flip_y;
    int sc_x0, sc_y0, sc_x1, sc_y1;
    uint32_t blend;
    float blend_color[4];
    uint32_t write_mask;
} GpuDrawState;

void gb_init(void);
void gb_draw(const GpuDrawState* s, const GpuVertex* v, uint32_t count);

void gb_target_flush(uint64_t addr, uint64_t size);
void gb_present(const GpuTarget* t, int window_w, int window_h);
int gb_read(const GpuTarget* t, uint8_t* rgba);
void gb_new_frame(void);
