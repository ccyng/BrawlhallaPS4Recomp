#include <stdlib.h>
#include <string.h>

#include <SDL.h>

#include "gpu.h"
#include "gpu_backend.h"
#include "hle/hle.h"
#include "runtime.h"

static int trace_pm4;
static int trace_frame = -1, flip_count;

#define CTX_REGS 0x400
#define SH_REGS 0x400
#define UCFG_REGS 0x400

static uint32_t ctx[CTX_REGS], sh[SH_REGS], ucfg[UCFG_REGS];

enum {
    PA_SC_SCREEN_SCISSOR_TL = 0x0C, PA_SC_SCREEN_SCISSOR_BR = 0x0D,
    PA_SC_WINDOW_OFFSET = 0x80, PA_SC_WINDOW_SCISSOR_TL = 0x81, PA_SC_WINDOW_SCISSOR_BR = 0x82,
    CB_TARGET_MASK = 0x8E,
    PA_SC_GENERIC_SCISSOR_TL = 0x90, PA_SC_GENERIC_SCISSOR_BR = 0x91,
    PA_SC_VPORT_SCISSOR_0_TL = 0x94, PA_SC_VPORT_SCISSOR_0_BR = 0x95,
    VGT_INDX_OFFSET = 0x102,
    CB_BLEND_RED = 0x105,
    PA_CL_VPORT_XSCALE = 0x10F, PA_CL_VPORT_XOFFSET, PA_CL_VPORT_YSCALE, PA_CL_VPORT_YOFFSET,
    CB_BLEND0_CONTROL = 0x1E0,
    CB_COLOR_CONTROL = 0x202,
    PA_CL_VTE_CNTL = 0x206,
    CB_COLOR0_BASE = 0x318, CB_COLOR0_PITCH, CB_COLOR0_SLICE, CB_COLOR0_VIEW, CB_COLOR0_INFO, CB_COLOR0_ATTRIB,
    SPI_SHADER_PGM_LO_PS = 0x08, SPI_SHADER_USER_DATA_PS_0 = 0x0C,
    SPI_SHADER_PGM_LO_VS = 0x48, SPI_SHADER_USER_DATA_VS_0 = 0x4C,
    VGT_PRIMITIVE_TYPE = 0x242, VGT_INDEX_TYPE = 0x243,
};

enum { PRIM_TRILIST = 4, PRIM_TRIFAN = 5, PRIM_TRISTRIP = 6, PRIM_RECTLIST = 0x11, PRIM_QUADLIST = 0x13 };

static uint64_t index_base;
static uint32_t index_size = 2;

static uint32_t ce_ram[0xC000 / 4];

enum { VS_UNKNOWN, VS_SPRITE, VS_FULLSCREEN };

typedef struct ShaderInfo {
    uint64_t addr;
    uint64_t hash;
    int kind;
} ShaderInfo;

#define SHADER_CACHE 256
static ShaderInfo shaders[SHADER_CACHE];
static int shader_count;
static uint64_t embedded[3];

void gpu_register_embedded(uint64_t vs, uint64_t ps0, uint64_t ps1) {
    embedded[0] = vs;
    embedded[1] = ps0;
    embedded[2] = ps1;
}

static uint64_t shader_hash(uint64_t addr) {
    const uint8_t* p = G(addr);
    for (uint32_t i = 0; i < 0x10000; i += 4) {
        if (!memcmp(p + i, "OrbShdr", 7)) {
            uint32_t h0, h1;
            memcpy(&h0, p + i + 0x10, 4);
            memcpy(&h1, p + i + 0x14, 4);
            return (uint64_t)h1 << 32 | h0;
        }
    }
    return 0;
}

static int shader_kind(uint64_t addr, int is_ps) {
    for (int i = 0; i < shader_count; i++) {
        if (shaders[i].addr == addr) {
            return shaders[i].kind;
        }
    }
    int kind;
    uint64_t hash = 0;
    if (addr == embedded[0]) {
        kind = VS_FULLSCREEN;
    } else if (addr == embedded[1] || addr == embedded[2]) {
        kind = PS_ZERO;
    } else {
        hash = shader_hash(addr);
        switch (hash) {
        case 0x156f7ee4: kind = VS_SPRITE; break;
        case 0xd074855b: kind = VS_FULLSCREEN; break;
        case 0xc9a50004: kind = PS_TEX_MUL; break;
        case 0xba5641a0: kind = PS_TEX_XFORM; break;
        case 0xa635d4df: kind = PS_CONST; break;
        case 0x5b09e8b0: kind = PS_COPY; break;
        case 0x48ead51b: kind = PS_TEX_COORD; break;
        default: kind = is_ps ? PS_COUNT : VS_UNKNOWN; break;
        }
    }
    LOG("gpu: %s shader at %#llx, hash %016llx: %s", is_ps ? "pixel" : "vertex", (unsigned long long)addr,
        (unsigned long long)hash, (is_ps ? kind == PS_COUNT : kind == VS_UNKNOWN) ? "UNKNOWN" : "known");
    if (shader_count < SHADER_CACHE) {
        shaders[shader_count].addr = addr;
        shaders[shader_count].hash = hash;
        shaders[shader_count++].kind = kind;
    }
    return kind;
}

static uint64_t vsharp_base(const uint32_t* v) {
    return v[0] | (uint64_t)(v[1] & 0xFF) << 32;
}

static void decode_image(const uint32_t* t, const uint32_t* s, GpuImage* img) {
    img->addr = (t[0] | (uint64_t)(t[1] & 0x3F) << 32) << 8;
    img->dfmt = (t[1] >> 20) & 0x3F;
    img->nfmt = (t[1] >> 26) & 0xF;
    img->width = (t[2] & 0x3FFF) + 1;
    img->height = ((t[2] >> 14) & 0x3FFF) + 1;
    img->swizzle = t[3] & 0xFFF;
    img->tiling = (t[3] >> 20) & 0x1F;
    img->pitch = ((t[4] >> 13) & 0x3FFF) + 1;
    memcpy(img->sampler, s, 16);
}

static void read_target(GpuTarget* t) {
    t->addr = (uint64_t)ctx[CB_COLOR0_BASE] << 8;
    const uint32_t pitch = ((ctx[CB_COLOR0_PITCH] & 0x7FF) + 1) * 8;
    const uint32_t slice = ((ctx[CB_COLOR0_SLICE] & 0x3FFFFF) + 1) * 64;
    t->width = pitch;
    t->height = slice / pitch;
    t->format = (ctx[CB_COLOR0_INFO] >> 2) & 0x1F;
    t->number_type = (ctx[CB_COLOR0_INFO] >> 8) & 7;
    t->comp_swap = (ctx[CB_COLOR0_INFO] >> 11) & 3;
    t->tiling = ctx[CB_COLOR0_ATTRIB] & 0x1F;
}

typedef struct FetchAttr {
    int vgpr, comps;
    uint32_t vsharp[4];
    uint32_t offset;
    int dfmt, nfmt;
} FetchAttr;

static int parse_fetch(uint64_t code, const uint32_t* user, FetchAttr* out, int max) {
    uint32_t sgpr[104] = {0};
    memcpy(sgpr, user, 16 * 4);
    const uint32_t* w = G(code);
    int n = 0;
    for (int i = 0; i < 256;) {
        const uint32_t x = w[i];
        if (x >> 27 == 0x18) {
            const uint32_t op = x >> 22 & 0x1F, d = x >> 15 & 0x7F, base = (x >> 9 & 0x3F) * 2;
            const uint32_t off = (x >> 8 & 1) ? (x & 0xFF) * 4 : sgpr[x & 0xFF];
            const int count = op == 0 ? 1 : op == 1 ? 2 : op == 2 ? 4 : op == 3 ? 8 : op == 4 ? 16 : 0;
            const uint64_t a = (sgpr[base] | (uint64_t)(sgpr[base + 1] & 0xFFFF) << 32) + off;
            for (int k = 0; k < count && d + k < 104; k++) {
                sgpr[d + k] = ((const uint32_t*)G(a))[k];
            }
            i++;
        } else if (x >> 26 == 0x38 || x >> 26 == 0x3A) {
            const uint32_t y = w[i + 1];
            const int mt = x >> 26 == 0x3A;
            const uint32_t op = mt ? (x >> 16 & 7) : (x >> 18 & 0x7F);
            if (op <= 3 && n < max) {
                FetchAttr* f = &out[n++];
                f->vgpr = y >> 8 & 0xFF;
                f->comps = (int)op + 1;
                memcpy(f->vsharp, &sgpr[(y >> 16 & 0x1F) * 4], 16);
                f->offset = x & 0xFFF;
                f->dfmt = mt ? (int)(x >> 19 & 0xF) : -1;
                f->nfmt = mt ? (int)(x >> 23 & 7) : -1;
            }
            i += 2;
        } else if (x >> 23 == 0x17D && (x >> 8 & 0xFF) == 0x20) {
            break;
        } else if (x >> 26 == 0x34 || x >> 26 == 0x32 || x >> 26 == 0x36 || x >> 26 == 0x3C || x >> 26 == 0x3E) {
            i += 2;
        } else {
            i++;
        }
    }
    return n;
}

static float unpack(uint32_t v, int bits, int nfmt) {
    switch (nfmt) {
    case 0: return (float)v / (float)((1ull << bits) - 1);
    case 1: return (float)((int32_t)(v << (32 - bits)) >> (32 - bits)) / (float)((1 << (bits - 1)) - 1);
    case 2: case 4: return (float)v;
    case 3: case 5: return (float)((int32_t)(v << (32 - bits)) >> (32 - bits));
    default: return 0;
    }
}

static float half_to_float(uint16_t h) {
    const uint32_t s = (uint32_t)(h >> 15) << 31, e = h >> 10 & 0x1F, m = h & 0x3FF;
    uint32_t f;
    if (e == 0) {
        if (!m) {
            f = s;
        } else {
            float v = (float)m / 16777216.0f;
            return s ? -v : v;
        }
    } else if (e == 31) {
        f = s | 0x7F800000u | m << 13;
    } else {
        f = s | (e + 112) << 23 | m << 13;
    }
    float r;
    memcpy(&r, &f, 4);
    return r;
}

static void fetch(const FetchAttr* f, uint32_t index, float* out) {
    const uint32_t* v = f->vsharp;
    const uint32_t stride = (v[1] >> 16) & 0x3FFF;
    const int dfmt = f->dfmt >= 0 ? f->dfmt : (int)(v[3] >> 15 & 0xF);
    const int nfmt = f->nfmt >= 0 ? f->nfmt : (int)(v[3] >> 12 & 7);
    if (index >= v[2] && stride) {
        out[0] = out[1] = out[2] = out[3] = 0;
        return;
    }
    const uint8_t* p = G(vsharp_base(v) + (uint64_t)index * stride + f->offset);
    float c[4] = {0, 0, 0, 1};
    switch (dfmt) {
    case 1: for (int i = 0; i < 1; i++) c[i] = unpack(p[i], 8, nfmt); break;
    case 3: for (int i = 0; i < 2; i++) c[i] = unpack(p[i], 8, nfmt); break;
    case 10: for (int i = 0; i < 4; i++) c[i] = unpack(p[i], 8, nfmt); break;
    case 2: case 5: case 12: {
        const int n = dfmt == 2 ? 1 : dfmt == 5 ? 2 : 4;
        for (int i = 0; i < n; i++) {
            uint16_t h;
            memcpy(&h, p + 2 * i, 2);
            c[i] = nfmt == 7 ? half_to_float(h) : unpack(h, 16, nfmt);
        }
        break;
    }
    case 4: case 11: case 13: case 14: {
        const int n = dfmt == 4 ? 1 : dfmt == 11 ? 2 : dfmt == 13 ? 3 : 4;
        for (int i = 0; i < n; i++) {
            uint32_t u;
            memcpy(&u, p + 4 * i, 4);
            if (nfmt == 7) {
                memcpy(&c[i], &u, 4);
            } else {
                c[i] = nfmt == 4 ? (float)u : nfmt == 5 ? (float)(int32_t)u : 0;
            }
        }
        break;
    }
    default: {
        static int warned[16];
        if (!warned[dfmt & 15]) {
            warned[dfmt & 15] = 1;
            LOG("gpu: vertex format %d/%d not handled", dfmt, nfmt);
        }
        break;
    }
    }
    const float sel[8] = {0, 1, 0, 0, c[0], c[1], c[2], c[3]};
    for (int i = 0; i < 4; i++) {
        out[i] = sel[(v[3] >> (3 * i)) & 7];
    }
}

#define MAX_VERTS 65536
static GpuVertex vs_out[MAX_VERTS];
static GpuVertex tris[MAX_VERTS * 3];

static uint32_t index_at(uint64_t base, uint32_t i, int indexed) {
    if (!indexed) {
        return i;
    }
    return index_size == 4 ? ((const uint32_t*)G(base))[i] : ((const uint16_t*)G(base))[i];
}

static const float* buffer_floats(const uint32_t* vsharp) {
    return G(vsharp_base(vsharp));
}

static void run_vs(int kind, const uint32_t* user, uint32_t index, const FetchAttr* fa, int nfa, GpuVertex* o) {
    float vgpr[32] = {0};
    for (int i = 0; i < nfa; i++) {
        float v[4];
        fetch(&fa[i], index, v);
        for (int k = 0; k < fa[i].comps && fa[i].vgpr + k < 32; k++) {
            vgpr[fa[i].vgpr + k] = v[k];
        }
    }
    switch (kind) {
    case VS_SPRITE: {
        const float* k = buffer_floats(user + 4);
        const float x = vgpr[4], y = vgpr[5];
        for (int i = 0; i < 4; i++) {
            o->pos[i] = k[12 + i] + k[i] * x + k[4 + i] * y;
        }
        o->param[0] = vgpr[8];
        o->param[1] = vgpr[9];
        o->param[2] = o->param[3] = 0;
        break;
    }
    case VS_FULLSCREEN: {
        const int x = (int)(index & 1) * 2 - 1, y = (int)(index & ~1u) - 1;
        o->pos[0] = (float)x;
        o->pos[1] = (float)y;
        o->pos[2] = 0;
        o->pos[3] = 1;
        o->param[0] = o->param[1] = o->param[2] = o->param[3] = 0;
        break;
    }
    default:
        memset(o, 0, sizeof *o);
        break;
    }
}

static void lerp_rect(const GpuVertex* a, const GpuVertex* b, const GpuVertex* c, GpuVertex* d) {
    for (int i = 0; i < 4; i++) {
        d->pos[i] = b->pos[i] + c->pos[i] - a->pos[i];
        d->param[i] = b->param[i] + c->param[i] - a->param[i];
    }
}

static void draw(uint32_t count, int indexed, uint64_t ibase) {
    if (!count || count > MAX_VERTS) {
        return;
    }
    const uint64_t vs_addr = ((uint64_t)sh[SPI_SHADER_PGM_LO_VS] | (uint64_t)sh[SPI_SHADER_PGM_LO_VS + 1] << 32) << 8;
    const uint64_t ps_addr = ((uint64_t)sh[SPI_SHADER_PGM_LO_PS] | (uint64_t)sh[SPI_SHADER_PGM_LO_PS + 1] << 32) << 8;
    const int vs = vs_addr ? shader_kind(vs_addr, 0) : VS_UNKNOWN;
    const int ps = ps_addr ? shader_kind(ps_addr, 1) : PS_NONE;
    if (vs == VS_UNKNOWN || ps == PS_COUNT || ps == PS_NONE) {
        return;
    }
    const uint32_t* vs_user = &sh[SPI_SHADER_USER_DATA_VS_0];
    const uint32_t* ps_user = &sh[SPI_SHADER_USER_DATA_PS_0];

    FetchAttr fa[16];
    int nfa = 0;
    if (vs == VS_SPRITE) {
        nfa = parse_fetch(vs_user[0] | (uint64_t)(vs_user[1] & 0xFFFF) << 32, vs_user, fa, 16);
    }
    const uint32_t offset = ctx[VGT_INDX_OFFSET];
    for (uint32_t i = 0; i < count; i++) {
        run_vs(vs, vs_user, index_at(ibase, i, indexed) + offset, fa, nfa, &vs_out[i]);
    }

    uint32_t n = 0;
    const uint32_t prim = ucfg[VGT_PRIMITIVE_TYPE];
    switch (prim) {
    case PRIM_TRILIST:
        memcpy(tris, vs_out, sizeof *tris * (count / 3 * 3));
        n = count / 3 * 3;
        break;
    case PRIM_TRISTRIP:
        for (uint32_t i = 2; i < count; i++) {
            const int odd = i & 1;
            tris[n++] = vs_out[i - 2 + odd];
            tris[n++] = vs_out[i - 1 - odd];
            tris[n++] = vs_out[i];
        }
        break;
    case PRIM_TRIFAN:
        for (uint32_t i = 2; i < count; i++) {
            tris[n++] = vs_out[0];
            tris[n++] = vs_out[i - 1];
            tris[n++] = vs_out[i];
        }
        break;
    case PRIM_RECTLIST:
        for (uint32_t i = 0; i + 3 <= count; i += 3) {
            GpuVertex d;
            lerp_rect(&vs_out[i], &vs_out[i + 1], &vs_out[i + 2], &d);
            tris[n++] = vs_out[i];
            tris[n++] = vs_out[i + 1];
            tris[n++] = vs_out[i + 2];
            tris[n++] = vs_out[i + 1];
            tris[n++] = d;
            tris[n++] = vs_out[i + 2];
        }
        break;
    case PRIM_QUADLIST:
        for (uint32_t i = 0; i + 4 <= count; i += 4) {
            tris[n++] = vs_out[i];
            tris[n++] = vs_out[i + 1];
            tris[n++] = vs_out[i + 2];
            tris[n++] = vs_out[i];
            tris[n++] = vs_out[i + 2];
            tris[n++] = vs_out[i + 3];
        }
        break;
    default: {
        static uint32_t warned;
        if (warned != prim + 1) {
            warned = prim + 1;
            LOG("gpu: primitive type %#x not handled", prim);
        }
        return;
    }
    }

    GpuDrawState s;
    memset(&s, 0, sizeof s);
    s.ps = ps;
    switch (ps) {
    case PS_TEX_MUL:
    case PS_TEX_XFORM:
    case PS_TEX_COORD:
    case PS_COPY:
        decode_image(ps_user, ps_user + 8, &s.image);
        s.has_image = 1;
        if (ps != PS_COPY) {
            memcpy(s.k, buffer_floats(ps_user + 12), (ps == PS_TEX_XFORM ? 9 : ps == PS_TEX_COORD ? 8 : 1) * 4);
        }
        break;
    case PS_CONST:
        memcpy(s.k, buffer_floats(ps_user), 16);
        break;
    default:
        break;
    }
    read_target(&s.target);
    if (!s.target.addr) {
        return;
    }

    float xs, xo, ys, yo;
    memcpy(&xs, &ctx[PA_CL_VPORT_XSCALE], 4);
    memcpy(&xo, &ctx[PA_CL_VPORT_XOFFSET], 4);
    memcpy(&ys, &ctx[PA_CL_VPORT_YSCALE], 4);
    memcpy(&yo, &ctx[PA_CL_VPORT_YOFFSET], 4);
    if (!(ctx[PA_CL_VTE_CNTL] & 1)) {
        xs = 1;
        xo = 0;
    }
    if (!(ctx[PA_CL_VTE_CNTL] & 4)) {
        ys = 1;
        yo = 0;
    }
    s.flip_y = ys < 0;
    const float ax = xs < 0 ? -xs : xs, ay = ys < 0 ? -ys : ys;
    s.vp_x = (int)(xo - ax);
    s.vp_y = (int)(yo - ay);
    s.vp_w = (int)(2 * ax);
    s.vp_h = (int)(2 * ay);

    int x0 = 0, y0 = 0, x1 = 16384, y1 = 16384;
    const uint32_t rects[4][2] = {{PA_SC_SCREEN_SCISSOR_TL, PA_SC_SCREEN_SCISSOR_BR},
                                  {PA_SC_WINDOW_SCISSOR_TL, PA_SC_WINDOW_SCISSOR_BR},
                                  {PA_SC_GENERIC_SCISSOR_TL, PA_SC_GENERIC_SCISSOR_BR},
                                  {PA_SC_VPORT_SCISSOR_0_TL, PA_SC_VPORT_SCISSOR_0_BR}};
    for (int i = 0; i < 4; i++) {
        const uint32_t tl = ctx[rects[i][0]], br = ctx[rects[i][1]];
        const int mask = i == 0 ? 0xFFFF : 0x7FFF;
        const int rx0 = (int)(tl & mask), ry0 = (int)(tl >> 16 & mask), rx1 = (int)(br & mask), ry1 = (int)(br >> 16 & mask);
        if (rx1 <= rx0 && ry1 <= ry0 && !rx1 && !ry1) {
            continue;
        }
        x0 = rx0 > x0 ? rx0 : x0;
        y0 = ry0 > y0 ? ry0 : y0;
        x1 = rx1 < x1 ? rx1 : x1;
        y1 = ry1 < y1 ? ry1 : y1;
    }
    s.sc_x0 = x0;
    s.sc_y0 = y0;
    s.sc_x1 = x1;
    s.sc_y1 = y1;

    s.blend = ctx[CB_BLEND0_CONTROL];
    memcpy(s.blend_color, &ctx[CB_BLEND_RED], 16);
    s.write_mask = ctx[CB_TARGET_MASK] & 0xF;
    if (((ctx[CB_COLOR_CONTROL] >> 4) & 7) == 0) {
        s.write_mask = 0;
    }
    if (ps == PS_ZERO && !s.write_mask) {
        return;
    }
    if (trace_frame >= 0 && flip_count == trace_frame) {
        LOG("draw vs %d ps %d prim %#x n %u -> target %#llx %ux%u fmt %u | vp %d,%d %dx%d flip %d | sc %d,%d-%d,%d | "
            "blend %#x mask %#x | k %g %g %g %g / %g %g %g %g / %g",
            vs, ps, prim, count, (unsigned long long)s.target.addr, s.target.width, s.target.height, s.target.format,
            s.vp_x, s.vp_y, s.vp_w, s.vp_h, s.flip_y, s.sc_x0, s.sc_y0, s.sc_x1, s.sc_y1, s.blend, s.write_mask,
            s.k[0], s.k[1], s.k[2], s.k[3], s.k[4], s.k[5], s.k[6], s.k[7], s.k[8]);
        if (s.has_image) {
            LOG("  image %#llx %ux%u pitch %u fmt %u/%u tiling %u swizzle %#x sampler %08x %08x %08x %08x",
                (unsigned long long)s.image.addr, s.image.width, s.image.height, s.image.pitch, s.image.dfmt,
                s.image.nfmt, s.image.tiling, s.image.swizzle, s.image.sampler[0], s.image.sampler[1],
                s.image.sampler[2], s.image.sampler[3]);
        }
        for (uint32_t i = 0; i < n && i < 3; i++) {
            LOG("  v%u pos %g %g %g %g param %g %g", i, tris[i].pos[0], tris[i].pos[1], tris[i].pos[2], tris[i].pos[3],
                tris[i].param[0], tris[i].param[1]);
        }
    }
    gb_draw(&s, tris, n);
}

static void clear_state(void) {
    memset(ctx, 0, sizeof ctx);
    ctx[CB_TARGET_MASK] = 0xFFFFFFFF;
    ctx[0x8F] = 0xFFFFFFFF;
    ctx[PA_SC_SCREEN_SCISSOR_BR] = 0x40004000;
    ctx[PA_SC_WINDOW_SCISSOR_BR] = 0x40004000;
    ctx[PA_SC_GENERIC_SCISSOR_BR] = 0x40004000;
    ctx[PA_SC_VPORT_SCISSOR_0_BR] = 0x40004000;
    ctx[CB_COLOR_CONTROL] = 0x00CC0010;
}

static void write_fence(uint64_t addr, uint32_t data_sel, uint32_t lo, uint32_t hi) {
    if (trace_pm4) {
        LOG("fence %#llx sel %u = %#x", (unsigned long long)addr, data_sel, lo);
    }
    if (!addr) {
        return;
    }
    switch (data_sel) {
    case 1: *(uint32_t*)G(addr) = lo; break;
    case 2: *(uint64_t*)G(addr) = lo | (uint64_t)hi << 32; break;
    case 3: case 4: *(uint64_t*)G(addr) = SDL_GetPerformanceCounter(); break;
    default: break;
    }
}

typedef struct Stream {
    const uint32_t *at, *end;
} Stream;

static void run_stream(Stream* s, Stream* ce, int is_ce);

static int run_packet(const uint32_t* cmd, uint32_t count, uint32_t op, Stream* ce, int is_ce) {
    const uint32_t* b = cmd + 1;
    const uint32_t nb = count + 1;
    if (trace_pm4) {
        LOG("%s pm4 %#x n %u: %08x %08x %08x %08x", is_ce ? "ce" : "de", op, nb, b[0], nb > 1 ? b[1] : 0,
            nb > 2 ? b[2] : 0, nb > 3 ? b[3] : 0);
    }
    switch (op) {
    case PM4_NOP:
        if (nb >= 4 && (b[0] == 0x68750778u || b[0] == 0x68750781u)) {
            write_fence((b[1] & ~3u) | (uint64_t)b[2] << 32, 1, b[3], 0);
        } else if (nb >= 2 && (b[0] >> 16) == 0xC01E) {
            for (uint32_t i = 1; i < nb && (b[0] & 0x3FF) + i - 1 < CTX_REGS; i++) {
                ctx[(b[0] & 0x3FF) + i - 1] = b[i];
            }
        }
        break;
    case PM4_CLEAR_STATE:
        clear_state();
        break;
    case PM4_SET_CONTEXT_REG:
        for (uint32_t i = 1; i < nb && (b[0] & 0xFFFF) + i - 1 < CTX_REGS; i++) {
            ctx[(b[0] & 0xFFFF) + i - 1] = b[i];
        }
        break;
    case PM4_SET_SH_REG:
        for (uint32_t i = 1; i < nb && (b[0] & 0xFFFF) + i - 1 < SH_REGS; i++) {
            sh[(b[0] & 0xFFFF) + i - 1] = b[i];
        }
        break;
    case PM4_SET_UCONFIG_REG:
        for (uint32_t i = 1; i < nb && (b[0] & 0xFFFF) + i - 1 < UCFG_REGS; i++) {
            ucfg[(b[0] & 0xFFFF) + i - 1] = b[i];
        }
        break;
    case PM4_INDEX_TYPE:
        index_size = (b[0] & 3) == 1 ? 4 : 2;
        break;
    case PM4_INDEX_BASE:
        index_base = b[0] | (uint64_t)(b[1] & 0xFFFF) << 32;
        break;
    case PM4_DRAW_INDEX_2:
        index_size = (ucfg[VGT_INDEX_TYPE] & 3) == 1 ? 4 : index_size;
        draw(b[3], 1, b[1] | (uint64_t)(b[2] & 0xFFFF) << 32);
        break;
    case PM4_DRAW_INDEX_OFFSET_2:
        draw(b[2], 1, index_base + (uint64_t)b[1] * index_size);
        break;
    case PM4_DRAW_INDEX_AUTO:
        draw(b[0], 0, 0);
        break;
    case PM4_DISPATCH_DIRECT: {
        static int warned;
        if (!warned) {
            warned = 1;
            LOG("gpu: compute dispatches are not run");
        }
        break;
    }
    case PM4_INDIRECT_BUFFER:
    case PM4_INDIRECT_BUFFER_CONST: {
        Stream sub = {G(b[0] | (uint64_t)(b[1] & 0xFFFF) << 32), NULL};
        sub.end = sub.at + (b[2] & 0xFFFFF);
        run_stream(&sub, ce, is_ce);
        break;
    }
    case PM4_EVENT_WRITE_EOP:
        write_fence(b[1] | (uint64_t)(b[2] & 0xFFFF) << 32, b[2] >> 29, b[3], b[4]);
        break;
    case PM4_EVENT_WRITE_EOS:
        if (((b[2] >> 29) & 3) == 2) {
            write_fence(b[1] | (uint64_t)(b[2] & 0xFFFF) << 32, 1, b[3], 0);
        }
        break;
    case PM4_RELEASE_MEM:
        write_fence(b[2] | (uint64_t)b[3] << 32, b[1] >> 29, b[4], b[5]);
        break;
    case PM4_WRITE_DATA:
        if (((b[0] >> 8) & 0xF) == 5) {
            const uint64_t addr = b[1] | (uint64_t)b[2] << 32;
            if (addr && nb > 3) {
                gb_target_flush(addr, (nb - 3) * 4);
                memcpy(G(addr), b + 3, (nb - 3) * 4);
            }
        }
        break;
    case PM4_DMA_DATA: {
        const uint32_t dst_sel = (b[0] >> 20) & 3, src_sel = (b[0] >> 29) & 3;
        const uint64_t src = b[1] | (uint64_t)b[2] << 32, dst = b[3] | (uint64_t)b[4] << 32;
        const uint32_t n = b[5] & 0x1FFFFF, registers = (b[5] >> 26) & 3;
        if (dst && !registers && (dst_sel == 0 || dst_sel == 3)) {
            gb_target_flush(dst, n);
            if (src_sel == 2) {
                for (uint32_t i = 0; i + 4 <= n; i += 4) {
                    memcpy((uint8_t*)G(dst) + i, &b[1], 4);
                }
            } else if ((src_sel == 0 || src_sel == 3) && src) {
                gb_target_flush(src, n);
                memmove(G(dst), G(src), n);
            }
        }
        break;
    }
    case PM4_WRITE_CONST_RAM:
        for (uint32_t i = 1; i < nb && (b[0] & 0xFFFF) / 4 + i - 1 < sizeof ce_ram / 4; i++) {
            ce_ram[(b[0] & 0xFFFF) / 4 + i - 1] = b[i];
        }
        break;
    case PM4_DUMP_CONST_RAM: {
        const uint32_t off = b[0] & 0xFFFF, n = b[1] & 0x7FFF;
        const uint64_t addr = b[2] | (uint64_t)b[3] << 32;
        if (off / 4 + n <= sizeof ce_ram / 4) {
            memcpy(G(addr), &ce_ram[off / 4], n * 4);
        }
        break;
    }
    case 0x80: {
        const uint64_t addr = b[0] | (uint64_t)b[1] << 32;
        const uint32_t n = b[2] & 0x7FFF, off = b[3] & 0xFFFF;
        if (off / 4 + n <= sizeof ce_ram / 4) {
            memcpy(&ce_ram[off / 4], G(addr), n * 4);
        }
        break;
    }
    case PM4_INCREMENT_CE_COUNTER:
        if (is_ce) {
            return 0;
        }
        break;
    case PM4_WAIT_ON_CE_COUNTER:
        if (!is_ce && ce && ce->at) {
            run_stream(ce, NULL, 1);
        }
        break;
    default:
        break;
    }
    return 1;
}

static void run_stream(Stream* s, Stream* ce, int is_ce) {
    while (s->at < s->end) {
        const uint32_t* cmd = s->at;
        const uint32_t h = cmd[0], type = h >> 30;
        if (type == 2) {
            s->at++;
            continue;
        }
        const uint32_t count = (h >> 16) & 0x3FFF;
        s->at += count + 2;
        if (type == 3 && !run_packet(cmd, count, (h >> 8) & 0xFF, ce, is_ce)) {
            return;
        }
    }
}

static SDL_mutex* lock;
static SDL_cond* cond;
static const GpuSubmit* pending;
static int done_seq, flip_waiting, flip_shown_seq, flip_seq;

typedef struct DisplayBuffer {
    uint64_t addr;
    uint32_t width, height, pitch, format, tiling;
} DisplayBuffer;
static DisplayBuffer display[16];
static int shown_buffer = -1;

void gpu_set_display_buffers(int first, int count, const uint64_t* addrs, uint32_t width, uint32_t height,
                             uint32_t pitch, uint32_t format, uint32_t tiling) {
    for (int i = 0; i < count && first + i < 16; i++) {
        display[first + i] = (DisplayBuffer){addrs[i], width, height, pitch, format, tiling};
        LOG("gpu: display buffer %d at %#llx, %ux%u (pitch %u), format %#x, tiling %u", first + i,
            (unsigned long long)addrs[i], width, height, pitch, format, tiling);
    }
}

static uint64_t flip_equeue, flip_udata;
void gpu_set_flip_event(uint64_t equeue, uint64_t udata) {
    flip_equeue = equeue;
    flip_udata = udata;
}

void gpu_submit(const GpuSubmit* s) {
    SDL_LockMutex(lock);
    while (pending) {
        SDL_CondWait(cond, lock);
    }
    pending = s;
    const int seq = done_seq;
    SDL_CondBroadcast(cond);
    while (done_seq == seq) {
        SDL_CondWait(cond, lock);
    }
    if (s->flip) {
        const int want = flip_seq;
        while (flip_shown_seq < want) {
            SDL_CondWait(cond, lock);
        }
    }
    SDL_UnlockMutex(lock);
}

static void run_submit(const GpuSubmit* s) {
    for (uint32_t i = 0; i < s->count; i++) {
        Stream ce = {NULL, NULL};
        if (s->ccb && s->ccb[i] && s->ccb_size && s->ccb_size[i]) {
            ce.at = G(s->ccb[i]);
            ce.end = ce.at + s->ccb_size[i] / 4;
        }
        if (s->dcb && s->dcb[i]) {
            Stream de = {G(s->dcb[i]), NULL};
            de.end = de.at + s->dcb_size[i] / 4;
            run_stream(&de, &ce, 0);
        }
        if (ce.at) {
            run_stream(&ce, NULL, 1);
        }
    }
}

void gpu_init(void) {
    lock = SDL_CreateMutex();
    cond = SDL_CreateCond();
    trace_pm4 = getenv("BH_TRACE_PM4") != NULL;
    clear_state();
    if (getenv("BH_TRACE_DRAWS")) {
        trace_frame = atoi(getenv("BH_TRACE_DRAWS"));
    }
    gb_init();
}

int gpu_service(void) {
    SDL_LockMutex(lock);
    const GpuSubmit* s = pending;
    SDL_UnlockMutex(lock);
    if (s) {
        run_submit(s);
        SDL_LockMutex(lock);
        if (s->flip) {
            flip_count++;
            shown_buffer = s->flip_buffer;
            flip_seq++;
            flip_waiting = 1;
        }
        pending = NULL;
        done_seq++;
        SDL_CondBroadcast(cond);
        SDL_UnlockMutex(lock);
    }
    return flip_waiting;
}

static int display_target(GpuTarget* t) {
    if (shown_buffer < 0 || shown_buffer >= 16 || !display[shown_buffer].addr) {
        return 0;
    }
    const DisplayBuffer* d = &display[shown_buffer];
    memset(t, 0, sizeof *t);
    t->addr = d->addr;
    t->width = d->pitch;
    t->height = d->height;
    t->tiling = d->tiling;
    t->format = d->format;
    return 1;
}

void gpu_present(int w, int h) {
    GpuTarget t;
    if (display_target(&t)) {
        gb_present(&t, w, h);
    }
}

int gpu_read_frame(uint8_t** rgba, int* w, int* h) {
    GpuTarget t;
    if (!display_target(&t)) {
        return 0;
    }
    *rgba = malloc((size_t)t.width * t.height * 4);
    *w = (int)t.width;
    *h = (int)t.height;
    return gb_read(&t, *rgba);
}

void gpu_flip_shown(void) {
    SDL_LockMutex(lock);
    if (flip_waiting) {
        flip_waiting = 0;
        flip_shown_seq = flip_seq;
        gb_new_frame();
        SDL_CondBroadcast(cond);
    }
    SDL_UnlockMutex(lock);
    if (flip_equeue) {
        hle_equeue_trigger(flip_equeue, 0, -13  , flip_udata);
    }
}
