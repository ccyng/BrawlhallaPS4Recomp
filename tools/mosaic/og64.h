#pragma once

#include <stdint.h>
#include <string.h>
#include <math.h>
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#ifdef _WIN32
#include <intrin.h>
#endif
#else
#define SIMDE_ENABLE_NATIVE_ALIASES
#if defined(__vita__) && defined(OG_MATH_NEON)

#include <math_neon.h>
#define simde_math_sqrtf(v) sqrtf_neon(v)
#define simde_math_floorf(v) floorf_neon(v)
#define simde_math_ceilf(v) ceilf_neon(v)
#define simde_math_fabsf(v) fabsf_neon(v)
#endif
#include <simde/x86/avx2.h>
#include <simde/x86/sse4.2.h>
#endif
#ifndef _WIN32
#ifdef __SIZEOF_INT128__
static inline int64_t _mul128(int64_t a, int64_t b, int64_t* hi) {
    __int128 p = (__int128)a * b;
    *hi = (int64_t)(p >> 64);
    return (int64_t)p;
}
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi) {
    unsigned __int128 p = (unsigned __int128)a * b;
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
}
#else
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi) {
    const uint64_t al = (uint32_t)a, ah = a >> 32, bl = (uint32_t)b, bh = b >> 32;
    const uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    const uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    return (mid << 32) | (uint32_t)ll;
}
static inline int64_t _mul128(int64_t a, int64_t b, int64_t* hi) {
    uint64_t uhi;
    const uint64_t lo = _umul128((uint64_t)a, (uint64_t)b, &uhi);
    uhi -= (a < 0 ? (uint64_t)b : 0) + (b < 0 ? (uint64_t)a : 0);
    *hi = (int64_t)uhi;
    return (int64_t)lo;
}
#endif
#endif

#ifdef _WIN32
#define OG_EXPORT __declspec(dllexport)
#else
#define OG_EXPORT __attribute__((visibility("default")))
#endif

typedef struct OgCtx {
    uint64_t r[16];
    uint8_t cf, pf, af, zf, sf, of, df, _pad;
    uint32_t mxcsr;
    uint64_t fs_base;
    uint64_t host_rsp;
    uint64_t _pad2;
    __attribute__((aligned(32))) union {
        uint8_t b[32];
        uint16_t w[16];
        uint32_t d[8];
        uint64_t q[4];
        float f[8];
        double g[4];
    } y[16];
    __attribute__((aligned(16))) long double st[8];
    uint32_t ftop;
    uint16_t fcw, fsw;
} OgCtx;

enum { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };

typedef struct OgHost {
    void (*call_native)(OgCtx* c, uint64_t target);
    void (*call_dynamic)(OgCtx* c, uint64_t target);
    void (*unsupported)(OgCtx* c, uint64_t at);
    void (*jump_native)(OgCtx* c, uint64_t target);
    uint64_t resume;
    uint64_t image_base;
} OgHost;

extern const OgHost* og_host;
extern uint64_t og_base;
extern uint8_t og_off[];

typedef uint8_t og_u8u __attribute__((aligned(1), may_alias));
typedef uint16_t og_u16u __attribute__((aligned(1), may_alias));
typedef uint32_t og_u32u __attribute__((aligned(1), may_alias));
typedef uint64_t og_u64u __attribute__((aligned(1), may_alias));

typedef struct { uint8_t v; } __attribute__((packed, may_alias)) og_m8;
typedef struct { uint16_t v; } __attribute__((packed, may_alias)) og_m16;
typedef struct { uint32_t v; } __attribute__((packed, may_alias)) og_m32;
typedef struct { uint64_t v; } __attribute__((packed, may_alias)) og_m64;
#define M8(a) (((volatile og_m8*)(uintptr_t)(a))->v)
#define M16(a) (((volatile og_m16*)(uintptr_t)(a))->v)
#define M32(a) (((volatile og_m32*)(uintptr_t)(a))->v)
#define M64(a) (((volatile og_m64*)(uintptr_t)(a))->v)
typedef struct { float v; } __attribute__((packed, may_alias)) og_mf32;
typedef struct { double v; } __attribute__((packed, may_alias)) og_mf64;
#define M32F(a) (((volatile og_mf32*)(uintptr_t)(a))->v)
#define M64F(a) (((volatile og_mf64*)(uintptr_t)(a))->v)

static inline __m128 og_ld128(uint64_t a) { return _mm_loadu_ps((const float*)(uintptr_t)a); }
static inline void og_st128(uint64_t a, __m128 v) { _mm_storeu_ps((float*)(uintptr_t)a, v); }
static inline __m128 og_x(OgCtx* c, int i) { return _mm_load_ps(c->y[i].f); }
static inline void og_setx(OgCtx* c, int i, __m128 v) {
    _mm_store_ps(c->y[i].f, v);
    memset(&c->y[i].b[16], 0, 16);
}

void og_cmpxchg16b(OgCtx* c, uint64_t a);

static inline void og_cpuid(OgCtx* c) {
    const uint32_t leaf = (uint32_t)c->r[0];
    uint32_t a = 0, b = 0, cc = 0, d = 0;
    if (leaf == 0) {
        a = 0xD;
        b = 0x68747541;
        d = 0x69746E65;
        cc = 0x444D4163;
    } else if (leaf == 1) {
        a = 0x00700F01;
        b = 0x00080800;
        cc = 0x3ED82203u;
        d = 0x178BFBFFu;
    } else if (leaf == 7) {
        b = 0x00000008;
    }
    c->r[0] = a;
    c->r[3] = b;
    c->r[1] = cc;
    c->r[2] = d;
}

typedef long double og_f80;
#define OG_ST(c, i) ((c)->st[((c)->ftop + (i)) & 7])
static inline void og_fpush(OgCtx* c, og_f80 v) {
    c->ftop = (c->ftop - 1) & 7;
    c->st[c->ftop] = v;
}
static inline void og_fpop(OgCtx* c) { c->ftop = (c->ftop + 1) & 7; }
static inline og_f80 og_ld80(uint64_t a) {
#if defined(__x86_64__) && __LDBL_MANT_DIG__ == 64
    long double v = 0;
    memcpy(&v, (const void*)(uintptr_t)a, 10);
    return v;
#else
    uint64_t m;
    uint16_t se;
    memcpy(&m, (const void*)(uintptr_t)a, 8);
    memcpy(&se, (const void*)(uintptr_t)(a + 8), 2);
    const int e = se & 0x7FFF;
    double v = e == 0x7FFF ? (m << 1 ? NAN : INFINITY) : ldexp((double)m, e - 16383 - 63);
    return (og_f80)(se & 0x8000 ? -v : v);
#endif
}
static inline void og_st80(uint64_t a, og_f80 v) {
#if defined(__x86_64__) && __LDBL_MANT_DIG__ == 64
    memcpy((void*)(uintptr_t)a, &v, 10);
#else
    uint64_t m = 0;
    uint16_t se = signbit((double)v) ? 0x8000 : 0;
    const double x = fabs((double)v);
    if (x != x) {
        se |= 0x7FFF;
        m = 0xC000000000000000ull;
    } else if (isinf(x)) {
        se |= 0x7FFF;
        m = 0x8000000000000000ull;
    } else if (x != 0) {
        int e;
        const double f = frexp(x, &e);
        m = (uint64_t)ldexp(f, 64);
        se |= (uint16_t)(e - 1 + 16383);
    }
    memcpy((void*)(uintptr_t)a, &m, 8);
    memcpy((void*)(uintptr_t)(a + 8), &se, 2);
#endif
}
static inline og_f80 og_fround(OgCtx* c, og_f80 v) {
    switch ((c->fcw >> 10) & 3) {
    case 1: return floorl(v);
    case 2: return ceill(v);
    case 3: return truncl(v);
    default: return rintl(v);
    }
}
static inline int64_t og_fist(OgCtx* c, og_f80 v, int bits, int truncate) {
    const og_f80 r = truncate ? truncl(v) : og_fround(c, v);
    const og_f80 lim = (og_f80)(1ull << (bits - 1));
    if (!(r >= -lim && r < lim)) {
        return bits == 64 ? INT64_MIN : -(int64_t)(1ll << (bits - 1));
    }
    return (int64_t)r;
}
static inline void og_fcom(OgCtx* c, og_f80 a, og_f80 b) {
    c->fsw &= (uint16_t)~0x4500;
    if (a != a || b != b) {
        c->fsw |= 0x4500;
    } else if (a < b) {
        c->fsw |= 0x0100;
    } else if (a == b) {
        c->fsw |= 0x4000;
    }
}
static inline void og_fcomi(OgCtx* c, og_f80 a, og_f80 b) {
    if (a != a || b != b) {
        c->zf = c->pf = c->cf = 1;
    } else {
        c->zf = (uint8_t)(a == b);
        c->pf = 0;
        c->cf = (uint8_t)(a < b);
    }
    c->of = c->sf = c->af = 0;
}
static inline void og_fxam(OgCtx* c, og_f80 v) {
    uint16_t cc;
    if (v != v) {
        cc = 0x0100;
    } else if (isinf((double)v)) {
        cc = 0x0500;
    } else if (v == 0) {
        cc = 0x4000;
    } else {
        cc = 0x0400;
    }
    if (signbit((double)v)) {
        cc |= 0x0200;
    }
    c->fsw = (uint16_t)((c->fsw & ~0x4700) | cc);
}
static inline uint16_t og_fnstsw(OgCtx* c) { return (uint16_t)((c->fsw & ~0x3800) | (c->ftop & 7) << 11); }

static inline uint8_t og_parity(uint64_t r) { return (uint8_t)(!__builtin_parity((unsigned)(r & 0xFF))); }

#define OG_LOGIC(c, res, bits)                                                                      \
    do {                                                                                            \
        uint64_t og_lr_ = (uint64_t)(res);        \
        (c)->cf = 0; (c)->of = 0; (c)->af = 0;                                                      \
        (c)->zf = (uint8_t)((og_lr_ & OG_MASK(bits)) == 0);                                         \
        (c)->sf = (uint8_t)((og_lr_ >> ((bits) - 1)) & 1);                                          \
        (c)->pf = og_parity(og_lr_);                                                                \
    } while (0)

#define OG_MASK(bits) ((bits) == 64 ? ~0ull : ((1ull << (bits)) - 1))

static inline void og_add_flags(OgCtx* c, uint64_t a, uint64_t b, uint64_t r, int bits, uint64_t carry_in) {
    const uint64_t m = OG_MASK(bits);
    a &= m; b &= m; r &= m;
    const int sh = bits - 1;
    c->cf = (uint8_t)(bits == 64 ? (r < a || (carry_in && r == a)) : (((a + b + carry_in) >> bits) & 1));
    c->zf = (uint8_t)(r == 0);
    c->sf = (uint8_t)((r >> sh) & 1);
    c->of = (uint8_t)((((a ^ r) & (b ^ r)) >> sh) & 1);
    c->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    c->pf = og_parity(r);
}

static inline void og_sub_flags(OgCtx* c, uint64_t a, uint64_t b, uint64_t r, int bits, uint64_t borrow_in) {
    const uint64_t m = OG_MASK(bits);
    a &= m; b &= m; r &= m;
    const int sh = bits - 1;
    c->cf = (uint8_t)(borrow_in ? (a <= b) : (a < b));
    c->zf = (uint8_t)(r == 0);
    c->sf = (uint8_t)((r >> sh) & 1);
    c->of = (uint8_t)((((a ^ b) & (a ^ r)) >> sh) & 1);
    c->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    c->pf = og_parity(r);
}

#define OG_O(c) ((c)->of)
#define OG_NO(c) (!(c)->of)
#define OG_B(c) ((c)->cf)
#define OG_AE(c) (!(c)->cf)
#define OG_E(c) ((c)->zf)
#define OG_NE(c) (!(c)->zf)
#define OG_BE(c) ((c)->cf || (c)->zf)
#define OG_A(c) (!(c)->cf && !(c)->zf)
#define OG_S(c) ((c)->sf)
#define OG_NS(c) (!(c)->sf)
#define OG_P(c) ((c)->pf)
#define OG_NP(c) (!(c)->pf)
#define OG_L(c) ((c)->sf != (c)->of)
#define OG_GE(c) ((c)->sf == (c)->of)
#define OG_LE(c) ((c)->zf || (c)->sf != (c)->of)
#define OG_G(c) (!(c)->zf && (c)->sf == (c)->of)

static inline __attribute__((noreturn)) void og_divide_error(void) {
#if defined(__x86_64__) || defined(_M_X64)
    volatile int og_z_ = 0;
    volatile int og_q_ = 1 / og_z_;
    (void)og_q_;
#endif
    __builtin_trap();
}
#if !defined(__x86_64__) && !defined(_M_X64) && !defined(__SIZEOF_INT128__)

static inline uint64_t og_udiv128_soft(uint64_t hi, uint64_t lo, uint64_t d, uint64_t* rem) {
    if (hi == 0) {
        *rem = lo % d;
        return lo / d;
    }
    for (int i = 0; i < 64; i++) {
        const uint64_t top = hi >> 63;
        hi = (hi << 1) | (lo >> 63);
        lo <<= 1;
        if (top || hi >= d) {
            hi -= d;
            lo |= 1;
        }
    }
    *rem = hi;
    return lo;
}
#endif
static inline uint64_t og_udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t* rem) {
    if (d == 0 || hi >= d) og_divide_error();
#if defined(__x86_64__) || defined(_M_X64)
    uint64_t q, r;
    __asm__("divq %4" : "=a"(q), "=d"(r) : "a"(lo), "d"(hi), "rm"(d));
    *rem = r;
    return q;
#elif defined(__SIZEOF_INT128__)
    unsigned __int128 n = ((unsigned __int128)hi << 64) | lo;
    *rem = (uint64_t)(n % d);
    return (uint64_t)(n / d);
#else
    return og_udiv128_soft(hi, lo, d, rem);
#endif
}
static inline int64_t og_idiv128(int64_t hi, uint64_t lo, int64_t d, int64_t* rem) {
#if defined(__x86_64__) || defined(_M_X64)
    if (d == 0) og_divide_error();
    int64_t q, r;
    __asm__("idivq %4" : "=a"(q), "=d"(r) : "a"(lo), "d"(hi), "rm"(d));
    *rem = r;
    return q;
#elif defined(__SIZEOF_INT128__)
    __int128 n = (__int128)(((unsigned __int128)(uint64_t)hi << 64) | lo);
    if (d == 0) og_divide_error();
    __int128 q = n / d;
    if (q > INT64_MAX || q < INT64_MIN) og_divide_error();
    *rem = (int64_t)(n % d);
    return (int64_t)q;
#else
    if (d == 0) og_divide_error();
    const int neg_n = hi < 0, neg_q = neg_n != (d < 0);
    uint64_t nh = (uint64_t)hi, nl = lo;
    if (neg_n) { nl = ~nl + 1; nh = ~nh + (nl == 0); }
    const uint64_t ud = d < 0 ? 0 - (uint64_t)d : (uint64_t)d;
    if (nh >= ud) og_divide_error();
    uint64_t r;
    const uint64_t q = og_udiv128_soft(nh, nl, ud, &r);
    if (q > (neg_q ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX)) og_divide_error();
    *rem = neg_n ? (int64_t)(0 - r) : (int64_t)r;
    return neg_q ? (int64_t)(0 - q) : (int64_t)q;
#endif
}

#define OG_PUSH(c, v) do { uint64_t og_pv_ = (uint64_t)(v); (c)->r[RSP] -= 8; M64((c)->r[RSP]) = og_pv_; } while (0)
#define OG_POP(c) ((c)->r[RSP] += 8, M64((c)->r[RSP] - 8))

#define OG_TAIL(c, how, target)                                                                     \
    do {                                                                                            \
        uint64_t og_ra_ = M64((c)->r[RSP]);                                                         \
        (c)->r[RSP] += 8;                                                                           \
        how((c), (target));                                                                         \
        M64((c)->r[RSP] - 8) = og_ra_;                                                              \
        return;                                                                                     \
    } while (0)
