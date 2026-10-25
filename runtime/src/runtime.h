#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef __vita__
#include <malloc.h>
#endif

#include "image.h"
#include "og64.h"

#define G(a) ((void*)(uintptr_t)(a))
#define H(p) ((uint64_t)(uintptr_t)(p))

static const int og_arg_regs[6] = {RDI, RSI, RDX, RCX, R8, R9};
#define ARG(c, i) ((c)->r[og_arg_regs[i]])
#define ARGP(c, i) G(ARG(c, i))
#define ARGF(c, i) ((c)->y[i].f[0])
#define ARGD(c, i) ((c)->y[i].g[0])
#define ARGS(c, i) (*(uint64_t*)G((c)->r[RSP] + 8 * ((i) - 6)))
#define RET(c, v) ((c)->r[RAX] = (uint64_t)(v))
#define RETF(c, v) do { memset((c)->y[0].b, 0, 16); (c)->y[0].f[0] = (float)(v); } while (0)
#define RETD(c, v) do { memset((c)->y[0].b, 0, 16); (c)->y[0].g[0] = (double)(v); } while (0)

extern uint64_t rt_base;

typedef void (*OgFn)(OgCtx*);

typedef struct RtImport {
    uint64_t addr;
    OgFn lifted;
    void (*hle)(OgCtx* c);
} RtImport;

typedef struct RtModule {
    const OgModule* m;
    uint64_t base;
    int tls_index;
    uint64_t tls_offset;
    RtImport* targets;
} RtModule;

static inline void* rt_aligned_alloc(size_t align, size_t size) {
#ifdef __vita__
    return memalign(align, size);
#else
    return aligned_alloc(align, size);
#endif
}

#ifdef __vita__
#define RT_HOST_STACK_MAIN (8u << 20)
#define RT_HOST_STACK_THREAD (2u << 20)
#else
#define RT_HOST_STACK_MAIN (64u << 20)
#define RT_HOST_STACK_THREAD (16u << 20)
#endif

void rt_log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
_Noreturn void rt_fatal(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
#define LOG(...) rt_log(__VA_ARGS__)

void rt_load_image(void);
void rt_link_images(void);
void rt_init_libraries(OgCtx* c);
int rt_module_count(void);
RtModule* rt_module(int i);
uint64_t rt_import_thunk(const RtModule* m, unsigned import);
uint64_t rt_export(const char* module, const char* name);
uint64_t rt_tls_size(void);
void rt_tls_init(uint8_t* tcb);
uint64_t rt_tls_block(uint64_t fs_base, uint64_t index);

void rt_dispatch_init(void);
OgFn rt_lifted_at(uint64_t addr);

uint64_t rt_guest_call(OgCtx* c, uint64_t fn, int nargs, const uint64_t* args);
#define GUEST_CALL(c, fn, ...) \
    rt_guest_call((c), (fn), sizeof((uint64_t[]){__VA_ARGS__}) / 8, (uint64_t[]){__VA_ARGS__})
OgCtx* rt_new_context(size_t stack);
void rt_free_context(OgCtx* c);

const char* rt_game_dir(void);
const char* rt_save_dir(void);
