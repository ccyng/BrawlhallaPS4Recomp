#include <stdlib.h>
#include <string.h>

#include <SDL.h>

#include "hle/hle.h"
#include "runtime.h"

typedef struct OgEntry {
    uint64_t addr;
    void (*fn)(OgCtx*);
} OgEntry;

static OgEntry* lifted;
static unsigned lifted_count;

typedef struct HleAt {
    uint64_t addr;
    HleFn fn;
} HleAt;
static HleAt* hle_at;
static unsigned hle_at_count;

static int by_addr(const void* a, const void* b) {
    const uint64_t x = ((const OgEntry*)a)->addr, y = ((const OgEntry*)b)->addr;
    return x < y ? -1 : x > y;
}

OgFn rt_lifted_at(uint64_t addr) {
    unsigned lo = 0, hi = lifted_count;
    while (lo < hi) {
        const unsigned mid = (lo + hi) / 2;
        if (lifted[mid].addr < addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < lifted_count && lifted[lo].addr == addr ? lifted[lo].fn : NULL;
}

static HleFn hle_at_addr(uint64_t addr) {
    unsigned lo = 0, hi = hle_at_count;
    while (lo < hi) {
        const unsigned mid = (lo + hi) / 2;
        if (hle_at[mid].addr < addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < hle_at_count && hle_at[lo].addr == addr ? hle_at[lo].fn : NULL;
}

static const RtImport* import_at(uint64_t addr, const RtModule** mod, unsigned* index) {
    for (int k = 0; k < rt_module_count(); k++) {
        const RtModule* r = rt_module(k);
        const OgModule* m = r->m;
        const uint64_t t0 = rt_import_thunk(r, 0);
        if (addr >= t0 && addr < t0 + 16ull * m->import_count && (addr - t0) % 16 == 0) {
            *mod = r;
            *index = (unsigned)((addr - t0) / 16);
            return &r->targets[*index];
        }
        if (addr < r->base || addr >= r->base + m->image_size) {
            continue;
        }
        const uint64_t off = addr - r->base;
        unsigned lo = 0, hi = m->plt_count;
        while (lo < hi) {
            const unsigned mid = (lo + hi) / 2;
            if (m->plt[mid].stub < off) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo < m->plt_count && m->plt[lo].stub == off) {
            *mod = r;
            *index = m->plt[lo].import;
            return &r->targets[*index];
        }
        return NULL;
    }
    return NULL;
}

static void call_lifted(OgCtx* c, OgFn fn) {
    c->r[RSP] -= 8;
    *(uint64_t*)G(c->r[RSP]) = 0;
    fn(c);
}

static uint8_t* warned_imports;

static void call_import(OgCtx* c, const RtModule* r, unsigned i, const RtImport* t) {
    if (t->lifted) {
        call_lifted(c, t->lifted);
        return;
    }
    if (t->hle) {
        t->hle(c);
        return;
    }
    const OgImport* imp = &r->m->imports[i];
    static SDL_SpinLock lock;
    SDL_AtomicLock(&lock);
    if (!warned_imports) {
        warned_imports = calloc(1, 1 << 16);
    }
    const unsigned key = (unsigned)(r - rt_module(0)) * 4096 + i;
    const int first = !warned_imports[key & 0xFFFF];
    warned_imports[key & 0xFFFF] = 1;
    SDL_AtomicUnlock(&lock);
    if (first) {
        LOG("UNIMPLEMENTED %s (%s %s, from %s), returning 0", imp->name, imp->library, imp->nid, r->m->name);
    }
    RET(c, 0);
}

static _Noreturn void bad_call(OgCtx* c, uint64_t target, void* from) {
    for (int i = 0; i < 16; i += 4) {
        LOG("  r%-2d %016llx  r%-2d %016llx  r%-2d %016llx  r%-2d %016llx", i, (unsigned long long)c->r[i], i + 1,
            (unsigned long long)c->r[i + 1], i + 2, (unsigned long long)c->r[i + 2], i + 3,
            (unsigned long long)c->r[i + 3]);
    }
    const char* in = "?";
    uint64_t off = target;
    for (int k = 0; k < rt_module_count(); k++) {
        const RtModule* r = rt_module(k);
        if (target >= r->base && target < r->base + r->m->image_size) {
            in = r->m->name;
            off = target - r->base;
        }
    }
    rt_fatal("call to %#llx (%s +%#llx): neither an import nor lifted; from host %p (rt_log at %p)",
             (unsigned long long)target, in, (unsigned long long)off, from, (void*)rt_log);
}

static void host_call_native(OgCtx* c, uint64_t target) {
    const RtModule* r;
    unsigned i;
    const RtImport* t = import_at(target, &r, &i);
    if (t) {
        call_import(c, r, i, t);
        return;
    }
    const HleFn h = hle_at_addr(target);
    if (h) {
        h(c);
        return;
    }
    const OgFn fn = rt_lifted_at(target);
    if (fn) {
        call_lifted(c, fn);
        return;
    }
    bad_call(c, target, __builtin_return_address(0));
}

static void host_call_dynamic(OgCtx* c, uint64_t target) {
    const OgFn fn = rt_lifted_at(target);
    if (fn) {
        call_lifted(c, fn);
        return;
    }
    host_call_native(c, target);
}

static void host_unsupported(OgCtx* c, uint64_t at) {
    (void)c;
    rt_fatal("unsupported instruction at %#llx (executable +%#llx)", (unsigned long long)at,
             (unsigned long long)(at - rt_base));
}

static void host_jump_native(OgCtx* c, uint64_t target) {
    const OgFn fn = rt_lifted_at(target);
    if (fn) {
        fn(c);
        return;
    }
    const HleFn h = hle_at_addr(target);
    if (h) {
        h(c);
        c->r[RSP] += 8;
        return;
    }
    rt_fatal("jump into the middle of a function at %#llx (executable +%#llx)", (unsigned long long)target,
             (unsigned long long)(target - rt_base));
}

void og_cmpxchg16b(OgCtx* c, uint64_t a) {
    static SDL_SpinLock lock;
    uint64_t* m = G(a);
    SDL_AtomicLock(&lock);
    if (m[0] == c->r[RAX] && m[1] == c->r[RDX]) {
        m[0] = c->r[RBX];
        m[1] = c->r[RCX];
        c->zf = 1;
    } else {
        c->r[RAX] = m[0];
        c->r[RDX] = m[1];
        c->zf = 0;
    }
    SDL_AtomicUnlock(&lock);
}

static OgHost hosts[8];

void rt_dispatch_init(void) {
    unsigned total = 0;
    const OgEntry* tables[8];
    unsigned counts[8];
    for (int k = 0; k < rt_module_count(); k++) {
        hosts[k] = (OgHost){host_call_native, host_call_dynamic, host_unsupported, host_jump_native, 0,
                            rt_module(k)->base};
        tables[k] = rt_module(k)->m->entries(&hosts[k], &counts[k]);
        total += counts[k];
    }
    lifted = malloc(sizeof *lifted * total);
    for (int k = 0; k < rt_module_count(); k++) {
        for (unsigned i = 0; i < counts[k]; i++) {
            lifted[lifted_count].addr = rt_module(k)->base + tables[k][i].addr;
            lifted[lifted_count++].fn = tables[k][i].fn;
        }
        LOG("%s: %u lifted functions", rt_module(k)->m->name, counts[k]);
    }
    qsort(lifted, lifted_count, sizeof *lifted, by_addr);

    for (int k = 0; k < rt_module_count(); k++) {
        const RtModule* r = rt_module(k);
        for (unsigned i = 0; i < r->m->export_count; i++) {
            const OgExport* ex = &r->m->exports[i];
            const uint64_t a = r->base + ex->value;
            HleFn h;
            if (!ex->is_data && (!rt_lifted_at(a) || hle_overrides(ex->name)) && (h = hle_find_func(ex->name))) {
                hle_at = realloc(hle_at, sizeof *hle_at * (hle_at_count + 1));
                hle_at[hle_at_count++] = (HleAt){a, h};
            }
        }
    }
    qsort(hle_at, hle_at_count, sizeof *hle_at, by_addr);
}

typedef struct Thread {
    OgCtx c;
    void* stack;
    void* tls;
} Thread;

static void* new_tls(uint64_t* fs_base) {
    const uint64_t off = (rt_tls_size() + 63) & ~63ull;
    uint8_t* p = rt_aligned_alloc(64, off + 256);
    memset(p, 0, off + 256);
    uint8_t* tcb = p + off;
    rt_tls_init(tcb);
    *(uint64_t*)tcb = H(tcb);
    *fs_base = H(tcb);
    return p;
}

OgCtx* rt_new_context(size_t stack) {
    Thread* t = rt_aligned_alloc(32, (sizeof(Thread) + 31) & ~(size_t)31);
    memset(t, 0, sizeof *t);
    t->stack = rt_aligned_alloc(64, stack);
    if (!t->stack) {
        rt_fatal("no memory for a guest stack of %zu bytes", stack);
    }
    t->c.r[RSP] = (H(t->stack) + stack) & ~15ull;
    t->c.mxcsr = 0x1F80;
    t->tls = new_tls(&t->c.fs_base);
    return &t->c;
}

void rt_free_context(OgCtx* c) {
    Thread* t = (Thread*)c;
    free(t->stack);
    free(t->tls);
    free(t);
}

uint64_t rt_guest_call(OgCtx* c, uint64_t fn, int nargs, const uint64_t* args) {
    void (*f)(OgCtx*) = rt_lifted_at(fn);
    if (!f) {
        rt_fatal("native code calls %#llx, which is not lifted", (unsigned long long)fn);
    }
    if (nargs > 6) {
        rt_fatal("guest call with %d arguments", nargs);
    }
    OgCtx saved;
    memcpy(&saved, c, sizeof saved);
    for (int i = 0; i < nargs; i++) {
        ARG(c, i) = args[i];
    }
    c->r[RAX] = 0;
    c->r[RSP] = ((c->r[RSP] - 256) & ~15ull) - 8;
    *(uint64_t*)G(c->r[RSP]) = 0;
    f(c);
    const uint64_t r = c->r[RAX];
    memcpy(c, &saved, sizeof saved);
    return r;
}
