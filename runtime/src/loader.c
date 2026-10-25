#include <stdlib.h>
#include <string.h>

#include "gpu.h"
#include "hle/hle.h"
#include "runtime.h"

extern const OgModule og_module, libc_module;

static RtModule modules[] = {{&og_module}, {&libc_module}};
#define MODULE_COUNT (int)(sizeof modules / sizeof *modules)

uint64_t rt_base;

int rt_module_count(void) {
    return MODULE_COUNT;
}

RtModule* rt_module(int i) {
    return &modules[i];
}

uint64_t rt_import_thunk(const RtModule* m, unsigned import) {
    return m->base + m->m->image_size + 16ull * import;
}

static const OgExport* find_export(const OgModule* m, const char* name) {
    unsigned lo = 0, hi = m->export_count;
    while (lo < hi) {
        const unsigned mid = (lo + hi) / 2;
        const int r = strcmp(m->exports[mid].name, name);
        if (!r) {
            return &m->exports[mid];
        }
        if (r < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

uint64_t rt_export(const char* module, const char* name) {
    for (int i = 0; i < MODULE_COUNT; i++) {
        if (!strcmp(modules[i].m->name, module)) {
            const OgExport* ex = find_export(modules[i].m, name);
            return ex ? modules[i].base + ex->value : 0;
        }
    }
    return 0;
}

static uint64_t tls_total;

uint64_t rt_tls_size(void) {
    return tls_total;
}

static void place(RtModule* r) {
    const OgModule* m = r->m;
    const size_t size = m->image_size + 16ull * m->import_count;
    uint8_t* image = rt_gpu_alloc((size + 0xFFFF) & ~(size_t)0xFFFF, 0x10000);
    memset(image, 0, size);
    r->base = H(image);
    for (unsigned i = 0; i < m->segment_count; i++) {
        const OgSegment* s = &m->segments[i];
        memcpy(image + s->vaddr, m->bytes + s->offset, s->filesz);
    }
    for (unsigned i = 0; i < m->relative_count; i++) {
        const uint64_t v = r->base + (uint64_t)m->relative[i].addend;
        memcpy(image + m->relative[i].offset, &v, 8);
    }
    if (m->tls.memsz) {
        static int next_index = 1;
        r->tls_index = next_index++;
        const uint64_t align = m->tls.align ? m->tls.align : 1;
        tls_total = (tls_total + m->tls.memsz + align - 1) & ~(align - 1);
        r->tls_offset = tls_total;
        for (unsigned i = 0; i < m->tls_module_slot_count; i++) {
            const uint64_t v = (uint64_t)r->tls_index;
            memcpy(image + m->tls_module_slots[i], &v, 8);
        }
    }
}

static void link_imports(RtModule* r) {
    const OgModule* m = r->m;
    uint8_t* image = G(r->base);
    unsigned missing_funcs = 0, missing_data = 0, lifted = 0;
    r->targets = calloc(m->import_count, sizeof *r->targets);
    for (unsigned i = 0; i < m->import_count; i++) {
        const OgImport* imp = &m->imports[i];
        RtImport* t = &r->targets[i];
        const OgExport* ex = NULL;
        const RtModule* from = NULL;
        for (int k = 0; k < MODULE_COUNT && !ex; k++) {
            if (&modules[k] != r && (ex = find_export(modules[k].m, imp->name))) {
                from = &modules[k];
            }
        }
        HleFn hle = imp->is_data ? NULL : hle_find_func(imp->name);
        if (ex && !imp->is_data && !hle_overrides(imp->name) && rt_lifted_at(from->base + ex->value)) {
            t->addr = from->base + ex->value;
            t->lifted = rt_lifted_at(t->addr);
            lifted++;
        } else if (hle) {
            t->hle = hle;
            t->addr = rt_import_thunk(r, i);
        } else if (imp->is_data) {
            void* d = ex ? NULL : hle_find_data(imp->name);
            if (ex) {
                t->addr = from->base + ex->value;
            } else if (d) {
                t->addr = H(d);
            } else {
                t->addr = H(calloc(1, 256));
                missing_data++;
                LOG("%s: data import %s (%s) is not implemented: zeros", m->name, imp->name, imp->library);
            }
        } else {
            t->addr = rt_import_thunk(r, i);
            missing_funcs++;
            if (getenv("BH_LIST_MISSING")) {
                LOG("%s: missing %s (%s)", m->name, imp->name, imp->library);
            }
        }
    }
    for (unsigned i = 0; i < m->slot_count; i++) {
        const OgSlot* s = &m->slots[i];
        const uint64_t v = r->targets[s->import].addr + (uint64_t)s->addend;
        memcpy(image + s->offset, &v, 8);
    }
    LOG("%s at %#llx, %#llx bytes; %u imports: %u to lifted code, %u functions and %u data not implemented",
        m->name, (unsigned long long)r->base, (unsigned long long)m->image_size, m->import_count, lifted,
        missing_funcs, missing_data);
}

void rt_load_image(void) {
    for (int i = 0; i < MODULE_COUNT; i++) {
        place(&modules[i]);
    }
    rt_base = modules[0].base;
}

void rt_link_images(void) {
    for (int i = 0; i < MODULE_COUNT; i++) {
        link_imports(&modules[i]);
    }
}

void rt_init_libraries(OgCtx* c) {
    for (int i = 1; i < MODULE_COUNT; i++) {
        const RtModule* r = &modules[i];
        if (rt_lifted_at(r->base + r->m->init)) {
            static uint64_t argv[2];
            LOG("%s: init at +%#llx", r->m->name, (unsigned long long)r->m->init);
            GUEST_CALL(c, r->base + r->m->init, 0, H(argv), 0);
        }
    }
}

void rt_tls_init(uint8_t* tcb) {
    for (int i = 0; i < MODULE_COUNT; i++) {
        const RtModule* r = &modules[i];
        if (r->tls_index) {
            memcpy(tcb - r->tls_offset, (uint8_t*)G(r->base + r->m->tls.vaddr), r->m->tls.filesz);
        }
    }
}

uint64_t rt_tls_block(uint64_t fs_base, uint64_t index) {
    for (int i = 0; i < MODULE_COUNT; i++) {
        if (modules[i].tls_index == (int)index) {
            return fs_base - modules[i].tls_offset;
        }
    }
    rt_fatal("no TLS block for module %llu", (unsigned long long)index);
}
