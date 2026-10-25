#include <string.h>

#include "hle.h"

void hle_libc_init(void);
void hle_stdio_init(void);
void hle_kernel_init(void);

static const HleFunc* const func_tables[] = {hle_libc_funcs, hle_stdio_funcs, hle_math_funcs, hle_kernel_funcs,
                                             hle_sce_funcs, hle_av_funcs, hle_gnm_funcs, hle_fios_funcs,
                                             hle_image_funcs, hle_services_funcs, hle_ajm_funcs, hle_kbm_funcs};
static const HleData* const data_tables[] = {hle_libc_data, hle_stdio_data, hle_kernel_data};

static void init_once(void) {
    static int done;
    if (!done) {
        done = 1;
        hle_libc_init();
        hle_stdio_init();
        hle_kernel_init();
    }
}

HleFn hle_find_func(const char* name) {
    init_once();
    for (size_t t = 0; t < sizeof func_tables / sizeof *func_tables; t++) {
        for (const HleFunc* f = func_tables[t]; f->name; f++) {
            if (!strcmp(f->name, name)) {
                return f->fn;
            }
        }
    }
    return NULL;
}

void* hle_find_data(const char* name) {
    init_once();
    for (size_t t = 0; t < sizeof data_tables / sizeof *data_tables; t++) {
        for (const HleData* d = data_tables[t]; d->name; d++) {
            if (!strcmp(d->name, name)) {
                return d->addr;
            }
        }
    }
    return NULL;
}

int hle_overrides(const char* name) {
    static const char* const names[] = {NULL};
    for (int i = 0; names[i]; i++) {
        if (!strcmp(names[i], name)) {
            return 1;
        }
    }
    return 0;
}
