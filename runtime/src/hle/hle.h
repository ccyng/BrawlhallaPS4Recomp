#pragma once

#include <string.h>

#include "../runtime.h"

typedef void (*HleFn)(OgCtx* c);

typedef struct HleFunc {
    const char* name;
    HleFn fn;
} HleFunc;

typedef struct HleData {
    const char* name;
    void* addr;
} HleData;

#define HLE(name) static void hle_##name(OgCtx* c)
#define HLE_FUNC(name) {#name, hle_##name}
#define HLE_FUNC_AS(sym, name) {sym, hle_##name}

extern const HleFunc hle_libc_funcs[], hle_stdio_funcs[], hle_math_funcs[], hle_kernel_funcs[],
    hle_sce_funcs[], hle_av_funcs[], hle_gnm_funcs[];
extern const HleFunc hle_fios_funcs[], hle_image_funcs[], hle_services_funcs[], hle_ajm_funcs[], hle_kbm_funcs[];
extern const HleData hle_libc_data[], hle_stdio_data[], hle_kernel_data[];

void rt_host_path(char* out, size_t cap, const char* path);
int hle_savedata_path(const char* path, char* out, size_t cap);
void hle_console_write(const void* s, size_t len);
int32_t* hle_errno(void);

HleFn hle_find_func(const char* name);
void* hle_find_data(const char* name);
int hle_overrides(const char* name);

void hle_equeue_trigger(uint64_t equeue, uint64_t ident, int16_t filter, uint64_t udata);

#define GSTR(a) ((const char*)G(a))

typedef struct GuestVa {
    OgCtx* c;
    int gp, fp;
    uint64_t stack;
    uint64_t va;
} GuestVa;
GuestVa guest_va_args(OgCtx* c, int fixed_gp);
GuestVa guest_va_list(OgCtx* c, uint64_t va_list);
int guest_vformat(char* out, size_t cap, const char* fmt, GuestVa* va);
