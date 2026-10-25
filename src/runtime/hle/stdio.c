#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <SDL.h>

#include "hle.h"

GuestVa guest_va_args(OgCtx* c, int fixed_gp) {
    GuestVa va = {c, fixed_gp, 0, c->r[RSP], 0};
    return va;
}

GuestVa guest_va_list(OgCtx* c, uint64_t va_list) {
    GuestVa va = {c, 0, 0, 0, va_list};
    return va;
}

typedef struct SysvVaList {
    uint32_t gp_offset, fp_offset;
    uint64_t overflow, reg_save;
} SysvVaList;

static uint64_t next_gp(GuestVa* va) {
    if (va->va) {
        SysvVaList* l = G(va->va);
        uint64_t v;
        if (l->gp_offset < 48) {
            v = *(uint64_t*)G(l->reg_save + l->gp_offset);
            l->gp_offset += 8;
        } else {
            v = *(uint64_t*)G(l->overflow);
            l->overflow += 8;
        }
        return v;
    }
    if (va->gp < 6) {
        return ARG(va->c, va->gp++);
    }
    const uint64_t v = *(uint64_t*)G(va->stack);
    va->stack += 8;
    return v;
}

static double next_fp(GuestVa* va) {
    double v;
    if (va->va) {
        SysvVaList* l = G(va->va);
        if (l->fp_offset < 176) {
            memcpy(&v, G(l->reg_save + l->fp_offset), 8);
            l->fp_offset += 16;
        } else {
            memcpy(&v, G(l->overflow), 8);
            l->overflow += 8;
        }
        return v;
    }
    if (va->fp < 8) {
        return va->c->y[va->fp++].g[0];
    }
    memcpy(&v, G(va->stack), 8);
    va->stack += 8;
    return v;
}

int guest_vformat(char* out, size_t cap, const char* fmt, GuestVa* va) {
    size_t n = 0;
#define PUT(s, len)                                         \
    do {                                                    \
        const size_t l_ = (len);                            \
        if (n < cap) {                                      \
            memcpy(out + n, (s), n + l_ < cap ? l_ : cap - n); \
        }                                                   \
        n += l_;                                            \
    } while (0)
    for (const char* p = fmt; *p;) {
        if (*p != '%') {
            const char* q = strchr(p, '%');
            const size_t len = q ? (size_t)(q - p) : strlen(p);
            PUT(p, len);
            p += len;
            continue;
        }
        if (p[1] == '%') {
            PUT("%", 1);
            p += 2;
            continue;
        }
        char spec[32];
        size_t s = 0;
        spec[s++] = *p++;
        while (strchr("-+ #0", *p) && s < 8) {
            spec[s++] = *p++;
        }
        int width = 0, prec = -1, has_width = 0;
        if (*p == '*') {
            width = (int)next_gp(va);
            has_width = 1;
            p++;
        } else {
            while (*p >= '0' && *p <= '9') {
                width = width * 10 + (*p++ - '0');
                has_width = 1;
            }
        }
        if (*p == '.') {
            p++;
            prec = 0;
            if (*p == '*') {
                prec = (int)next_gp(va);
                p++;
            } else {
                while (*p >= '0' && *p <= '9') {
                    prec = prec * 10 + (*p++ - '0');
                }
            }
        }
        int big = 0, half = 0;
        for (;;) {
            if (*p == 'l' || *p == 'z' || *p == 'j' || *p == 't' || *p == 'q') {
                big = 1;
            } else if (*p == 'h') {
                half++;
            } else if (*p == 'L') {
                big = 2;
            } else {
                break;
            }
            p++;
        }
        const char conv = *p ? *p++ : 0;
        if (has_width) {
            s += (size_t)snprintf(spec + s, sizeof spec - s, "%d", width);
        }
        if (prec >= 0) {
            s += (size_t)snprintf(spec + s, sizeof spec - s, ".%d", prec);
        }
        char tmp[512];
        int len = 0;
        switch (conv) {
        case 'd':
        case 'i': {
            const uint64_t raw = next_gp(va);
            const long long v = big ? (long long)(int64_t)raw
                                    : half == 1 ? (short)raw : half >= 2 ? (signed char)raw : (int)raw;
            memcpy(spec + s, "ll", 2);
            spec[s + 2] = conv;
            spec[s + 3] = 0;
            len = snprintf(tmp, sizeof tmp, spec, v);
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        case 'o': {
            const uint64_t raw = next_gp(va);
            const unsigned long long v = big ? raw
                                             : half == 1 ? (unsigned short)raw : half >= 2 ? (unsigned char)raw : (unsigned)raw;
            memcpy(spec + s, "ll", 2);
            spec[s + 2] = conv;
            spec[s + 3] = 0;
            len = snprintf(tmp, sizeof tmp, spec, v);
            break;
        }
        case 'c':
            spec[s] = 'c';
            spec[s + 1] = 0;
            len = snprintf(tmp, sizeof tmp, spec, (int)next_gp(va));
            break;
        case 'p':
            len = snprintf(tmp, sizeof tmp, "0x%llx", (unsigned long long)next_gp(va));
            break;
        case 's': {
            const char* str = GSTR(next_gp(va));
            spec[s] = 's';
            spec[s + 1] = 0;
            if (!str) {
                str = "(null)";
            }
            if (!has_width && prec < 0) {
                PUT(str, strlen(str));
                continue;
            }
            len = snprintf(tmp, sizeof tmp, spec, str);
            break;
        }
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A':
            if (big == 2) {
                rt_fatal("printf of a long double (%%L%c)", conv);
            }
            spec[s] = conv;
            spec[s + 1] = 0;
            len = snprintf(tmp, sizeof tmp, spec, next_fp(va));
            break;
        case 'n':
            *(int*)G(next_gp(va)) = (int)n;
            continue;
        default:
            PUT(spec, s);
            if (conv) {
                PUT(&conv, 1);
            }
            continue;
        }
        if (len > 0) {
            PUT(tmp, (size_t)len < sizeof tmp ? (size_t)len : sizeof tmp - 1);
        }
    }
    if (cap) {
        out[n < cap ? n : cap - 1] = 0;
    }
    return (int)n;
#undef PUT
}

static SDL_mutex* out_lock;
static char out_line[1024];
static size_t out_len;

void hle_console_write(const void* data, size_t len) {
    const char* s = data;
    SDL_LockMutex(out_lock);
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\n' || out_len == sizeof out_line - 1) {
            out_line[out_len] = 0;
            LOG("[title] %s", out_line);
            out_len = 0;
            if (s[i] == '\n') {
                continue;
            }
        }
        out_line[out_len++] = s[i];
    }
    SDL_UnlockMutex(out_lock);
}

static int format_out(OgCtx* c, const char* fmt, GuestVa* va) {
    char buf[2048];
    const int n = guest_vformat(buf, sizeof buf, fmt, va);
    hle_console_write(buf, (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1);
    (void)c;
    return n;
}

HLE(printf) {
    GuestVa va = guest_va_args(c, 1);
    RET(c, format_out(c, GSTR(ARG(c, 0)), &va));
}
HLE(puts) {
    const char* s = GSTR(ARG(c, 0));
    hle_console_write(s, strlen(s));
    hle_console_write("\n", 1);
    RET(c, 0);
}
HLE(putchar) {
    const char ch = (char)ARG(c, 0);
    hle_console_write(&ch, 1);
    RET(c, (uint8_t)ch);
}
HLE(sprintf) {
    GuestVa va = guest_va_args(c, 2);
    RET(c, guest_vformat(ARGP(c, 0), (size_t)-1 / 2, GSTR(ARG(c, 1)), &va));
}
HLE(vsprintf) {
    GuestVa va = guest_va_list(c, ARG(c, 2));
    RET(c, guest_vformat(ARGP(c, 0), (size_t)-1 / 2, GSTR(ARG(c, 1)), &va));
}
HLE(vsnprintf) {
    GuestVa va = guest_va_list(c, ARG(c, 3));
    RET(c, guest_vformat(ARGP(c, 0), ARG(c, 1), GSTR(ARG(c, 2)), &va));
}

static uint8_t guest_stderr[128];

static FILE* host_file(uint64_t f) {
    return f == H(guest_stderr) ? stderr : G(f);
}

void rt_host_path(char* out, size_t cap, const char* p) {
    if (hle_savedata_path(p, out, cap)) {
        return;
    }
    if (!strncmp(p, "/app0/", 6)) {
        snprintf(out, cap, "%s/%s", rt_game_dir(), p + 6);
    } else if (!strncmp(p, "/sce_sys/", 9)) {
        snprintf(out, cap, "%s/%s", rt_game_dir(), p + 1);
    } else if (!strncmp(p, "/hostapp/", 9)) {
        snprintf(out, cap, "%s/%s", rt_game_dir(), p + 9);
    } else if (p[0] != '/') {
        snprintf(out, cap, "%s/%s", rt_game_dir(), p);
    } else {
        snprintf(out, cap, "%s%s", rt_save_dir(), p);
    }
}

HLE(fopen) {
    const char* name = GSTR(ARG(c, 0));
    const char* mode = GSTR(ARG(c, 1));
    char path[1024];
    rt_host_path(path, sizeof path, name);
    FILE* f = fopen(path, mode);
    if (!f || getenv("BH_TRACE_FILES")) {
        LOG("fopen %s (%s): %s", name, mode, f ? "ok" : "not found");
    }
    RET(c, H(f));
}
HLE(fclose) { RET(c, (int64_t)fclose(host_file(ARG(c, 0)))); }
HLE(fread) { RET(c, fread(ARGP(c, 0), ARG(c, 1), ARG(c, 2), host_file(ARG(c, 3)))); }
HLE(fwrite) { RET(c, fwrite(ARGP(c, 0), ARG(c, 1), ARG(c, 2), host_file(ARG(c, 3)))); }
HLE(fseek) { RET(c, (int64_t)fseek(host_file(ARG(c, 0)), (long)(int64_t)ARG(c, 1), (int)ARG(c, 2))); }
HLE(ftell) { RET(c, (int64_t)ftell(host_file(ARG(c, 0)))); }
HLE(fprintf) {
    GuestVa va = guest_va_args(c, 2);
    FILE* f = host_file(ARG(c, 0));
    if (f == stderr || f == stdout) {
        RET(c, format_out(c, GSTR(ARG(c, 1)), &va));
        return;
    }
    char buf[4096];
    const int n = guest_vformat(buf, sizeof buf, GSTR(ARG(c, 1)), &va);
    RET(c, (int64_t)fwrite(buf, 1, (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1, f));
}

const HleFunc hle_stdio_funcs[] = {
    HLE_FUNC(printf), HLE_FUNC(puts), HLE_FUNC(putchar), HLE_FUNC(sprintf), HLE_FUNC(vsprintf),
    HLE_FUNC(vsnprintf), HLE_FUNC(fopen), HLE_FUNC(fclose), HLE_FUNC(fread), HLE_FUNC(fwrite),
    HLE_FUNC(fseek), HLE_FUNC(ftell), HLE_FUNC(fprintf),
    {NULL, NULL},
};

const HleData hle_stdio_data[] = {
    {"_Stderr", guest_stderr},
    {NULL, NULL},
};

void hle_stdio_init(void) {
    out_lock = SDL_CreateMutex();
}
