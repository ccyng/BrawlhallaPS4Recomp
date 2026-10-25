#include <stdlib.h>
#include <string.h>

#include "runtime.h"

#define RETURN(c) ((c)->r[RSP] += 8)

typedef struct GuestString {
    uint64_t unused;
    union {
        uint8_t buf[16];
        uint64_t ptr;
    };
    uint64_t size, capacity;
} GuestString;

__attribute__((unused)) static const void* string_chars(const GuestString* s, size_t char_size) {
    return s->capacity >= 16 / char_size ? G(s->ptr) : (const void*)s->buf;
}

__attribute__((unused)) static void string_init(GuestString* s, const char* text, size_t n) {
    s->unused = 0;
    if (n < 16) {
        memcpy(s->buf, text, n);
        s->buf[n] = 0;
        s->capacity = 15;
    } else {
        char* p = rt_aligned_alloc(16, (n + 16) & ~(size_t)15);
        memcpy(p, text, n);
        p[n] = 0;
        s->ptr = H(p);
        s->capacity = n;
    }
    s->size = n;
}

// Unlocks all legends
static int unlock_all(void) {
    static int unlock = -1;
    if (unlock < 0) {
        const char* v = getenv("BH_UNLOCK_ALL");
        unlock = !(v && v[0] == '0');
        LOG("ownership: %s", unlock ? "everything owned (BH_UNLOCK_ALL=0 turns it off)" : "the save's own");
    }
    return unlock;
}

// UNlocks all skins
void og_orig_f_72AF0(OgCtx* c);
void og_f_72AF0(OgCtx* c) {
    if (!unlock_all() || !*(uint64_t*)G(c->r[RSI])) {
        og_orig_f_72AF0(c);
        return;
    }
    RET(c, 1);
    RETURN(c);
}

// unlocks all colors
void og_orig_f_74C90(OgCtx* c);
void og_f_74C90(OgCtx* c) {
    if (!unlock_all() || !*(uint64_t*)G(c->r[RDX])) {
        og_orig_f_74C90(c);
        return;
    }
    RET(c, 1);
    RETURN(c);
}

// also related to legend unlocking (iirc)
void og_orig_f_6D6A0(OgCtx* c);
void og_f_6D6A0(OgCtx* c) {
    const uint64_t out = c->r[RDI];
    og_orig_f_6D6A0(c);
    const uint64_t info = *(uint64_t*)G(out);
    if (unlock_all() && info) {
        *(uint32_t*)G(info + 0x1C) = 0xFFFFFFFFu;
    }
}
