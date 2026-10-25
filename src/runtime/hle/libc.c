#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <SDL.h>

#include "hle.h"

static void* guest_alloc(size_t n) {
    return rt_aligned_alloc(16, (n + 15) & ~(size_t)15);
}

HLE(malloc) { RET(c, H(guest_alloc(ARG(c, 0) ? ARG(c, 0) : 1))); }
HLE(free) { free(ARGP(c, 0)); }
HLE(calloc) {
    const size_t n = ARG(c, 0) * ARG(c, 1);
    void* p = guest_alloc(n ? n : 1);
    if (p) {
        memset(p, 0, n);
    }
    RET(c, H(p));
}
HLE(realloc) {
    void* old = ARGP(c, 0);
    const size_t n = ARG(c, 1);
    if (!old) {
        RET(c, H(guest_alloc(n ? n : 1)));
        return;
    }
    void* p = realloc(old, n ? n : 1);
    if (p && (H(p) & 15)) {
        void* q = guest_alloc(n);
        memcpy(q, p, n);
        free(p);
        p = q;
    }
    RET(c, H(p));
}

HLE(memcpy) { RET(c, H(memcpy(ARGP(c, 0), ARGP(c, 1), ARG(c, 2)))); }
HLE(memmove) { RET(c, H(memmove(ARGP(c, 0), ARGP(c, 1), ARG(c, 2)))); }
HLE(memset) { RET(c, H(memset(ARGP(c, 0), (int)ARG(c, 1), ARG(c, 2)))); }
HLE(memcmp) { RET(c, (int64_t)memcmp(ARGP(c, 0), ARGP(c, 1), ARG(c, 2))); }
HLE(memchr) { RET(c, H(memchr(ARGP(c, 0), (int)ARG(c, 1), ARG(c, 2)))); }
HLE(strlen) { RET(c, strlen(ARGP(c, 0))); }
HLE(strcpy) { RET(c, H(strcpy(ARGP(c, 0), ARGP(c, 1)))); }
HLE(strncpy) { RET(c, H(strncpy(ARGP(c, 0), ARGP(c, 1), ARG(c, 2)))); }
HLE(strcat) { RET(c, H(strcat(ARGP(c, 0), ARGP(c, 1)))); }
HLE(strncat) { RET(c, H(strncat(ARGP(c, 0), ARGP(c, 1), ARG(c, 2)))); }
HLE(strcmp) { RET(c, (int64_t)strcmp(ARGP(c, 0), ARGP(c, 1))); }
HLE(strstr) { RET(c, H(strstr(ARGP(c, 0), ARGP(c, 1)))); }
HLE(strchr) { RET(c, H(strchr(ARGP(c, 0), (int)ARG(c, 1)))); }
HLE(strrchr) { RET(c, H(strrchr(ARGP(c, 0), (int)ARG(c, 1)))); }
HLE(strncmp) { RET(c, (int64_t)strncmp(ARGP(c, 0), ARGP(c, 1), ARG(c, 2))); }
HLE(strnlen_s) { RET(c, ARG(c, 0) ? strnlen(ARGP(c, 0), ARG(c, 1)) : 0); }

HLE(setjmp) {
    uint64_t* jb = ARGP(c, 0);
    const int regs[7] = {RBX, RSP, RBP, R12, R13, R14, R15};
    jb[0] = 0;
    for (int i = 0; i < 7; i++) {
        jb[1 + i] = c->r[regs[i]];
    }
    RET(c, 0);
}
HLE(longjmp) {
    rt_fatal("longjmp(%#llx, %d): not possible in lifted code", (unsigned long long)ARG(c, 0), (int)ARG(c, 1));
}
HLE(strlcpy) {
    char* d = ARGP(c, 0);
    const char* s = ARGP(c, 1);
    const size_t n = ARG(c, 2), len = strlen(s);
    if (n) {
        const size_t k = len < n - 1 ? len : n - 1;
        memcpy(d, s, k);
        d[k] = 0;
    }
    RET(c, len);
}

HLE(_Znwm) { RET(c, H(guest_alloc(ARG(c, 0) ? ARG(c, 0) : 1))); }
HLE(_ZdlPv) { free(ARGP(c, 0)); }

static SDL_mutex* guard_lock;
HLE(__cxa_guard_acquire) {
    uint8_t* g = ARGP(c, 0);
    if (*g) {
        RET(c, 0);
        return;
    }
    SDL_LockMutex(guard_lock);
    if (*g) {
        SDL_UnlockMutex(guard_lock);
        RET(c, 0);
        return;
    }
    RET(c, 1);
}
HLE(__cxa_guard_release) {
    *(uint8_t*)ARGP(c, 0) = 1;
    SDL_UnlockMutex(guard_lock);
}

HLE(_Atomic_fetch_add_4) { RET(c, (uint32_t)__atomic_fetch_add((uint32_t*)ARGP(c, 0), (uint32_t)ARG(c, 1), __ATOMIC_SEQ_CST)); }
HLE(_Atomic_fetch_sub_4) { RET(c, (uint32_t)__atomic_fetch_sub((uint32_t*)ARGP(c, 0), (uint32_t)ARG(c, 1), __ATOMIC_SEQ_CST)); }

static SDL_mutex* syslock;
HLE(_Locksyslock) { SDL_LockMutex(syslock); }
HLE(_Unlocksyslock) { SDL_UnlockMutex(syslock); }

#define THROWS(fn, what) \
    HLE(fn) { (void)c; rt_fatal("the title throws " what); }
THROWS(xlength, "std::length_error")
THROWS(xout_of_range, "std::out_of_range")
THROWS(xbad_alloc, "std::bad_alloc")
THROWS(xbad_function_call, "std::bad_function_call")
THROWS(throw_c_error, "a C error")
THROWS(throw_cpp_error, "a C++ error")
THROWS(raise, "an exception")

#define MAX_ATEXIT 64
static struct {
    uint64_t fn, arg;
    int with_arg;
} exits[MAX_ATEXIT];
static int exit_count;

HLE(atexit) {
    if (ARG(c, 0) && exit_count < MAX_ATEXIT) {
        exits[exit_count].fn = ARG(c, 0);
        exits[exit_count++].with_arg = 0;
    }
    RET(c, 0);
}
HLE(__cxa_atexit) {
    if (exit_count < MAX_ATEXIT) {
        exits[exit_count].fn = ARG(c, 0);
        exits[exit_count].arg = ARG(c, 1);
        exits[exit_count++].with_arg = 1;
    }
    RET(c, 0);
}

static _Noreturn void run_exit(OgCtx* c, int code) {
    LOG("the title exits (%d)", code);
    while (exit_count > 0) {
        exit_count--;
        if (exits[exit_count].with_arg) {
            GUEST_CALL(c, exits[exit_count].fn, exits[exit_count].arg);
        } else {
            rt_guest_call(c, exits[exit_count].fn, 0, NULL);
        }
    }
    exit(code);
}

HLE(exit) { run_exit(c, (int)ARG(c, 0)); }
HLE(catchReturnFromMain) { run_exit(c, (int)ARG(c, 0)); }
HLE(_init_env) { (void)c; }

static OgCtx* qsort_ctx;
static uint64_t qsort_cmp;
static int qsort_call(const void* a, const void* b) {
    return (int)GUEST_CALL(qsort_ctx, qsort_cmp, H(a), H(b));
}
HLE(qsort) {
    static SDL_mutex* lock;
    if (!lock) {
        lock = SDL_CreateMutex();
    }
    SDL_LockMutex(lock);
    OgCtx* outer_ctx = qsort_ctx;
    const uint64_t outer_cmp = qsort_cmp;
    qsort_ctx = c;
    qsort_cmp = ARG(c, 3);
    qsort(ARGP(c, 0), ARG(c, 1), ARG(c, 2), qsort_call);
    qsort_ctx = outer_ctx;
    qsort_cmp = outer_cmp;
    SDL_UnlockMutex(lock);
}

HLE(rand) { RET(c, (uint32_t)(rand() & 0x7FFFFFFF)); }
HLE(time) {
    const int64_t t = (int64_t)time(NULL);
    if (ARG(c, 0)) {
        *(int64_t*)ARGP(c, 0) = t;
    }
    RET(c, t);
}

static short toupper_table[257];
static const short* toupper_ptr = toupper_table + 1;
HLE(_Getptoupper) { RET(c, H(&toupper_ptr)); }

static uint8_t need_libc[16];

const HleFunc hle_libc_funcs[] = {
    HLE_FUNC(malloc), HLE_FUNC(free), HLE_FUNC(calloc), HLE_FUNC(realloc),
    HLE_FUNC(memcpy), HLE_FUNC(memmove), HLE_FUNC(memset), HLE_FUNC(memcmp), HLE_FUNC_AS("bcmp", memcmp),
    HLE_FUNC(memchr),
    HLE_FUNC(strlen), HLE_FUNC(strcpy), HLE_FUNC(strncpy), HLE_FUNC(strcat), HLE_FUNC(strncat),
    HLE_FUNC(strcmp), HLE_FUNC(strstr), HLE_FUNC(strlcpy), HLE_FUNC(strchr), HLE_FUNC(strrchr), HLE_FUNC(strncmp),
    HLE_FUNC(strnlen_s), HLE_FUNC_AS("strnlen", strnlen_s),
    HLE_FUNC(setjmp), HLE_FUNC_AS("_setjmp", setjmp), HLE_FUNC(longjmp), HLE_FUNC_AS("_longjmp", longjmp),
    HLE_FUNC(_Znwm), HLE_FUNC_AS("_Znam", _Znwm), HLE_FUNC(_ZdlPv), HLE_FUNC_AS("_ZdaPv", _ZdlPv),
    HLE_FUNC(__cxa_guard_acquire), HLE_FUNC(__cxa_guard_release),
    HLE_FUNC(_Atomic_fetch_add_4), HLE_FUNC(_Atomic_fetch_sub_4),
    HLE_FUNC(_Locksyslock), HLE_FUNC(_Unlocksyslock),
    HLE_FUNC_AS("_ZSt14_Xlength_errorPKc", xlength), HLE_FUNC_AS("_ZSt14_Xout_of_rangePKc", xout_of_range),
    HLE_FUNC_AS("_ZSt11_Xbad_allocv", xbad_alloc), HLE_FUNC_AS("_ZSt19_Xbad_function_callv", xbad_function_call),
    HLE_FUNC_AS("_ZSt14_Throw_C_errori", throw_c_error), HLE_FUNC_AS("_ZSt16_Throw_Cpp_errori", throw_cpp_error),
    HLE_FUNC_AS("_ZNKSt9exception6_RaiseEv", raise),
    HLE_FUNC(atexit), HLE_FUNC(__cxa_atexit), HLE_FUNC(exit), HLE_FUNC(catchReturnFromMain), HLE_FUNC(_init_env),
    HLE_FUNC(qsort), HLE_FUNC(rand), HLE_FUNC(time), HLE_FUNC(_Getptoupper),
    {NULL, NULL},
};

const HleData hle_libc_data[] = {
    {"Need_sceLibc", need_libc},
    {NULL, NULL},
};

void hle_libc_init(void) {
    guard_lock = SDL_CreateMutex();
    syslock = SDL_CreateMutex();
    for (int i = -1; i < 256; i++) {
        toupper_table[i + 1] = (short)(i >= 'a' && i <= 'z' ? i - 32 : i);
    }
}
