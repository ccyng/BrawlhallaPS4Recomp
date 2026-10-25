#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <SDL.h>
#ifndef __vita__
#include <sys/mman.h>
#endif

#include "../gpu.h"
#include "../memwatch.h"
#include "hle.h"

#define ORBIS_OK 0
#define KERR(e) (0x80020000u | (e))
#define E_PERM 1
#define E_NOENT 2
#define E_BADF 9
#define E_NOMEM 12
#define E_ACCES 13
#define E_BUSY 16
#define E_EXIST 17
#define E_INVAL 22
#define E_AGAIN 35
#define E_TIMEDOUT 60
#define E_DEADLK 11

static uint64_t stack_chk_guard = 0x2B992DDFA23249D6ull;
static char progname_str[] = "eboot.bin";
static uint64_t progname = 0;

HLE(__stack_chk_fail) {
    (void)c;
    rt_fatal("__stack_chk_fail: the title's stack is corrupt");
}

#define MAX_KEYS 256

#define KERNEL_ROOM 0x400

typedef struct GuestThread {
    uint8_t kernel_fields[KERNEL_ROOM];
    uint64_t entry, arg;
    char name[32];
    SDL_Thread* thread;
    uint64_t ret;
    int detached, done;
    SDL_mutex* lock;
    SDL_cond* cond;
    int32_t err;
    uint64_t specific[MAX_KEYS];
    jmp_buf exit_to;
    OgCtx* ctx;
} GuestThread;

static __thread GuestThread* self;
static GuestThread main_thread = {.name = "main"};

static GuestThread* current(void) {
    if (!self) {
        self = &main_thread;
    }
    return self;
}

int32_t* hle_errno(void) {
    return &current()->err;
}

typedef struct GuestAttr {
    uint8_t kernel_fields[KERNEL_ROOM];
    uint64_t stack_size;
    int detached;
} GuestAttr;

static uint64_t key_dtor[MAX_KEYS];
static int key_count = 1;

static void run_key_dtors(OgCtx* c, GuestThread* t) {
    for (int round = 0; round < 4; round++) {
        int any = 0;
        for (int k = 1; k < key_count; k++) {
            if (key_dtor[k] && t->specific[k]) {
                const uint64_t v = t->specific[k];
                t->specific[k] = 0;
                GUEST_CALL(c, key_dtor[k], v);
                any = 1;
            }
        }
        if (!any) {
            break;
        }
    }
}

static int thread_main(void* p) {
    GuestThread* t = p;
    self = t;
    OgCtx* c = rt_new_context(1u << 20);
    t->ctx = c;
    LOG("thread %s starts at %#llx", t->name, (unsigned long long)t->entry);
    if (!setjmp(t->exit_to)) {
        t->ret = GUEST_CALL(c, t->entry, t->arg);
    }
    run_key_dtors(c, t);
    LOG("thread %s ends", t->name);
    SDL_LockMutex(t->lock);
    t->done = 1;
    SDL_CondBroadcast(t->cond);
    SDL_UnlockMutex(t->lock);
    rt_free_context(c);
    return 0;
}

static int create_thread(OgCtx* c, uint64_t* out, const GuestAttr* a, uint64_t entry, uint64_t arg, const char* name) {
    (void)c;
    GuestThread* t = calloc(1, sizeof *t);
    t->entry = entry;
    t->arg = arg;
    t->lock = SDL_CreateMutex();
    t->cond = SDL_CreateCond();
    t->detached = a && a->detached;
    snprintf(t->name, sizeof t->name, "%s", name ? name : "title thread");
    *out = H(t);
    t->thread = SDL_CreateThreadWithStackSize(thread_main, t->name, RT_HOST_STACK_THREAD, t);
    if (!t->thread) {
        return E_AGAIN;
    }
    SDL_DetachThread(t->thread);
    return 0;
}

static GuestAttr* attr_of(uint64_t handle_addr) {
    uint64_t* h = G(handle_addr);
    if (!*h) {
        *h = H(calloc(1, sizeof(GuestAttr)));
    }
    return G(*h);
}

HLE(scePthreadAttrInit) {
    *(uint64_t*)ARGP(c, 0) = H(calloc(1, sizeof(GuestAttr)));
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrDestroy) {
    uint64_t* h = ARGP(c, 0);
    free(G(*h));
    *h = 0;
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrSetstacksize) {
    attr_of(ARG(c, 0))->stack_size = ARG(c, 1);
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrSetdetachstate) {
    attr_of(ARG(c, 0))->detached = ARG(c, 1) == 1;
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrGetdetachstate) {
    *(int32_t*)ARGP(c, 1) = attr_of(ARG(c, 0))->detached;
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrGetaffinity) {
    *(uint64_t*)ARGP(c, 1) = 0x7F;
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrGetschedparam) {
    *(int32_t*)ARGP(c, 1) = 700;
    RET(c, ORBIS_OK);
}
HLE(scePthreadAttrGet) {
    *(uint64_t*)ARGP(c, 1) = H(calloc(1, sizeof(GuestAttr)));
    RET(c, ORBIS_OK);
}
HLE(pthread_attr_ok) { RET(c, ORBIS_OK); }

HLE(scePthreadCreate) {
    const GuestAttr* a = ARG(c, 1) ? G(*(uint64_t*)ARGP(c, 1)) : NULL;
    const int e = create_thread(c, ARGP(c, 0), a, ARG(c, 2), ARG(c, 3), ARG(c, 4) ? GSTR(ARG(c, 4)) : NULL);
    RET(c, e ? KERR(e) : ORBIS_OK);
}
HLE(pthread_create) {
    const GuestAttr* a = ARG(c, 1) ? G(*(uint64_t*)ARGP(c, 1)) : NULL;
    RET(c, create_thread(c, ARGP(c, 0), a, ARG(c, 2), ARG(c, 3), NULL));
}

static int join(uint64_t handle, uint64_t* ret) {
    GuestThread* t = G(handle);
    if (!t || t == current()) {
        return E_DEADLK;
    }
    SDL_LockMutex(t->lock);
    while (!t->done) {
        SDL_CondWait(t->cond, t->lock);
    }
    SDL_UnlockMutex(t->lock);
    if (ret) {
        *ret = t->ret;
    }
    return 0;
}
HLE(scePthreadJoin) {
    const int e = join(ARG(c, 0), ARG(c, 1) ? ARGP(c, 1) : NULL);
    RET(c, e ? KERR(e) : ORBIS_OK);
}
HLE(pthread_join) { RET(c, join(ARG(c, 0), ARG(c, 1) ? ARGP(c, 1) : NULL)); }
HLE(scePthreadDetach) { RET(c, ORBIS_OK); }
HLE(scePthreadExit) {
    GuestThread* t = current();
    if (t == &main_thread) {
        rt_fatal("the main thread exits through scePthreadExit");
    }
    t->ret = ARG(c, 0);
    longjmp(t->exit_to, 1);
}
HLE(scePthreadSelf) { RET(c, H(current())); }
HLE(scePthreadEqual) { RET(c, ARG(c, 0) == ARG(c, 1)); }
HLE(scePthreadGetname) {
    snprintf(ARGP(c, 1), 32, "%s", ((GuestThread*)ARGP(c, 0))->name);
    RET(c, ORBIS_OK);
}
HLE(scePthreadYield) {
    (void)c;
    SDL_Delay(0);
}
HLE(scePthreadSetaffinity) { RET(c, ORBIS_OK); }
HLE(scePthreadSetprio) { RET(c, ORBIS_OK); }

static SDL_SpinLock key_lock;

static int key_create(uint32_t* key, uint64_t dtor) {
    SDL_AtomicLock(&key_lock);
    if (key_count == MAX_KEYS) {
        SDL_AtomicUnlock(&key_lock);
        return E_AGAIN;
    }
    const int k = key_count++;
    key_dtor[k] = dtor;
    SDL_AtomicUnlock(&key_lock);
    *key = (uint32_t)k;
    return 0;
}
HLE(scePthreadKeyCreate) {
    const int e = key_create(ARGP(c, 0), ARG(c, 1));
    RET(c, e ? KERR(e) : ORBIS_OK);
}
HLE(pthread_key_create) { RET(c, key_create(ARGP(c, 0), ARG(c, 1))); }
HLE(scePthreadKeyDelete) {
    const uint32_t k = (uint32_t)ARG(c, 0);
    if (k < MAX_KEYS) {
        key_dtor[k] = 0;
    }
    RET(c, ORBIS_OK);
}
HLE(pthread_getspecific) {
    const uint32_t k = (uint32_t)ARG(c, 0);
    RET(c, k < MAX_KEYS ? current()->specific[k] : 0);
}
HLE(pthread_setspecific) {
    const uint32_t k = (uint32_t)ARG(c, 0);
    if (k >= MAX_KEYS) {
        RET(c, E_INVAL);
        return;
    }
    current()->specific[k] = ARG(c, 1);
    RET(c, 0);
}

static SDL_mutex* once_lock;

HLE(scePthreadOnce) {
    int32_t* state = ARGP(c, 0);
    if (__atomic_load_n(state, __ATOMIC_ACQUIRE) == 2) {
        RET(c, ORBIS_OK);
        return;
    }
    SDL_LockMutex(once_lock);
    if (*state != 2) {
        *state = 1;
        rt_guest_call(c, ARG(c, 1), 0, NULL);
        __atomic_store_n(state, 2, __ATOMIC_RELEASE);
    }
    SDL_UnlockMutex(once_lock);
    RET(c, ORBIS_OK);
}

typedef struct GuestSync {
    uint8_t kernel_fields[KERNEL_ROOM];
    void* obj;
} GuestSync;

static uint64_t new_sync(void* obj) {
    GuestSync* g = calloc(1, sizeof *g);
    g->obj = obj;
    return H(g);
}

static SDL_mutex* mutex_of(uint64_t handle_addr) {
    static SDL_SpinLock lazy;
    uint64_t* h = G(handle_addr);
    uint64_t v = __atomic_load_n(h, __ATOMIC_ACQUIRE);
    if (!v) {
        SDL_AtomicLock(&lazy);
        if (!*h) {
            __atomic_store_n(h, new_sync(SDL_CreateMutex()), __ATOMIC_RELEASE);
        }
        SDL_AtomicUnlock(&lazy);
        v = *h;
    }
    return ((GuestSync*)G(v))->obj;
}

HLE(scePthreadMutexInit) {
    *(uint64_t*)ARGP(c, 0) = new_sync(SDL_CreateMutex());
    RET(c, ORBIS_OK);
}
HLE(scePthreadMutexDestroy) {
    uint64_t* h = ARGP(c, 0);
    if (*h) {
        SDL_DestroyMutex(((GuestSync*)G(*h))->obj);
        free(G(*h));
        *h = 0;
    }
    RET(c, ORBIS_OK);
}
HLE(scePthreadMutexLock) {
    SDL_LockMutex(mutex_of(ARG(c, 0)));
    RET(c, ORBIS_OK);
}
HLE(scePthreadMutexUnlock) {
    SDL_UnlockMutex(mutex_of(ARG(c, 0)));
    RET(c, ORBIS_OK);
}
HLE(scePthreadMutexTrylock) { RET(c, SDL_TryLockMutex(mutex_of(ARG(c, 0))) ? KERR(E_BUSY) : ORBIS_OK); }
HLE(pthread_mutex_trylock) { RET(c, SDL_TryLockMutex(mutex_of(ARG(c, 0))) ? E_BUSY : 0); }
HLE(scePthreadMutexTimedlock) {
    SDL_mutex* m = mutex_of(ARG(c, 0));
    const uint64_t until = SDL_GetTicks64() + (uint32_t)ARG(c, 1) / 1000;
    while (SDL_TryLockMutex(m)) {
        if (SDL_GetTicks64() >= until) {
            RET(c, KERR(E_TIMEDOUT));
            return;
        }
        SDL_Delay(1);
    }
    RET(c, ORBIS_OK);
}
HLE(mutexattr) {
    if (ARG(c, 0)) {
        uint64_t* h = ARGP(c, 0);
        if (!*h) {
            *h = 1;
        }
    }
    RET(c, ORBIS_OK);
}

static SDL_cond* cond_of(uint64_t handle_addr) {
    static SDL_SpinLock lazy;
    uint64_t* h = G(handle_addr);
    uint64_t v = __atomic_load_n(h, __ATOMIC_ACQUIRE);
    if (!v) {
        SDL_AtomicLock(&lazy);
        if (!*h) {
            __atomic_store_n(h, new_sync(SDL_CreateCond()), __ATOMIC_RELEASE);
        }
        SDL_AtomicUnlock(&lazy);
        v = *h;
    }
    return ((GuestSync*)G(v))->obj;
}

HLE(scePthreadCondInit) {
    *(uint64_t*)ARGP(c, 0) = new_sync(SDL_CreateCond());
    RET(c, ORBIS_OK);
}
HLE(scePthreadCondDestroy) {
    uint64_t* h = ARGP(c, 0);
    if (*h) {
        SDL_DestroyCond(((GuestSync*)G(*h))->obj);
        free(G(*h));
        *h = 0;
    }
    RET(c, ORBIS_OK);
}
HLE(scePthreadCondSignal) {
    SDL_CondSignal(cond_of(ARG(c, 0)));
    RET(c, ORBIS_OK);
}
HLE(scePthreadCondBroadcast) {
    SDL_CondBroadcast(cond_of(ARG(c, 0)));
    RET(c, ORBIS_OK);
}
HLE(scePthreadCondWait) {
    SDL_CondWait(cond_of(ARG(c, 0)), mutex_of(ARG(c, 1)));
    RET(c, ORBIS_OK);
}
HLE(scePthreadCondTimedwait) {
    const int r = SDL_CondWaitTimeout(cond_of(ARG(c, 0)), mutex_of(ARG(c, 1)), ((uint32_t)ARG(c, 2) + 999) / 1000);
    RET(c, r == SDL_MUTEX_TIMEDOUT ? KERR(E_TIMEDOUT) : ORBIS_OK);
}
HLE(pthread_cond_timedwait) {
    const int64_t* ts = ARGP(c, 2);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    const int64_t ms = (ts[0] - now.tv_sec) * 1000 + (ts[1] - now.tv_nsec) / 1000000;
    const int r = SDL_CondWaitTimeout(cond_of(ARG(c, 0)), mutex_of(ARG(c, 1)), ms > 0 ? (Uint32)ms : 0);
    RET(c, r == SDL_MUTEX_TIMEDOUT ? E_TIMEDOUT : 0);
}
HLE(condattr) { RET(c, ORBIS_OK); }

HLE(pthread_rwlock_lock) {
    SDL_LockMutex(mutex_of(ARG(c, 0)));
    RET(c, 0);
}
HLE(pthread_rwlock_unlock) {
    SDL_UnlockMutex(mutex_of(ARG(c, 0)));
    RET(c, 0);
}

typedef struct EventFlag {
    uint8_t kernel_fields[KERNEL_ROOM];
    SDL_mutex* lock;
    SDL_cond* cond;
    uint64_t bits;
} EventFlag;

enum { EF_AND = 1, EF_OR = 2, EF_CLEAR_ALL = 0x10, EF_CLEAR_PAT = 0x20 };

HLE(sceKernelCreateEventFlag) {
    EventFlag* f = calloc(1, sizeof *f);
    f->lock = SDL_CreateMutex();
    f->cond = SDL_CreateCond();
    f->bits = ARG(c, 3);
    *(uint64_t*)ARGP(c, 0) = H(f);
    RET(c, ORBIS_OK);
}
HLE(sceKernelDeleteEventFlag) {
    EventFlag* f = ARGP(c, 0);
    SDL_DestroyCond(f->cond);
    SDL_DestroyMutex(f->lock);
    free(f);
    RET(c, ORBIS_OK);
}
HLE(sceKernelSetEventFlag) {
    EventFlag* f = ARGP(c, 0);
    SDL_LockMutex(f->lock);
    f->bits |= ARG(c, 1);
    SDL_CondBroadcast(f->cond);
    SDL_UnlockMutex(f->lock);
    RET(c, ORBIS_OK);
}
HLE(sceKernelClearEventFlag) {
    EventFlag* f = ARGP(c, 0);
    SDL_LockMutex(f->lock);
    f->bits &= ARG(c, 1);
    SDL_UnlockMutex(f->lock);
    RET(c, ORBIS_OK);
}

static int ef_match(EventFlag* f, uint64_t want, uint32_t mode, uint64_t* result) {
    const int ok = (mode & EF_AND) ? (f->bits & want) == want : (f->bits & want) != 0;
    if (ok) {
        if (result) {
            *result = f->bits;
        }
        if (mode & EF_CLEAR_ALL) {
            f->bits = 0;
        } else if (mode & EF_CLEAR_PAT) {
            f->bits &= ~want;
        }
    }
    return ok;
}

HLE(sceKernelWaitEventFlag) {
    EventFlag* f = ARGP(c, 0);
    const uint64_t want = ARG(c, 1);
    const uint32_t mode = (uint32_t)ARG(c, 2);
    uint64_t* result = ARG(c, 3) ? ARGP(c, 3) : NULL;
    uint32_t* timeout = ARG(c, 4) ? ARGP(c, 4) : NULL;
    SDL_LockMutex(f->lock);
    const uint64_t until = timeout ? SDL_GetTicks64() + (*timeout + 999) / 1000 : 0;
    while (!ef_match(f, want, mode, result)) {
        if (timeout) {
            const uint64_t now = SDL_GetTicks64();
            if (now >= until) {
                if (result) {
                    *result = f->bits;
                }
                *timeout = 0;
                SDL_UnlockMutex(f->lock);
                RET(c, KERR(E_TIMEDOUT));
                return;
            }
            SDL_CondWaitTimeout(f->cond, f->lock, (Uint32)(until - now));
        } else {
            SDL_CondWait(f->cond, f->lock);
        }
    }
    SDL_UnlockMutex(f->lock);
    RET(c, ORBIS_OK);
}
HLE(sceKernelPollEventFlag) {
    EventFlag* f = ARGP(c, 0);
    SDL_LockMutex(f->lock);
    const int ok = ef_match(f, ARG(c, 1), (uint32_t)ARG(c, 2), ARG(c, 3) ? ARGP(c, 3) : NULL);
    SDL_UnlockMutex(f->lock);
    RET(c, ok ? ORBIS_OK : KERR(E_BUSY));
}

static uint64_t start_counter;

HLE(sceKernelUsleep) {
    const uint64_t us = (uint32_t)ARG(c, 0);
    SDL_Delay((Uint32)((us + 999) / 1000));
    RET(c, ORBIS_OK);
}
HLE(usleep) {
    const uint64_t us = (uint32_t)ARG(c, 0);
    SDL_Delay((Uint32)((us + 999) / 1000));
    RET(c, 0);
}
HLE(nanosleep) {
    const int64_t* ts = ARGP(c, 0);
    const int64_t ms = ts[0] * 1000 + ts[1] / 1000000;
    SDL_Delay(ms > 0 ? (Uint32)ms : 0);
    RET(c, 0);
}
HLE(sceKernelReadTsc) { RET(c, SDL_GetPerformanceCounter()); }
HLE(sceKernelGetTscFrequency) { RET(c, SDL_GetPerformanceFrequency()); }
HLE(sceKernelGetProcessTime) {
    RET(c, (SDL_GetPerformanceCounter() - start_counter) * 1000000 / SDL_GetPerformanceFrequency());
}
HLE(clock_gettime) {
    const int id = (int)ARG(c, 0);
    struct timespec t;
    clock_gettime(id == 0 || id == 9 || id == 10 ? CLOCK_REALTIME : CLOCK_MONOTONIC, &t);
    int64_t* out = ARGP(c, 1);
    out[0] = t.tv_sec;
    out[1] = t.tv_nsec;
    RET(c, 0);
}
HLE(gettimeofday) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    if (ARG(c, 0)) {
        int64_t* out = ARGP(c, 0);
        out[0] = t.tv_sec;
        out[1] = t.tv_nsec / 1000;
    }
    if (ARG(c, 1)) {
        memset(ARGP(c, 1), 0, 8);
    }
    RET(c, 0);
}
HLE(getrusage) {
    memset(ARGP(c, 1), 0, 144);
    RET(c, 0);
}
HLE(sceKernelConvertUtcToLocaltime) {
    const time_t t = (time_t)ARG(c, 0);
    struct tm lt;
    localtime_r(&t, &lt);
    const int64_t off = lt.tm_gmtoff;
    *(int64_t*)ARGP(c, 1) = (int64_t)t + off;
    if (ARG(c, 2)) {
        int64_t* ts = ARGP(c, 2);
        ts[0] = (int64_t)t;
        ((uint32_t*)ts)[2] = (uint32_t)(off - (lt.tm_isdst > 0 ? 3600 : 0));
        ((uint32_t*)ts)[3] = lt.tm_isdst > 0 ? 3600 : 0;
    }
    if (ARG(c, 3)) {
        *(uint64_t*)ARGP(c, 3) = lt.tm_isdst > 0 ? 3600 : 0;
    }
    RET(c, ORBIS_OK);
}
HLE(sceKernelConvertLocaltimeToUtc) {
    const time_t t = (time_t)ARG(c, 0);
    struct tm lt;
    localtime_r(&t, &lt);
    *(int64_t*)ARGP(c, 2) = (int64_t)t - lt.tm_gmtoff;
    if (ARG(c, 3)) {
        memset(ARGP(c, 3), 0, 8);
    }
    if (ARG(c, 4)) {
        *(int32_t*)ARGP(c, 4) = 0;
    }
    RET(c, ORBIS_OK);
}

typedef struct KEvent {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t data;
    uint64_t udata;
} KEvent;

#define EQUEUE_MAX 16

typedef struct Equeue {
    uint8_t kernel_fields[KERNEL_ROOM];
    SDL_mutex* lock;
    SDL_cond* cond;
    int count;
    KEvent events[EQUEUE_MAX];
} Equeue;

HLE(sceKernelCreateEqueue) {
    Equeue* q = calloc(1, sizeof *q);
    q->lock = SDL_CreateMutex();
    q->cond = SDL_CreateCond();
    *(uint64_t*)ARGP(c, 0) = H(q);
    RET(c, ORBIS_OK);
}
HLE(sceKernelDeleteEqueue) {
    Equeue* q = ARGP(c, 0);
    SDL_DestroyCond(q->cond);
    SDL_DestroyMutex(q->lock);
    free(q);
    RET(c, ORBIS_OK);
}

void hle_equeue_trigger(uint64_t q_addr, uint64_t ident, int16_t filter, uint64_t udata) {
    Equeue* q = G(q_addr);
    SDL_LockMutex(q->lock);
    int i = 0;
    while (i < q->count && !(q->events[i].ident == ident && q->events[i].filter == filter)) {
        i++;
    }
    if (i == q->count && q->count < EQUEUE_MAX) {
        memset(&q->events[i], 0, sizeof q->events[i]);
        q->events[i].ident = ident;
        q->events[i].filter = filter;
        q->count++;
    }
    if (i < q->count) {
        q->events[i].udata = udata;
        q->events[i].data++;
    }
    SDL_CondBroadcast(q->cond);
    SDL_UnlockMutex(q->lock);
}

HLE(sceKernelWaitEqueue) {
    Equeue* q = ARGP(c, 0);
    KEvent* ev = ARGP(c, 1);
    const int max = (int)ARG(c, 2);
    int* out = ARGP(c, 3);
    const uint32_t* timeout_us = ARGP(c, 4);
    SDL_LockMutex(q->lock);
    if (!q->count) {
        if (timeout_us) {
            SDL_CondWaitTimeout(q->cond, q->lock, (*timeout_us + 999) / 1000);
        } else {
            while (!q->count) {
                SDL_CondWait(q->cond, q->lock);
            }
        }
    }
    const int n = q->count < max ? q->count : max;
    memcpy(ev, q->events, sizeof *ev * (size_t)n);
    memmove(q->events, q->events + n, sizeof *ev * (size_t)(q->count - n));
    q->count -= n;
    SDL_UnlockMutex(q->lock);
    if (out) {
        *out = n;
    }
    RET(c, n ? ORBIS_OK : KERR(E_TIMEDOUT));
}

HLE(sceKernelGetDirectMemorySize) { RET(c, 5ull << 30); }
HLE(sceKernelIsNeoMode) { RET(c, 0); }

static void* direct_alloc(uint64_t len, uint64_t align) {
#ifdef __vita__
    return rt_aligned_alloc(align, (len + align - 1) & ~(align - 1));
#else
    static SDL_SpinLock lock;
    static uint64_t next = 0x4000000000ull;
    SDL_AtomicLock(&lock);
    const uint64_t at = (next + align - 1) & ~(align - 1);
    void* p = mmap((void*)(uintptr_t)at, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                   -1, 0);
    if (p == MAP_FAILED) {
        p = NULL;
    } else {
        next = at + ((len + 0xFFFF) & ~0xFFFFull);
    }
    SDL_AtomicUnlock(&lock);
    return p;
#endif
}

void* rt_gpu_alloc(uint64_t size, uint64_t align) {
    void* p = direct_alloc((size + 0xFFFF) & ~0xFFFFull, align < 0x10000 ? 0x10000 : align);
    if (!p) {
        rt_fatal("no GPU memory for %llu bytes", (unsigned long long)size);
    }
    return p;
}

#ifndef __vita__
#define MEMSTAT_MAX 512
static struct {
    uint64_t addr, len;
    int type;
} memstat[MEMSTAT_MAX];
static int memstat_count;

static void memstat_add(void* p, uint64_t len, int type) {
    if (p && memstat_count < MEMSTAT_MAX) {
        memstat[memstat_count].addr = H(p);
        memstat[memstat_count].len = len;
        memstat[memstat_count++].type = type;
    }
}

static int memstat_main(void* unused) {
    (void)unused;
    static unsigned char vec[1 << 20];
    for (;;) {
        SDL_Delay(30000);
        uint64_t total = 0;
        for (int i = 0; i < memstat_count; i++) {
            uint64_t res = 0;
            for (uint64_t off = 0; off < memstat[i].len; off += (uint64_t)sizeof vec * 4096) {
                const uint64_t n = memstat[i].len - off < (uint64_t)sizeof vec * 4096 ? memstat[i].len - off
                                                                                     : (uint64_t)sizeof vec * 4096;
                if (!mincore(G(memstat[i].addr + off), n, vec)) {
                    for (uint64_t k = 0; k < (n + 4095) / 4096; k++) {
                        res += vec[k] & 1;
                    }
                }
            }
            total += res * 4096;
            if (res * 4096 >= (1u << 20)) {
                LOG("memstat: %s %#llx, %llu MB of %llu MB resident", memstat[i].type < 0 ? "flexible" : "direct",
                    (unsigned long long)memstat[i].addr, (unsigned long long)(res * 4096 >> 20),
                    (unsigned long long)(memstat[i].len >> 20));
            }
        }
        LOG("memstat: %llu MB resident in the title's allocations", (unsigned long long)(total >> 20));
    }
    return 0;
}
#else
#define memstat_add(p, len, type) ((void)0)
#endif

HLE(sceKernelAllocateDirectMemory) {
    const uint64_t len = ARG(c, 2), align = ARG(c, 3) ? ARG(c, 3) : 0x4000;
    void* p = direct_alloc(len, align);
    memstat_add(p, len, (int)ARG(c, 4));
    LOG("sceKernelAllocateDirectMemory(%#llx bytes, align %#llx, type %d) = %p", (unsigned long long)len,
        (unsigned long long)align, (int)ARG(c, 4), p);
    if (!p) {
        RET(c, KERR(E_NOMEM));
        return;
    }
    *(uint64_t*)ARGP(c, 5) = H(p);
    RET(c, ORBIS_OK);
}
HLE(sceKernelMapDirectMemory) {
    *(uint64_t*)ARGP(c, 0) = ARG(c, 4);
    RET(c, ORBIS_OK);
}
HLE(sceKernelReleaseDirectMemory) {
#ifndef __vita__
    munmap(ARGP(c, 0), ARG(c, 1));
#endif
    RET(c, ORBIS_OK);
}
HLE(sceKernelMapNamedFlexibleMemory) {
    const uint64_t len = (ARG(c, 1) + 0x3FFF) & ~0x3FFFull;
#ifdef __vita__
    void* p = rt_aligned_alloc(0x4000, len);
#else
    void* p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        p = NULL;
    }
#endif
    memstat_add(p, len, -1);
    LOG("sceKernelMapNamedFlexibleMemory(%#llx bytes, %s) = %p", (unsigned long long)len,
        ARG(c, 4) ? GSTR(ARG(c, 4)) : "", p);
    if (!p) {
        RET(c, KERR(E_NOMEM));
        return;
    }
    *(uint64_t*)ARGP(c, 0) = H(p);
    RET(c, ORBIS_OK);
}
HLE(sceKernelMunmap) {
#ifndef __vita__
    munmap(ARGP(c, 0), ARG(c, 1));
#endif
    RET(c, ORBIS_OK);
}
HLE(sceKernelMlock) { RET(c, ORBIS_OK); }

static int host_flags(uint32_t f) {
    int h = (f & 3) == 0 ? O_RDONLY : (f & 3) == 1 ? O_WRONLY : O_RDWR;
    if (f & 0x8) {
        h |= O_APPEND;
    }
    if (f & 0x200) {
        h |= O_CREAT;
    }
    if (f & 0x400) {
        h |= O_TRUNC;
    }
    if (f & 0x800) {
        h |= O_EXCL;
    }
    if (f & 0x20000) {
        h |= O_DIRECTORY;
    }
    return h;
}

static int open_file(const char* name, uint32_t flags, int mode) {
    char path[1024];
    rt_host_path(path, sizeof path, name);
    const int fd = open(path, host_flags(flags), mode ? mode : 0644);
    if (fd < 0 || getenv("BH_TRACE_FILES")) {
        LOG("open %s (%s, flags %#x): %d", name, path, flags, fd);
    }
    return fd;
}

static int bsd_errno(int e) {
    switch (e) {
    case ENOENT: return E_NOENT;
    case EBADF: return E_BADF;
    case EACCES: return E_ACCES;
    case EEXIST: return E_EXIST;
    case ENOMEM: return E_NOMEM;
    default: return E_INVAL;
    }
}

static void fill_stat(uint8_t* out, const struct stat* st) {
    memset(out, 0, 120);
    const uint16_t mode = (uint16_t)((S_ISDIR(st->st_mode) ? 0040000 : 0100000) | (st->st_mode & 0777));
    memcpy(out + 8, &mode, 2);
    const uint16_t nlink = 1;
    memcpy(out + 10, &nlink, 2);
    const int64_t times[6] = {st->st_atime, 0, st->st_mtime, 0, st->st_ctime, 0};
    memcpy(out + 24, times, 48);
    const int64_t size = st->st_size, blocks = (st->st_size + 511) / 512;
    memcpy(out + 72, &size, 8);
    memcpy(out + 80, &blocks, 8);
    const uint32_t blksize = 0x4000;
    memcpy(out + 88, &blksize, 4);
    memcpy(out + 104, times + 2, 8);
}

HLE(open) {
    const int fd = open_file(GSTR(ARG(c, 0)), (uint32_t)ARG(c, 1), (int)ARG(c, 2));
    if (fd < 0) {
        *hle_errno() = bsd_errno(errno);
    }
    RET(c, (int64_t)fd);
}
HLE(sceKernelOpen) {
    const int fd = open_file(GSTR(ARG(c, 0)), (uint32_t)ARG(c, 1), (int)ARG(c, 2));
    RET(c, fd < 0 ? (int64_t)(int32_t)KERR(bsd_errno(errno)) : fd);
}
HLE(close) { RET(c, (int64_t)close((int)ARG(c, 0))); }
HLE(sceKernelClose) { RET(c, close((int)ARG(c, 0)) ? (int64_t)(int32_t)KERR(E_BADF) : 0); }

static int64_t do_write(int fd, const void* buf, size_t n) {
    if (fd == 1 || fd == 2) {
        hle_console_write(buf, n);
        return (int64_t)n;
    }
    return write(fd, buf, n);
}
HLE(read) {
    memwatch_touch(ARG(c, 1), ARG(c, 2));
    RET(c, read((int)ARG(c, 0), ARGP(c, 1), ARG(c, 2)));
}
HLE(write) { RET(c, do_write((int)ARG(c, 0), ARGP(c, 1), ARG(c, 2))); }
HLE(sceKernelRead) {
    memwatch_touch(ARG(c, 1), ARG(c, 2));
    const ssize_t n = read((int)ARG(c, 0), ARGP(c, 1), ARG(c, 2));
    if (getenv("BH_TRACE_FILES")) {
        LOG("read fd %d, %llu bytes: %zd", (int)ARG(c, 0), (unsigned long long)ARG(c, 2), n);
    }
    RET(c, n < 0 ? (int64_t)(int32_t)KERR(bsd_errno(errno)) : n);
}
HLE(sceKernelWrite) { RET(c, do_write((int)ARG(c, 0), ARGP(c, 1), ARG(c, 2))); }
HLE(lseek) { RET(c, lseek((int)ARG(c, 0), (off_t)ARG(c, 1), (int)ARG(c, 2))); }
HLE(sceKernelLseek) {
    const off_t r = lseek((int)ARG(c, 0), (off_t)ARG(c, 1), (int)ARG(c, 2));
    RET(c, r < 0 ? (int64_t)(int32_t)KERR(bsd_errno(errno)) : r);
}

static int stat_path(const char* name, uint8_t* out) {
    char path[1024];
    rt_host_path(path, sizeof path, name);
    struct stat st;
    if (stat(path, &st)) {
        if (getenv("BH_TRACE_FILES")) {
            LOG("stat %s (%s): not found", name, path);
        }
        return -1;
    }
    fill_stat(out, &st);
    return 0;
}
HLE(stat) {
    const int r = stat_path(GSTR(ARG(c, 0)), ARGP(c, 1));
    if (r) {
        *hle_errno() = E_NOENT;
    }
    RET(c, (int64_t)r);
}
HLE(sceKernelStat) { RET(c, stat_path(GSTR(ARG(c, 0)), ARGP(c, 1)) ? (int64_t)(int32_t)KERR(E_NOENT) : 0); }
HLE(fstat) {
    struct stat st;
    if (fstat((int)ARG(c, 0), &st)) {
        RET(c, -1);
        return;
    }
    fill_stat(ARGP(c, 1), &st);
    RET(c, 0);
}
HLE(sceKernelFstat) {
    struct stat st;
    if (fstat((int)ARG(c, 0), &st)) {
        RET(c, (int64_t)(int32_t)KERR(E_BADF));
        return;
    }
    fill_stat(ARGP(c, 1), &st);
    RET(c, 0);
}
HLE(getpid) { RET(c, 1000); }

HLE(__error) { RET(c, H(hle_errno())); }
HLE(__tls_get_addr) {
    const uint64_t* ti = ARGP(c, 0);
    RET(c, rt_tls_block(c->fs_base, ti[0]) + ti[1]);
}
HLE(sceKernelGetProcParam) { RET(c, rt_base + rt_module(0)->m->procparam); }
HLE(_sceKernelSetThreadDtors) { (void)c; }
HLE(kernel_zero) { RET(c, 0); }
HLE(sceLibcHeapGetTraceInfo) {
    static uint64_t counters[2][64];
    uint8_t* info = ARGP(c, 0);
    memset(info + 8, 0, 8);
    const uint64_t p[2] = {H(counters[0]), H(counters[1])};
    memcpy(info + 0x10, p, 16);
    RET(c, ORBIS_OK);
}
HLE(kernel_unsupported) { RET(c, (int64_t)(int32_t)KERR(E_PERM)); }
HLE(sceKernelDebugRaiseException) {
    rt_fatal("sceKernelDebugRaiseException(%#llx, %#llx)", (unsigned long long)ARG(c, 0), (unsigned long long)ARG(c, 1));
}
HLE(_exit) {
    LOG("the title exits (_exit %d)", (int)ARG(c, 0));
    exit((int)ARG(c, 0));
}
HLE(sceKernelLoadStartModule) {
    LOG("sceKernelLoadStartModule(%s): not loaded", GSTR(ARG(c, 0)));
    RET(c, (int64_t)(int32_t)0x80020002u);
}
HLE(sceKernelDlsym) { RET(c, (int64_t)(int32_t)KERR(E_NOENT)); }

const HleFunc hle_kernel_funcs[] = {
    HLE_FUNC(__stack_chk_fail),
    HLE_FUNC(scePthreadAttrInit), HLE_FUNC(scePthreadAttrDestroy), HLE_FUNC(scePthreadAttrSetstacksize),
    HLE_FUNC(scePthreadAttrSetdetachstate), HLE_FUNC(scePthreadAttrGetdetachstate), HLE_FUNC(scePthreadAttrGetaffinity),
    HLE_FUNC(scePthreadAttrGetschedparam), HLE_FUNC(scePthreadAttrGet),
    HLE_FUNC_AS("scePthreadAttrSetaffinity", pthread_attr_ok), HLE_FUNC_AS("scePthreadAttrSetinheritsched", pthread_attr_ok),
    HLE_FUNC_AS("scePthreadAttrSetschedparam", pthread_attr_ok), HLE_FUNC_AS("scePthreadAttrSetschedpolicy", pthread_attr_ok),
    HLE_FUNC_AS("scePthreadAttrSetguardsize", pthread_attr_ok),
    HLE_FUNC_AS("pthread_attr_init", scePthreadAttrInit), HLE_FUNC_AS("pthread_attr_destroy", scePthreadAttrDestroy),
    HLE_FUNC_AS("pthread_attr_setstacksize", scePthreadAttrSetstacksize),
    HLE_FUNC_AS("pthread_attr_setdetachstate", scePthreadAttrSetdetachstate),
    HLE_FUNC(scePthreadCreate), HLE_FUNC(pthread_create), HLE_FUNC(scePthreadJoin), HLE_FUNC(pthread_join),
    HLE_FUNC(scePthreadDetach), HLE_FUNC_AS("pthread_detach", scePthreadDetach), HLE_FUNC(scePthreadExit),
    HLE_FUNC_AS("pthread_exit", scePthreadExit), HLE_FUNC(scePthreadSelf), HLE_FUNC_AS("pthread_self", scePthreadSelf),
    HLE_FUNC(scePthreadEqual), HLE_FUNC_AS("pthread_equal", scePthreadEqual), HLE_FUNC(scePthreadGetname),
    HLE_FUNC(scePthreadYield), HLE_FUNC_AS("pthread_yield", scePthreadYield), HLE_FUNC_AS("sched_yield", scePthreadYield),
    HLE_FUNC(scePthreadSetaffinity), HLE_FUNC(scePthreadSetprio),
    HLE_FUNC(scePthreadKeyCreate), HLE_FUNC(pthread_key_create), HLE_FUNC(scePthreadKeyDelete),
    HLE_FUNC_AS("pthread_key_delete", scePthreadKeyDelete),
    HLE_FUNC(pthread_getspecific), HLE_FUNC_AS("scePthreadGetspecific", pthread_getspecific),
    HLE_FUNC(pthread_setspecific), HLE_FUNC_AS("scePthreadSetspecific", pthread_setspecific),
    HLE_FUNC(scePthreadOnce), HLE_FUNC_AS("pthread_once", scePthreadOnce),
    HLE_FUNC(scePthreadMutexInit), HLE_FUNC(scePthreadMutexDestroy), HLE_FUNC(scePthreadMutexLock),
    HLE_FUNC(scePthreadMutexUnlock), HLE_FUNC(scePthreadMutexTrylock), HLE_FUNC(scePthreadMutexTimedlock),
    HLE_FUNC_AS("pthread_mutex_init", scePthreadMutexInit), HLE_FUNC_AS("pthread_mutex_destroy", scePthreadMutexDestroy),
    HLE_FUNC_AS("pthread_mutex_lock", scePthreadMutexLock), HLE_FUNC_AS("pthread_mutex_unlock", scePthreadMutexUnlock),
    HLE_FUNC(pthread_mutex_trylock),
    HLE_FUNC_AS("scePthreadMutexattrInit", mutexattr), HLE_FUNC_AS("scePthreadMutexattrDestroy", mutexattr),
    HLE_FUNC_AS("scePthreadMutexattrSettype", mutexattr), HLE_FUNC_AS("scePthreadMutexattrSetprotocol", mutexattr),
    HLE_FUNC_AS("pthread_mutexattr_init", mutexattr), HLE_FUNC_AS("pthread_mutexattr_destroy", mutexattr),
    HLE_FUNC_AS("pthread_mutexattr_settype", mutexattr), HLE_FUNC_AS("pthread_mutexattr_setprotocol", mutexattr),
    HLE_FUNC(scePthreadCondInit), HLE_FUNC(scePthreadCondDestroy), HLE_FUNC(scePthreadCondSignal),
    HLE_FUNC(scePthreadCondBroadcast), HLE_FUNC(scePthreadCondWait), HLE_FUNC(scePthreadCondTimedwait),
    HLE_FUNC_AS("pthread_cond_init", scePthreadCondInit), HLE_FUNC_AS("pthread_cond_destroy", scePthreadCondDestroy),
    HLE_FUNC_AS("pthread_cond_signal", scePthreadCondSignal), HLE_FUNC_AS("pthread_cond_broadcast", scePthreadCondBroadcast),
    HLE_FUNC_AS("pthread_cond_wait", scePthreadCondWait), HLE_FUNC(pthread_cond_timedwait),
    HLE_FUNC_AS("scePthreadCondattrInit", condattr), HLE_FUNC_AS("scePthreadCondattrDestroy", condattr),
    HLE_FUNC_AS("pthread_condattr_init", condattr), HLE_FUNC_AS("pthread_condattr_destroy", condattr),
    HLE_FUNC_AS("pthread_rwlock_rdlock", pthread_rwlock_lock), HLE_FUNC_AS("pthread_rwlock_wrlock", pthread_rwlock_lock),
    HLE_FUNC(pthread_rwlock_unlock),
    HLE_FUNC(sceKernelCreateEventFlag), HLE_FUNC(sceKernelDeleteEventFlag), HLE_FUNC(sceKernelSetEventFlag),
    HLE_FUNC(sceKernelClearEventFlag), HLE_FUNC(sceKernelWaitEventFlag), HLE_FUNC(sceKernelPollEventFlag),
    HLE_FUNC(sceKernelUsleep), HLE_FUNC(usleep), HLE_FUNC(nanosleep), HLE_FUNC_AS("_nanosleep", nanosleep),
    HLE_FUNC(sceKernelReadTsc), HLE_FUNC(sceKernelGetTscFrequency), HLE_FUNC(sceKernelGetProcessTime),
    HLE_FUNC(clock_gettime), HLE_FUNC(gettimeofday), HLE_FUNC(getrusage),
    HLE_FUNC(sceKernelConvertUtcToLocaltime), HLE_FUNC(sceKernelConvertLocaltimeToUtc),
    HLE_FUNC(sceKernelCreateEqueue), HLE_FUNC(sceKernelDeleteEqueue), HLE_FUNC(sceKernelWaitEqueue),
    HLE_FUNC(sceKernelGetDirectMemorySize), HLE_FUNC(sceKernelIsNeoMode), HLE_FUNC(sceKernelAllocateDirectMemory),
    HLE_FUNC(sceKernelMapDirectMemory), HLE_FUNC(sceKernelReleaseDirectMemory), HLE_FUNC(sceKernelMapNamedFlexibleMemory),
    HLE_FUNC(sceKernelMunmap), HLE_FUNC(sceKernelMlock),
    HLE_FUNC(open), HLE_FUNC(sceKernelOpen), HLE_FUNC(close), HLE_FUNC(sceKernelClose), HLE_FUNC(read),
    HLE_FUNC_AS("_read", read), HLE_FUNC(write), HLE_FUNC_AS("_write", write), HLE_FUNC(sceKernelRead),
    HLE_FUNC(sceKernelWrite), HLE_FUNC(lseek), HLE_FUNC(sceKernelLseek), HLE_FUNC(stat), HLE_FUNC(sceKernelStat),
    HLE_FUNC(fstat), HLE_FUNC(sceKernelFstat), HLE_FUNC(getpid),
    HLE_FUNC(__error), HLE_FUNC(__tls_get_addr), HLE_FUNC(sceKernelGetProcParam), HLE_FUNC(_sceKernelSetThreadDtors),
    HLE_FUNC_AS("_sceKernelRtldSetApplicationHeapAPI", kernel_zero),
    HLE_FUNC_AS("_sceKernelRtldThreadAtexitIncrement", kernel_zero),
    HLE_FUNC_AS("_sceKernelRtldThreadAtexitDecrement", kernel_zero),
    HLE_FUNC_AS("_sceKernelSetThreadAtexitCount", kernel_zero), HLE_FUNC_AS("_sceKernelSetThreadAtexitReport", kernel_zero),
    HLE_FUNC_AS("sceKernelGetSanitizerMallocReplaceExternal", kernel_zero),
    HLE_FUNC_AS("sceKernelGetSanitizerNewReplaceExternal", kernel_zero),
    HLE_FUNC_AS("sceKernelIsAddressSanitizerEnabled", kernel_zero), HLE_FUNC_AS("__pthread_cxa_finalize", kernel_zero),
    HLE_FUNC_AS("signal", kernel_zero), HLE_FUNC_AS("_sigprocmask", kernel_zero), HLE_FUNC_AS("_is_signal_return", kernel_zero),
    HLE_FUNC_AS("__elf_phdr_match_addr", kernel_zero), HLE_FUNC_AS("sceKernelPrintBacktraceWithModuleInfo", kernel_zero),
    HLE_FUNC(sceLibcHeapGetTraceInfo),
    HLE_FUNC_AS("sceKernelGetModuleInfoForUnwind", kernel_unsupported),
    HLE_FUNC_AS("sceKernelGetModuleInfoFromAddr", kernel_unsupported),
    HLE_FUNC_AS("sceKernelInternalMemoryGetModuleSegmentInfo", kernel_unsupported),
    HLE_FUNC_AS("sceSysmoduleGetModuleInfoForUnwind", kernel_unsupported),
    HLE_FUNC(sceKernelDebugRaiseException), HLE_FUNC_AS("sceKernelDebugRaiseExceptionOnReleaseMode", sceKernelDebugRaiseException),
    HLE_FUNC(_exit), HLE_FUNC(sceKernelLoadStartModule), HLE_FUNC(sceKernelDlsym),
    {NULL, NULL},
};

const HleData hle_kernel_data[] = {
    {"__stack_chk_guard", &stack_chk_guard},
    {"__progname", &progname},
    {NULL, NULL},
};

void hle_kernel_init(void) {
    once_lock = SDL_CreateMutex();
    start_counter = SDL_GetPerformanceCounter();
    progname = H(progname_str);
    main_thread.lock = SDL_CreateMutex();
    main_thread.cond = SDL_CreateCond();
#ifndef __vita__
    if (getenv("BH_MEMSTAT")) {
        SDL_DetachThread(SDL_CreateThread(memstat_main, "memstat", NULL));
    }
#endif
}
