#include "memwatch.h"

#include <stdlib.h>
#include <string.h>

#include "runtime.h"

#ifndef __vita__
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#define REGION_BASE 0x4000000000ull
#define REGION_SIZE (64ull << 30)
#define PAGE_SHIFT 12
#define PAGES (REGION_SIZE >> PAGE_SHIFT)

static uint32_t* written;
static uint8_t* watched;
static volatile uint32_t seq = 1;
static struct sigaction previous;

static void on_fault(int sig, siginfo_t* info, void* uc) {
    const uint64_t a = (uint64_t)(uintptr_t)info->si_addr;
    if (a >= REGION_BASE && a < REGION_BASE + REGION_SIZE) {
        const uint64_t page = (a - REGION_BASE) >> PAGE_SHIFT;
        if (watched[page]) {
            watched[page] = 0;
            written[page] = __atomic_add_fetch(&seq, 1, __ATOMIC_SEQ_CST);
            mprotect((void*)(uintptr_t)(REGION_BASE + (page << PAGE_SHIFT)), 1u << PAGE_SHIFT, PROT_READ | PROT_WRITE);
            return;
        }
    }
    if (previous.sa_flags & SA_SIGINFO) {
        previous.sa_sigaction(sig, info, uc);
    } else if (previous.sa_handler != SIG_IGN && previous.sa_handler != SIG_DFL) {
        previous.sa_handler(sig);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

void memwatch_init(void) {
    written = mmap(NULL, PAGES * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    watched = mmap(NULL, PAGES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &previous);
}

static int range(uint64_t addr, uint64_t size, uint64_t* p0, uint64_t* p1) {
    if (addr < REGION_BASE || addr + size > REGION_BASE + REGION_SIZE || !size) {
        return 0;
    }
    *p0 = (addr - REGION_BASE) >> PAGE_SHIFT;
    *p1 = (addr + size - 1 - REGION_BASE) >> PAGE_SHIFT;
    return 1;
}

uint32_t memwatch_watch(uint64_t addr, uint64_t size) {
    uint64_t p0, p1;
    const uint32_t now = __atomic_load_n(&seq, __ATOMIC_SEQ_CST);
    if (!range(addr, size, &p0, &p1)) {
        return now;
    }
    for (uint64_t p = p0; p <= p1; p++) {
        if (!watched[p]) {
            watched[p] = 1;
            mprotect((void*)(uintptr_t)(REGION_BASE + (p << PAGE_SHIFT)), 1u << PAGE_SHIFT, PROT_READ);
        }
    }
    return now;
}

void memwatch_touch(uint64_t addr, uint64_t size) {
    uint64_t p0, p1;
    if (!written || !range(addr, size, &p0, &p1)) {
        return;
    }
    for (uint64_t p = p0; p <= p1; p++) {
        if (watched[p]) {
            watched[p] = 0;
            written[p] = __atomic_add_fetch(&seq, 1, __ATOMIC_SEQ_CST);
            mprotect((void*)(uintptr_t)(REGION_BASE + (p << PAGE_SHIFT)), 1u << PAGE_SHIFT, PROT_READ | PROT_WRITE);
        }
    }
}

int memwatch_written(uint64_t addr, uint64_t size, uint32_t since) {
    uint64_t p0, p1;
    if (!range(addr, size, &p0, &p1)) {
        return 1;
    }
    for (uint64_t p = p0; p <= p1; p++) {
        if (written[p] > since || !watched[p]) {
            return 1;
        }
    }
    return 0;
}
#else
void memwatch_init(void) {}
uint32_t memwatch_watch(uint64_t addr, uint64_t size) {
    (void)addr;
    (void)size;
    return 0;
}
int memwatch_written(uint64_t addr, uint64_t size, uint32_t since) {
    (void)addr;
    (void)size;
    (void)since;
    return 1;
}
void memwatch_touch(uint64_t addr, uint64_t size) {
    (void)addr;
    (void)size;
}
#endif
