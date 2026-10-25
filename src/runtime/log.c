#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <SDL.h>

#include "runtime.h"

static FILE* log_file;
static SDL_mutex* log_lock;

static void log_line(const char* prefix, const char* fmt, va_list ap) {
    char buf[1024];
    vsnprintf(buf, sizeof buf, fmt, ap);
    if (!log_lock) {
        log_lock = SDL_CreateMutex();
    }
    SDL_LockMutex(log_lock);
    if (!log_file) {
        char path[512];
        snprintf(path, sizeof path, "%s/brawlhalla.log", rt_save_dir());
        log_file = fopen(path, "w");
    }
    fprintf(stderr, "%s%s\n", prefix, buf);
    if (log_file) {
        fprintf(log_file, "%s%s\n", prefix, buf);
        fflush(log_file);
    }
    SDL_UnlockMutex(log_lock);
}

void rt_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_line("", fmt, ap);
    va_end(ap);
}

_Noreturn void rt_fatal(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_line("FATAL: ", fmt, ap);
    va_end(ap);
    exit(1);
}
