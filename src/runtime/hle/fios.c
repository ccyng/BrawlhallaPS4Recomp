#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../memwatch.h"
#include "hle.h"

#define ORBIS_OK 0
#define FIOS_ERROR_BAD_PATH 0x80160008u
#define FIOS_ERROR_BAD_FH 0x8016000Eu

enum { FIOS_O_READ = 1, FIOS_O_WRITE = 2, FIOS_O_APPEND = 4, FIOS_O_CREAT = 8, FIOS_O_TRUNC = 16 };

static int open_fh(const char* name, const uint32_t* params) {
    const uint32_t f = params ? params[0] & 0xFFFF : FIOS_O_READ;
    int flags = (f & FIOS_O_WRITE) ? ((f & FIOS_O_READ) ? O_RDWR : O_WRONLY) : O_RDONLY;
    if (f & FIOS_O_APPEND) {
        flags |= O_APPEND;
    }
    if (f & FIOS_O_CREAT) {
        flags |= O_CREAT;
    }
    if (f & FIOS_O_TRUNC) {
        flags |= O_TRUNC;
    }
    char path[1024];
    rt_host_path(path, sizeof path, name);
    const int fd = open(path, flags, 0644);
    if (fd < 0 || getenv("BH_TRACE_FILES")) {
        LOG("fios open %s (%s, flags %#x): %d", name, path, f, fd);
    }
    return fd;
}

HLE(sceFiosInitialize) { RET(c, ORBIS_OK); }
HLE(sceFiosFHOpenSync) {
    const int fd = open_fh(GSTR(ARG(c, 2)), ARG(c, 3) ? ARGP(c, 3) : NULL);
    if (fd < 0) {
        RET(c, (int64_t)(int32_t)FIOS_ERROR_BAD_PATH);
        return;
    }
    *(int32_t*)ARGP(c, 1) = fd;
    RET(c, ORBIS_OK);
}
HLE(sceFiosFHCloseSync) { RET(c, ARG(c, 1) > 2 ? close((int)ARG(c, 1)) : 0); }
HLE(sceFiosFHReadSync) {
    memwatch_touch(ARG(c, 2), ARG(c, 3));
    const ssize_t n = read((int)ARG(c, 1), ARGP(c, 2), ARG(c, 3));
    if (getenv("BH_TRACE_FILES")) {
        LOG("fios read fh %d, %llu bytes at %#llx: %zd", (int)ARG(c, 1), (unsigned long long)ARG(c, 3),
            (unsigned long long)ARG(c, 2), n);
    }
    RET(c, n < 0 ? (int64_t)(int32_t)FIOS_ERROR_BAD_FH : n);
}
HLE(sceFiosFHWriteSync) {
    const int fd = (int)ARG(c, 1);
    if (fd == 1 || fd == 2) {
        hle_console_write(ARGP(c, 2), ARG(c, 3));
        RET(c, ARG(c, 3));
        return;
    }
    const ssize_t n = write(fd, ARGP(c, 2), ARG(c, 3));
    RET(c, n < 0 ? (int64_t)(int32_t)FIOS_ERROR_BAD_FH : n);
}
HLE(sceFiosFHSeek) {
    const off_t r = lseek((int)ARG(c, 0), (off_t)ARG(c, 1), (int)ARG(c, 2));
    RET(c, r < 0 ? (int64_t)(int32_t)FIOS_ERROR_BAD_FH : r);
}

static void fill_stat(uint8_t* out, const struct stat* st, int64_t offset) {
    (void)offset;
    memset(out, 0, 80);
    int64_t v[5] = {st->st_size, st->st_size, (int64_t)st->st_atime * 1000000000, (int64_t)st->st_mtime * 1000000000,
                    (int64_t)st->st_ctime * 1000000000};
    memcpy(out, v, sizeof v);
    const uint32_t flags = (S_ISDIR(st->st_mode) ? 1 : 0) | 2 | 4;
    memcpy(out + 40, &flags, 4);
}

HLE(sceFiosFHStatSync) {
    struct stat st;
    const int fd = (int)ARG(c, 1);
    if (fstat(fd, &st)) {
        RET(c, (int64_t)(int32_t)FIOS_ERROR_BAD_FH);
        return;
    }
    fill_stat(ARGP(c, 2), &st, lseek(fd, 0, SEEK_CUR));
    RET(c, ORBIS_OK);
}
HLE(sceFiosStatSync) {
    char path[1024];
    rt_host_path(path, sizeof path, GSTR(ARG(c, 1)));
    struct stat st;
    if (stat(path, &st)) {
        RET(c, (int64_t)(int32_t)FIOS_ERROR_BAD_PATH);
        return;
    }
    fill_stat(ARGP(c, 2), &st, 0);
    RET(c, ORBIS_OK);
}
HLE(sceFiosExistsSync) {
    char path[1024];
    rt_host_path(path, sizeof path, GSTR(ARG(c, 1)));
    struct stat st;
    const int ok = !stat(path, &st);
    if (ARG(c, 2)) {
        *(uint8_t*)ARGP(c, 2) = (uint8_t)ok;
    }
    RET(c, ok);
}
HLE(sceFiosDeleteSync) {
    char path[1024];
    rt_host_path(path, sizeof path, GSTR(ARG(c, 1)));
    RET(c, unlink(path) ? (int64_t)(int32_t)FIOS_ERROR_BAD_PATH : 0);
}
HLE(sceFiosRenameSync) {
    char from[1024], to[1024];
    rt_host_path(from, sizeof from, GSTR(ARG(c, 1)));
    rt_host_path(to, sizeof to, GSTR(ARG(c, 2)));
    RET(c, rename(from, to) ? (int64_t)(int32_t)FIOS_ERROR_BAD_PATH : 0);
}
HLE(sceFiosFHToFileno) { RET(c, (int32_t)ARG(c, 0)); }
HLE(sceFiosFilenoToFH) { RET(c, (int32_t)ARG(c, 0)); }
HLE(sceFiosIsValidHandle) { RET(c, (int32_t)ARG(c, 0) >= 0); }
HLE(sceFiosDeallocatePassthruFH) { RET(c, ORBIS_OK); }

const HleFunc hle_fios_funcs[] = {
    HLE_FUNC(sceFiosInitialize), HLE_FUNC(sceFiosFHOpenSync), HLE_FUNC_AS("sceFiosFHOpenWithModeSync", sceFiosFHOpenSync),
    HLE_FUNC(sceFiosFHCloseSync), HLE_FUNC(sceFiosFHReadSync), HLE_FUNC(sceFiosFHWriteSync), HLE_FUNC(sceFiosFHSeek),
    HLE_FUNC(sceFiosFHStatSync), HLE_FUNC(sceFiosStatSync), HLE_FUNC(sceFiosExistsSync), HLE_FUNC(sceFiosDeleteSync),
    HLE_FUNC(sceFiosRenameSync), HLE_FUNC(sceFiosFHToFileno), HLE_FUNC(sceFiosFilenoToFH), HLE_FUNC(sceFiosIsValidHandle),
    HLE_FUNC(sceFiosDeallocatePassthruFH),
    {NULL, NULL},
};
