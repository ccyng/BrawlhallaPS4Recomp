#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <SDL.h>

#include "platform.h"
#include "runtime.h"

#ifdef __vita__
#include <psp2/kernel/processmgr.h>

unsigned int _newlib_heap_size_user = 192 * 1024 * 1024;
#define GAME_DIR "ux0:data/brawlhalla/assets"
#define SAVE_DIR "ux0:data/brawlhalla/save"
#else
#define GAME_DIR BH_ASSETS_DIR
#define SAVE_DIR "save"
#endif

static const char* game_dir = GAME_DIR;
static const char* save_dir = SAVE_DIR;

const char* rt_game_dir(void) {
    return game_dir;
}

const char* rt_save_dir(void) {
    return save_dir;
}

typedef struct EntryParams {
    int32_t argc;
    uint32_t padding;
    uint64_t argv[33];
    uint64_t entry_addr;
} EntryParams;

static int run_title(void* unused) {
    (void)unused;
    platform_wait_gpu();
    static EntryParams params;
    static char arg0[] = "eboot.bin";
    params.argc = 1;
    params.argv[0] = H(arg0);
    params.entry_addr = rt_base + rt_module(0)->m->entry;

    OgCtx* c = rt_new_context(16u << 20);
    c->r[RSP] -= 8;
    const uint64_t* p = (const uint64_t*)&params;
    c->r[RSP] -= 8;
    *(uint64_t*)G(c->r[RSP]) = p[1];
    c->r[RSP] -= 8;
    *(uint64_t*)G(c->r[RSP]) = p[0];
    c->r[RDI] = H(&params);
    c->r[RSI] = 0;

    rt_init_libraries(c);
    const uint64_t entry_off = rt_module(0)->m->entry;
    void (*entry)(OgCtx*) = rt_lifted_at(rt_base + entry_off);
    if (!entry) {
        rt_fatal("the entry is not lifted");
    }
    LOG("entering the title at image +%#llx", (unsigned long long)entry_off);
    entry(c);
    LOG("the title's entry returned (%#llx)", (unsigned long long)c->r[RAX]);
    platform_quit();
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        game_dir = argv[1];
    }
    if (getenv("BH_SAVE_DIR")) {
        save_dir = getenv("BH_SAVE_DIR");
    }
    mkdir(save_dir, 0777);
    platform_headless();
#ifdef __vita__
    const Uint32 sdl_parts = SDL_INIT_TIMER | SDL_INIT_EVENTS | SDL_INIT_AUDIO;
#else
    const Uint32 sdl_parts = SDL_INIT_TIMER | SDL_INIT_EVENTS | SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_GAMECONTROLLER;
#endif
    if (SDL_Init(sdl_parts) != 0) {
        rt_fatal("SDL_Init: %s", SDL_GetError());
    }
    LOG("Brawlhalla recomp: game files in %s, saves in %s", game_dir, save_dir);
    platform_init();
    rt_load_image();
    rt_dispatch_init();
    rt_link_images();

    SDL_CreateThreadWithStackSize(run_title, "title", RT_HOST_STACK_MAIN, NULL);
    platform_run();
    LOG("quitting");
#ifndef __vita__
    _exit(0);
#endif
    SDL_Quit();
#ifdef __vita__
    sceKernelExitProcess(0);
#endif
    return 0;
}
