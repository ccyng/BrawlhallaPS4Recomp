#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <SDL.h>

#include "platform.h"
#include "runtime.h"

#ifdef __vita__
#define WINDOW_W 960
#define WINDOW_H 544
#else
#define WINDOW_W 1280
#define WINDOW_H 720
#endif

#define MAX_W 1280
#define MAX_H 720

static SDL_mutex* lock;
static SDL_cond* shown;
static int frame_seq, quitting, gpu_ready;

static SDL_SpinLock pad_lock;
static PadState pad = {0, 128, 128, 128, 128, 0, 0};

#ifdef __vita__
static uint16_t frame[MAX_W * MAX_H];
static int frame_w, frame_h, frame_new;

void platform_present(const uint16_t* pixels, int width, int height, int pitch) {
    if (width > MAX_W || height > MAX_H || width <= 0 || height <= 0) {
        return;
    }
    SDL_LockMutex(lock);
    for (int y = 0; y < height; y++) {
        memcpy(frame + y * width, pixels + y * pitch, (size_t)width * 2);
    }
    frame_w = width;
    frame_h = height;
    frame_new = 1;
    static int dump_every = -1, presented;
    if (dump_every < 0) {
        dump_every = getenv("BH_DUMP") ? atoi(getenv("BH_DUMP")) : 0;
    }
    if (dump_every > 0 && presented % dump_every == 0) {
        SDL_Surface* s = SDL_CreateRGBSurfaceWithFormatFrom(frame, width, height, 16, width * 2, SDL_PIXELFORMAT_RGB565);
        char path[512];
        snprintf(path, sizeof path, "%s/frame_%05d.bmp", rt_save_dir(), presented);
        SDL_SaveBMP(s, path);
        SDL_FreeSurface(s);
    }
    presented++;
    const int seq = frame_seq;
    while (frame_seq == seq && !quitting) {
        SDL_CondWaitTimeout(shown, lock, 100);
    }
    SDL_UnlockMutex(lock);
}
#endif

static uint32_t scripted_input(int frame_no, uint8_t* keys);

PadState platform_pad(void) {
    SDL_AtomicLock(&pad_lock);
    PadState p = pad;
    SDL_AtomicUnlock(&pad_lock);
    p.buttons |= scripted_input(frame_seq, NULL);
    return p;
}

enum { B_L3 = 0x2, B_R3 = 0x4, B_OPTIONS = 0x8, B_UP = 0x10, B_RIGHT = 0x20, B_DOWN = 0x40, B_LEFT = 0x80,
       B_L2 = 0x100, B_R2 = 0x200, B_L1 = 0x400, B_R1 = 0x800, B_TRIANGLE = 0x1000, B_CIRCLE = 0x2000,
       B_CROSS = 0x4000, B_SQUARE = 0x8000, B_TOUCHPAD = 0x100000 };

static SDL_GameController* controller;

static uint32_t scripted_input(int frame_no, uint8_t* keys) {
    static const struct { const char* name; uint32_t bit; } names[] = {
        {"up", B_UP}, {"down", B_DOWN}, {"left", B_LEFT}, {"right", B_RIGHT}, {"cross", B_CROSS},
        {"circle", B_CIRCLE}, {"square", B_SQUARE}, {"triangle", B_TRIANGLE}, {"start", B_OPTIONS},
        {"l1", B_L1}, {"r1", B_R1}, {"touchpad", B_TOUCHPAD},
    };
    const char* script = getenv("BH_INPUT");
    uint32_t held = 0;
    for (const char* p = script; p && *p;) {
        int from = 0, len = 0, n = 0;
        char name[16] = {0};
        if (sscanf(p, "%d+%d=%15[a-z0-9]%n", &from, &len, name, &n) != 3) {
            break;
        }
        if (frame_no >= from && frame_no < from + len) {
            if (name[0] == 'k' && keys) {
                keys[strtol(name + 1, NULL, 16) & 0xFF] = 1;
            }
            for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
                if (!strcmp(name, names[i].name)) {
                    held |= names[i].bit;
                }
            }
        }
        p += n;
        if (*p == ',') {
            p++;
        }
    }
    return held;
}

static SDL_SpinLock kbm_lock;
static uint8_t key_state[256];
static int mouse_dx, mouse_dy, mouse_wheel;
static uint32_t mouse_buttons;
static int native_keyboard, native_mouse;

void platform_use_native_keyboard(void) {
    if (!native_keyboard) {
        LOG("the title reads the keyboard itself: keys no longer act as a pad");
    }
    native_keyboard = 1;
}

void platform_use_native_mouse(void) {
    native_mouse = 1;
}

void platform_keyboard(uint8_t keys[256]) {
    SDL_AtomicLock(&kbm_lock);
    memcpy(keys, key_state, 256);
    SDL_AtomicUnlock(&kbm_lock);
    scripted_input(frame_seq, keys);
}

void platform_mouse(int* dx, int* dy, int* wheel, uint32_t* buttons) {
    SDL_AtomicLock(&kbm_lock);
    *dx = mouse_dx;
    *dy = mouse_dy;
    *wheel = mouse_wheel;
    *buttons = mouse_buttons;
    mouse_dx = mouse_dy = mouse_wheel = 0;
    SDL_AtomicUnlock(&kbm_lock);
}

static int window_w = 1920, window_h = 1080;

static void mouse_event(const SDL_Event* e) {
    SDL_AtomicLock(&kbm_lock);
    if (e->type == SDL_MOUSEMOTION) {
        mouse_dx += e->motion.xrel * 1920 / (window_w ? window_w : 1920);
        mouse_dy += e->motion.yrel * 1080 / (window_h ? window_h : 1080);
    } else if (e->type == SDL_MOUSEWHEEL) {
        mouse_wheel += e->wheel.y;
    }
    SDL_AtomicUnlock(&kbm_lock);
}

static void read_input(void) {
    PadState p = {0, 128, 128, 128, 128, 0, 0};
    const Uint8* k = SDL_GetKeyboardState(NULL);
    {
        const uint32_t b = SDL_GetMouseState(NULL, NULL);
        SDL_AtomicLock(&kbm_lock);
        for (int i = 0; i < 256; i++) {
            key_state[i] = i < SDL_NUM_SCANCODES && k[i];
        }
        mouse_buttons = ((b & SDL_BUTTON_LMASK) ? 1 : 0) | ((b & SDL_BUTTON_RMASK) ? 2 : 0) |
                        ((b & SDL_BUTTON_MMASK) ? 4 : 0);
        SDL_AtomicUnlock(&kbm_lock);
    }
    if (native_keyboard && !getenv("BH_KEYS_AS_PAD")) {
        static const Uint8 none[SDL_NUM_SCANCODES];
        k = none;
    }
    static const struct { SDL_Scancode key; uint32_t bit; } keys[] = {
        {SDL_SCANCODE_UP, B_UP}, {SDL_SCANCODE_DOWN, B_DOWN}, {SDL_SCANCODE_LEFT, B_LEFT},
        {SDL_SCANCODE_RIGHT, B_RIGHT}, {SDL_SCANCODE_Z, B_CROSS}, {SDL_SCANCODE_SPACE, B_CROSS},
        {SDL_SCANCODE_X, B_SQUARE}, {SDL_SCANCODE_C, B_CIRCLE}, {SDL_SCANCODE_V, B_TRIANGLE},
        {SDL_SCANCODE_RETURN, B_OPTIONS}, {SDL_SCANCODE_ESCAPE, B_CIRCLE}, {SDL_SCANCODE_Q, B_L1},
        {SDL_SCANCODE_W, B_R1}, {SDL_SCANCODE_LSHIFT, B_R1}, {SDL_SCANCODE_A, B_L2}, {SDL_SCANCODE_S, B_R2},
        {SDL_SCANCODE_BACKSPACE, B_TOUCHPAD},
    };
    for (size_t i = 0; i < sizeof keys / sizeof *keys; i++) {
        if (k[keys[i].key]) {
            p.buttons |= keys[i].bit;
        }
    }
    if (p.buttons & B_LEFT) {
        p.lx = 0;
    } else if (p.buttons & B_RIGHT) {
        p.lx = 255;
    }
    if (p.buttons & B_UP) {
        p.ly = 0;
    } else if (p.buttons & B_DOWN) {
        p.ly = 255;
    }
    if (p.buttons & B_L2) {
        p.l2 = 255;
    }
    if (p.buttons & B_R2) {
        p.r2 = 255;
    }
    if (controller) {
        static const struct { SDL_GameControllerButton b; uint32_t bit; } buttons[] = {
            {SDL_CONTROLLER_BUTTON_A, B_CROSS}, {SDL_CONTROLLER_BUTTON_B, B_CIRCLE},
            {SDL_CONTROLLER_BUTTON_X, B_SQUARE}, {SDL_CONTROLLER_BUTTON_Y, B_TRIANGLE},
            {SDL_CONTROLLER_BUTTON_START, B_OPTIONS}, {SDL_CONTROLLER_BUTTON_BACK, B_TOUCHPAD},
            {SDL_CONTROLLER_BUTTON_LEFTSHOULDER, B_L1}, {SDL_CONTROLLER_BUTTON_RIGHTSHOULDER, B_R1},
            {SDL_CONTROLLER_BUTTON_LEFTSTICK, B_L3}, {SDL_CONTROLLER_BUTTON_RIGHTSTICK, B_R3},
            {SDL_CONTROLLER_BUTTON_DPAD_UP, B_UP}, {SDL_CONTROLLER_BUTTON_DPAD_DOWN, B_DOWN},
            {SDL_CONTROLLER_BUTTON_DPAD_LEFT, B_LEFT}, {SDL_CONTROLLER_BUTTON_DPAD_RIGHT, B_RIGHT},
        };
        for (size_t i = 0; i < sizeof buttons / sizeof *buttons; i++) {
            if (SDL_GameControllerGetButton(controller, buttons[i].b)) {
                p.buttons |= buttons[i].bit;
            }
        }
        const int axes[4] = {SDL_CONTROLLER_AXIS_LEFTX, SDL_CONTROLLER_AXIS_LEFTY, SDL_CONTROLLER_AXIS_RIGHTX,
                             SDL_CONTROLLER_AXIS_RIGHTY};
        uint8_t* out[4] = {&p.lx, &p.ly, &p.rx, &p.ry};
        for (int i = 0; i < 4; i++) {
            *out[i] = (uint8_t)((SDL_GameControllerGetAxis(controller, axes[i]) + 32768) >> 8);
        }
        p.l2 = (uint8_t)(SDL_GameControllerGetAxis(controller, SDL_CONTROLLER_AXIS_TRIGGERLEFT) >> 7);
        p.r2 = (uint8_t)(SDL_GameControllerGetAxis(controller, SDL_CONTROLLER_AXIS_TRIGGERRIGHT) >> 7);
        if (p.l2 > 64) {
            p.buttons |= B_L2;
        }
        if (p.r2 > 64) {
            p.buttons |= B_R2;
        }
    }
    SDL_AtomicLock(&pad_lock);
    pad = p;
    SDL_AtomicUnlock(&pad_lock);
}

static SDL_AudioDeviceID audio;
static int audio_buffer_bytes;

int platform_audio_open(int rate, int channels, int is_float, int samples) {
    if (audio) {
        return 1;
    }
    SDL_AudioSpec want = {0}, have;
    want.freq = rate;
    want.channels = (Uint8)channels;
    want.format = is_float ? AUDIO_F32SYS : AUDIO_S16SYS;
    want.samples = (Uint16)(samples < 1024 ? 1024 : samples);
    audio = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
    if (!audio) {
        LOG("audio: %s", SDL_GetError());
        return 0;
    }
    audio_buffer_bytes = samples * channels * (is_float ? 4 : 2);
    SDL_PauseAudioDevice(audio, 0);
    LOG("audio: %d Hz, %d channels, %s, %d samples a buffer", rate, channels, is_float ? "float" : "s16", samples);
    return 1;
}

void platform_audio_output(const void* data, int bytes) {
    static FILE* dump;
    static int dump_checked;
    if (!dump_checked) {
        dump_checked = 1;
        if (getenv("BH_AUDIO_DUMP")) {
            dump = fopen(getenv("BH_AUDIO_DUMP"), "wb");
        }
    }
    if (dump) {
        fwrite(data, 1, (size_t)bytes, dump);
    }
    if (!audio) {
        return;
    }
    static int started, underruns;
    const Uint32 queued = SDL_GetQueuedAudioSize(audio);
    if (started && queued == 0 && ++underruns % 10 == 1) {
        LOG("audio: the output ran dry (%d times)", underruns);
    }
    started = 1;
    while (SDL_GetQueuedAudioSize(audio) > (Uint32)audio_buffer_bytes * 4 && !quitting) {
        SDL_Delay(1);
    }
    SDL_QueueAudio(audio, data, (Uint32)bytes);
}

void platform_quit(void) {
    SDL_LockMutex(lock);
    quitting = 1;
    SDL_CondBroadcast(shown);
    SDL_UnlockMutex(lock);
}

static int headless;

#ifdef __vita__
static void run_headless(void) {
    while (!quitting) {
        SDL_Delay(16);
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) {
                quitting = 1;
            }
        }
        SDL_LockMutex(lock);
        frame_new = 0;
        frame_seq++;
        SDL_CondBroadcast(shown);
        SDL_UnlockMutex(lock);
    }
}
#endif

#ifdef __vita__
#include <psp2/ctrl.h>
#include <psp2/display.h>

#include "vita_gxm.h"

static void vita_read_pad(void) {
    SceCtrlData d;
    if (sceCtrlPeekBufferPositive(0, &d, 1) < 0) {
        return;
    }
    static const struct { uint32_t vita, ps4; } map[] = {
        {SCE_CTRL_UP, B_UP}, {SCE_CTRL_DOWN, B_DOWN}, {SCE_CTRL_LEFT, B_LEFT}, {SCE_CTRL_RIGHT, B_RIGHT},
        {SCE_CTRL_CROSS, B_CROSS}, {SCE_CTRL_CIRCLE, B_CIRCLE}, {SCE_CTRL_SQUARE, B_SQUARE},
        {SCE_CTRL_TRIANGLE, B_TRIANGLE}, {SCE_CTRL_START, B_OPTIONS}, {SCE_CTRL_SELECT, B_TOUCHPAD},
        {SCE_CTRL_LTRIGGER, B_L1}, {SCE_CTRL_RTRIGGER, B_R1},
    };
    PadState p = {0, d.lx, d.ly, d.rx, d.ry, 0, 0};
    for (size_t i = 0; i < sizeof map / sizeof *map; i++) {
        if (d.buttons & map[i].vita) {
            p.buttons |= map[i].ps4;
        }
    }
    SDL_AtomicLock(&pad_lock);
    pad = p;
    SDL_AtomicUnlock(&pad_lock);
}

static void run_vita(void) {
    vita_display_init();
    sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);
    while (!quitting) {
        vita_read_pad();
        SDL_LockMutex(lock);
        const int fresh = frame_new;
        frame_new = 0;
        SDL_UnlockMutex(lock);
        if (fresh) {
            vita_display_present(frame, frame_w, frame_h);
        } else {
            sceDisplayWaitVblankStart();
        }
        SDL_LockMutex(lock);
        frame_seq++;
        SDL_CondBroadcast(shown);
        SDL_UnlockMutex(lock);
    }
}
#endif

#ifndef __vita__
#include "gpu.h"

static void dump_frame(void) {
    static int dump_every = -1, flips;
    if (dump_every < 0) {
        dump_every = getenv("BH_DUMP") ? atoi(getenv("BH_DUMP")) : 0;
    }
    if (dump_every > 0 && flips % dump_every == 0) {
        uint8_t* rgba = NULL;
        int w, h;
        if (gpu_read_frame(&rgba, &w, &h)) {
            const int sw = w > 1920 ? 1920 : w;
            SDL_Surface* s = SDL_CreateRGBSurfaceWithFormat(0, sw, h, 32, SDL_PIXELFORMAT_ABGR8888);
            for (int y = 0; y < h; y++) {
                memcpy((uint8_t*)s->pixels + y * s->pitch, rgba + (size_t)y * w * 4, (size_t)sw * 4);
            }
            char path[512];
            snprintf(path, sizeof path, "%s/frame_%05d.bmp", rt_save_dir(), flips);
            SDL_SaveBMP(s, path);
            SDL_FreeSurface(s);
        }
        free(rgba);
    }
    flips++;
}
#endif

void platform_run(void) {
#ifdef __vita__
    if (headless) {
        run_headless();
        return;
    }
    run_vita();
    platform_quit();
    return;
#else
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_Window* window = SDL_CreateWindow("Brawlhalla", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, WINDOW_W,
                                          WINDOW_H, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE |
                                                        (headless ? SDL_WINDOW_HIDDEN : 0));
    SDL_GLContext gl = window ? SDL_GL_CreateContext(window) : NULL;
    if (!window || !gl) {
        rt_fatal("no OpenGL 3.3 window: %s", SDL_GetError());
    }
    SDL_GL_SetSwapInterval(headless ? 0 : 1);
    gpu_init();
    SDL_LockMutex(lock);
    gpu_ready = 1;
    SDL_CondBroadcast(shown);
    SDL_UnlockMutex(lock);
    uint64_t last_flip = SDL_GetTicks64();
    while (!quitting) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) {
                quitting = 1;
            } else if (e.type == SDL_CONTROLLERDEVICEADDED && !controller) {
                controller = SDL_GameControllerOpen(e.cdevice.which);
            } else if (e.type == SDL_MOUSEMOTION || e.type == SDL_MOUSEWHEEL) {
                mouse_event(&e);
            }
        }
        SDL_GetWindowSize(window, &window_w, &window_h);
        if (native_mouse && !headless) {
            SDL_ShowCursor(SDL_DISABLE);
        }
        read_input();
        if (!gpu_service()) {
            SDL_Delay(0);
            continue;
        }
        int w, h;
        SDL_GL_GetDrawableSize(window, &w, &h);
        gpu_present(w, h);
        SDL_GL_SwapWindow(window);
        if (headless) {
            const uint64_t now = SDL_GetTicks64();
            if (now - last_flip < 16) {
                SDL_Delay((Uint32)(16 - (now - last_flip)));
            }
            last_flip = SDL_GetTicks64();
        }
        dump_frame();
        static uint64_t fps_t0;
        static int fps_n;
        fps_n++;
        if (SDL_GetTicks64() - fps_t0 >= 10000) {
            if (fps_t0) {
                LOG("%.1f fps", fps_n * 1000.0 / (double)(SDL_GetTicks64() - fps_t0));
            }
            fps_t0 = SDL_GetTicks64();
            fps_n = 0;
        }
        SDL_LockMutex(lock);
        frame_seq++;
        SDL_UnlockMutex(lock);
        gpu_flip_shown();
    }
    platform_quit();
#endif
}

void platform_wait_gpu(void) {
#ifndef __vita__
    SDL_LockMutex(lock);
    while (!gpu_ready) {
        SDL_CondWait(shown, lock);
    }
    SDL_UnlockMutex(lock);
#endif
}

int platform_headless(void) {
    if (getenv("BH_HEADLESS") && atoi(getenv("BH_HEADLESS"))) {
        headless = 1;
        SDL_setenv("SDL_AUDIODRIVER", "dummy", 1);
#ifdef __vita__
        SDL_setenv("SDL_VIDEODRIVER", "dummy", 1);
#endif
    }
    return headless;
}

void platform_init(void) {
    lock = SDL_CreateMutex();
    shown = SDL_CreateCond();
}
