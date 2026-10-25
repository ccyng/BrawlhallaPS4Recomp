#include <string.h>

#include <SDL.h>

#include "../platform.h"
#include "hle.h"

#define ORBIS_OK 0
#define KEYBOARD_HANDLE 1
#define MOUSE_HANDLE 1

HLE(kbm_ok) { RET(c, ORBIS_OK); }

HLE(sceKeyboardOpen) {
    LOG("keyboard opened (user %d)", (int)ARG(c, 0));
    platform_use_native_keyboard();
    RET(c, KEYBOARD_HANDLE);
}

HLE(sceKeyboardRead) {
    uint8_t* d = ARGP(c, 1);
    if (!d || !ARG(c, 2)) {
        RET(c, 0);
        return;
    }
    uint8_t keys[256];
    platform_keyboard(keys);
    uint16_t codes[32] = {0};
    uint32_t mods = 0, n = 0;
    for (int k = 4; k < 256; k++) {
        if (!keys[k]) {
            continue;
        }
        if (k >= 0xE0 && k <= 0xE7) {
            mods |= 1u << (k - 0xE0);
        } else if (n < 32) {
            codes[n++] = (uint16_t)k;
        }
    }
    if (!n) {
        n = 1;
    }
    static uint16_t last_codes[32];
    static uint32_t last_mods, last_n;
    static int reported;
    if (reported && n == last_n && mods == last_mods && !memcmp(codes, last_codes, sizeof codes)) {
        RET(c, 0);
        return;
    }
    reported = 1;
    memcpy(last_codes, codes, sizeof codes);
    last_mods = mods;
    last_n = n;
    memset(d, 0, 96);
    const uint64_t t = SDL_GetTicks64() * 1000;
    memcpy(d, &t, 8);
    d[0x10] = 1;
    memcpy(d + 0x14, &n, 4);
    memcpy(d + 0x1C, &mods, 4);
    memcpy(d + 0x20, codes, sizeof codes);
    RET(c, 1);
}

HLE(sceMouseOpen) {
    LOG("mouse opened (user %d)", (int)ARG(c, 0));
    platform_use_native_mouse();
    RET(c, MOUSE_HANDLE);
}

HLE(sceMouseRead) {
    uint8_t* d = ARGP(c, 1);
    if (!d || !ARG(c, 2)) {
        RET(c, 0);
        return;
    }
    int dx, dy, wheel;
    uint32_t buttons;
    platform_mouse(&dx, &dy, &wheel, &buttons);
    memset(d, 0, 40);
    const uint64_t t = SDL_GetTicks64() * 1000;
    memcpy(d, &t, 8);
    d[8] = 1;
    const int32_t v[4] = {dx, dy, wheel, 0};
    memcpy(d + 12, &buttons, 4);
    memcpy(d + 16, v, 16);
    RET(c, 1);
}

static uint16_t virtual_keycode(uint32_t k) {
    if (k >= 0x04 && k <= 0x1D) {
        return (uint16_t)(0x41 + k - 0x04);
    }
    if (k >= 0x1E && k <= 0x26) {
        return (uint16_t)(0x31 + k - 0x1E);
    }
    if (k >= 0x3A && k <= 0x45) {
        return (uint16_t)(0x70 + k - 0x3A);
    }
    if (k >= 0x59 && k <= 0x61) {
        return (uint16_t)(0x61 + k - 0x59);
    }
    static const struct { uint8_t hid, vk; } map[] = {
        {0x27, 0x30}, {0x28, 0x0D}, {0x29, 0x1B}, {0x2A, 0x08}, {0x2B, 0x09}, {0x2C, 0x20}, {0x2D, 0xBD},
        {0x2E, 0xBB}, {0x2F, 0xDB}, {0x30, 0xDD}, {0x31, 0xDC}, {0x33, 0xBA}, {0x34, 0xDE}, {0x35, 0xC0},
        {0x36, 0xBC}, {0x37, 0xBE}, {0x38, 0xBF}, {0x39, 0x14}, {0x46, 0x2C}, {0x47, 0x91}, {0x48, 0x13},
        {0x49, 0x2D}, {0x4A, 0x24}, {0x4B, 0x21}, {0x4C, 0x2E}, {0x4D, 0x23}, {0x4E, 0x22}, {0x4F, 0x27},
        {0x50, 0x25}, {0x51, 0x28}, {0x52, 0x26}, {0x53, 0x90}, {0x54, 0x6F}, {0x55, 0x6A}, {0x56, 0x6D},
        {0x57, 0x6B}, {0x58, 0x0D}, {0x62, 0x60}, {0x63, 0x6E}, {0xE0, 0x11}, {0xE1, 0x10}, {0xE2, 0x12},
        {0xE3, 0x5B}, {0xE4, 0x11}, {0xE5, 0x10}, {0xE6, 0x12}, {0xE7, 0x5C},
    };
    for (size_t i = 0; i < sizeof map / sizeof *map; i++) {
        if (map[i].hid == k) {
            return map[i].vk;
        }
    }
    return 0;
}

HLE(sceConvertKeycodeGetVirtualKeycode) {
    if (ARG(c, 2)) {
        *(uint16_t*)ARGP(c, 2) = virtual_keycode((uint32_t)ARG(c, 0) & 0xFFFF);
    }
    RET(c, ORBIS_OK);
}

const HleFunc hle_kbm_funcs[] = {
    HLE_FUNC_AS("sceKeyboardInit", kbm_ok), HLE_FUNC(sceKeyboardOpen), HLE_FUNC(sceKeyboardRead),
    HLE_FUNC_AS("sceKeyboardClose", kbm_ok), HLE_FUNC_AS("sceMouseInit", kbm_ok), HLE_FUNC(sceMouseOpen),
    HLE_FUNC(sceMouseRead), HLE_FUNC_AS("sceMouseClose", kbm_ok), HLE_FUNC(sceConvertKeycodeGetVirtualKeycode),
    {NULL, NULL},
};
