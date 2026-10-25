#pragma once

#include <stdint.h>

int platform_headless(void);
void platform_init(void);
void platform_run(void);
void platform_quit(void);
void platform_wait_gpu(void);

#ifdef __vita__
void platform_present(const uint16_t* pixels, int width, int height, int pitch);
#endif

typedef struct PadState {
    uint32_t buttons;
    uint8_t lx, ly, rx, ry, l2, r2;
} PadState;
PadState platform_pad(void);

int platform_audio_open(int rate, int channels, int is_float, int samples);
void platform_audio_output(const void* data, int bytes);

void platform_keyboard(uint8_t keys[256]);
void platform_mouse(int* dx, int* dy, int* wheel, uint32_t* buttons);
void platform_use_native_keyboard(void);
void platform_use_native_mouse(void);
