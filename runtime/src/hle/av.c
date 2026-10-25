#include <stdlib.h>
#include <string.h>

#include <SDL.h>

#include "../gpu.h"
#include "../platform.h"
#include "hle.h"

#define ORBIS_OK 0

#define VIDEO_HANDLE 1
#define PAD_HANDLE 1
#define AUDIO_HANDLE 1

HLE(sceVideoOutOpen) { RET(c, VIDEO_HANDLE); }
HLE(sceVideoOutClose) { RET(c, ORBIS_OK); }
HLE(sceVideoOutSetFlipRate) { RET(c, ORBIS_OK); }
HLE(sceVideoOutSetBufferAttribute) {
    uint32_t* a = ARGP(c, 0);
    memset(a, 0, 40);
    a[0] = (uint32_t)ARG(c, 1);
    a[1] = (uint32_t)ARG(c, 2);
    a[2] = (uint32_t)ARG(c, 3);
    a[3] = (uint32_t)ARG(c, 4);
    a[4] = (uint32_t)ARG(c, 5);
    a[5] = (uint32_t)ARGS(c, 6);
    RET(c, ORBIS_OK);
}
HLE(sceVideoOutRegisterBuffers) {
    const uint32_t* a = ARGP(c, 4);
    gpu_set_display_buffers((int)ARG(c, 1), (int)ARG(c, 3), ARGP(c, 2), a[3], a[4], a[5], a[0], a[1] ? 8 : 10);
    RET(c, ORBIS_OK);
}
HLE(sceVideoOutGetResolutionStatus) {
    uint8_t* s = ARGP(c, 1);
    const int32_t dims[4] = {1920, 1080, 1920, 1080};
    memcpy(s, dims, 16);
    *(uint64_t*)(s + 16) = 3;
    RET(c, ORBIS_OK);
}
HLE(sceVideoOutAddFlipEvent) {
    gpu_set_flip_event(ARG(c, 0), ARG(c, 2));
    RET(c, ORBIS_OK);
}

HLE(scePadInit) { RET(c, ORBIS_OK); }
HLE(scePadOpen) { RET(c, PAD_HANDLE); }
HLE(scePadClose) { RET(c, ORBIS_OK); }
HLE(scePadReadState) {
    uint8_t* d = ARGP(c, 1);
    const PadState p = platform_pad();
    memset(d, 0, 120);
    memcpy(d, &p.buttons, 4);
    d[4] = p.lx;
    d[5] = p.ly;
    d[6] = p.rx;
    d[7] = p.ry;
    d[8] = p.l2;
    d[9] = p.r2;
    const float w = 1.0f;
    memcpy(d + 24, &w, 4);
    d[76] = 1;
    const uint64_t t = SDL_GetTicks64() * 1000;
    memcpy(d + 80, &t, 8);
    d[104] = 1;
    RET(c, ORBIS_OK);
}

HLE(scePadGetHandle) { RET(c, PAD_HANDLE); }
HLE(scePadSetVibration) { RET(c, ORBIS_OK); }
HLE(scePadGetControllerInformation) {
    uint8_t* d = ARGP(c, 1);
    memset(d, 0, 28);
    const float density = 44.86f;
    memcpy(d, &density, 4);
    const uint16_t res[2] = {1920, 943};
    memcpy(d + 4, res, 4);
    d[8] = d[9] = 13;
    d[10] = 0;
    d[11] = 1;
    d[12] = 1;
    RET(c, ORBIS_OK);
}

typedef struct AudioPort {
    int open, len, channels, is_float, playing;
    float volume[8];
} AudioPort;

#define AUDIO_PORTS 8
static AudioPort ports[AUDIO_PORTS];

HLE(sceAudioOutInit) { RET(c, ORBIS_OK); }
HLE(sceAudioOutOpen) {
    const int type = (int)ARG(c, 1), len = (int)ARG(c, 3), freq = (int)ARG(c, 4), fmt = (int)(ARG(c, 5) & 0xFF);
    static const int channels[8] = {1, 2, 8, 1, 2, 8, 8, 8};
    int h = 0;
    while (h < AUDIO_PORTS && ports[h].open) {
        h++;
    }
    if (h == AUDIO_PORTS) {
        RET(c, (int64_t)(int32_t)0x80260005u);
        return;
    }
    AudioPort* p = &ports[h];
    memset(p, 0, sizeof *p);
    p->open = 1;
    p->len = len;
    p->channels = channels[fmt & 7];
    p->is_float = fmt >= 3 && fmt != 6;
    for (int i = 0; i < 8; i++) {
        p->volume[i] = 1;
    }
    int any = 0;
    for (int i = 0; i < AUDIO_PORTS; i++) {
        any |= i != h && ports[i].playing;
    }
    if (!any) {
        p->playing = platform_audio_open(freq, 2, 1, len);
    }
    LOG("sceAudioOutOpen(type %d, len %d, %d Hz, format %d) = port %d%s", type, len, freq, fmt, h + 1,
        p->playing ? "" : " (not heard)");
    RET(c, h + 1);
}
HLE(sceAudioOutClose) {
    const int h = (int)ARG(c, 0) - 1;
    if (h >= 0 && h < AUDIO_PORTS) {
        ports[h].open = 0;
        ports[h].playing = 0;
    }
    RET(c, ORBIS_OK);
}

static void output(int handle, const void* data) {
    const int h = handle - 1;
    if (h < 0 || h >= AUDIO_PORTS || !ports[h].open) {
        return;
    }
    AudioPort* p = &ports[h];
    if (!p->playing || !data) {
        SDL_Delay((Uint32)(p->len * 1000 / 48000));
        return;
    }
    static float out[2 * 4096];
    const int n = p->len < 4096 ? p->len : 4096;
    for (int i = 0; i < n; i++) {
        float s[8];
        for (int k = 0; k < p->channels; k++) {
            s[k] = p->is_float ? ((const float*)data)[i * p->channels + k]
                               : ((const int16_t*)data)[i * p->channels + k] / 32768.0f;
        }
        float l, r;
        if (p->channels == 1) {
            l = r = s[0];
        } else if (p->channels == 2) {
            l = s[0];
            r = s[1];
        } else {
            l = s[0] + 0.707f * s[2] + 0.707f * s[4] + 0.5f * s[6];
            r = s[1] + 0.707f * s[2] + 0.707f * s[5] + 0.5f * s[7];
        }
        out[2 * i] = l * p->volume[0];
        out[2 * i + 1] = r * p->volume[1];
    }
    platform_audio_output(out, n * 8);
}

HLE(sceAudioOutOutput) {
    output((int)ARG(c, 0), ARG(c, 1) ? ARGP(c, 1) : NULL);
    RET(c, ORBIS_OK);
}
HLE(sceAudioOutOutputs) {
    const uint8_t* params = ARGP(c, 0);
    for (uint32_t i = 0; i < (uint32_t)ARG(c, 1); i++) {
        int32_t h;
        uint64_t data;
        memcpy(&h, params + 16 * i, 4);
        memcpy(&data, params + 16 * i + 8, 8);
        output(h, data ? G(data) : NULL);
    }
    RET(c, ORBIS_OK);
}
HLE(sceAudioOutSetVolume) {
    const int h = (int)ARG(c, 0) - 1;
    const uint32_t flags = (uint32_t)ARG(c, 1);
    const int32_t* vol = ARGP(c, 2);
    if (h >= 0 && h < AUDIO_PORTS) {
        for (int i = 0; i < 8; i++) {
            if (flags & (1u << i)) {
                ports[h].volume[i] = vol[i] / 32768.0f;
            }
        }
    }
    RET(c, ORBIS_OK);
}
HLE(sceAudioOutGetPortState) {
    uint8_t* st = ARGP(c, 1);
    memset(st, 0, 32);
    const uint16_t output = 1, channels = 2, volume = 127;
    memcpy(st, &output, 2);
    st[2] = (uint8_t)channels;
    memcpy(st + 4, &volume, 2);
    RET(c, ORBIS_OK);
}

const HleFunc hle_av_funcs[] = {
    HLE_FUNC(sceVideoOutOpen), HLE_FUNC(sceVideoOutClose), HLE_FUNC(sceVideoOutSetFlipRate),
    HLE_FUNC(sceVideoOutSetBufferAttribute), HLE_FUNC(sceVideoOutRegisterBuffers),
    HLE_FUNC(sceVideoOutGetResolutionStatus), HLE_FUNC(sceVideoOutAddFlipEvent),
    HLE_FUNC(scePadInit), HLE_FUNC(scePadOpen), HLE_FUNC(scePadClose), HLE_FUNC(scePadReadState),
    HLE_FUNC_AS("scePadRead", scePadReadState), HLE_FUNC(scePadGetHandle), HLE_FUNC(scePadSetVibration),
    HLE_FUNC(scePadGetControllerInformation),
    HLE_FUNC(sceAudioOutInit), HLE_FUNC(sceAudioOutOpen), HLE_FUNC(sceAudioOutClose), HLE_FUNC(sceAudioOutOutput),
    HLE_FUNC(sceAudioOutOutputs), HLE_FUNC(sceAudioOutSetVolume), HLE_FUNC(sceAudioOutGetPortState),
    {NULL, NULL},
};
