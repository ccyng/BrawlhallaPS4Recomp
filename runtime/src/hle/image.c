#include <stdlib.h>
#include <string.h>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_NO_STDIO
#include "stb_image.h"

#include "hle.h"

#define ORBIS_OK 0
#define PNG_ERROR_INVALID_DATA 0x80690010u
#define JPEG_ERROR_INVALID_DATA 0x80650010u

HLE(dec_query_memory) { RET(c, 0x100); }
HLE(dec_create) {
    *(uint64_t*)ARGP(c, 3) = ARG(c, 1) ? ARG(c, 1) : 1;
    RET(c, ORBIS_OK);
}
HLE(dec_delete) { RET(c, ORBIS_OK); }

static void put_rgba(uint8_t* out, uint32_t pitch, const uint8_t* rgba, int w, int h, int bgra) {
    for (int y = 0; y < h; y++) {
        uint8_t* d = out + (size_t)y * pitch;
        const uint8_t* s = rgba + (size_t)y * w * 4;
        if (!bgra) {
            memcpy(d, s, (size_t)w * 4);
            continue;
        }
        for (int x = 0; x < w; x++) {
            d[4 * x] = s[4 * x + 2];
            d[4 * x + 1] = s[4 * x + 1];
            d[4 * x + 2] = s[4 * x];
            d[4 * x + 3] = s[4 * x + 3];
        }
    }
}

static int png_info(const uint8_t* png, uint32_t size, uint8_t* info) {
    int w, h, comp;
    if (!stbi_info_from_memory(png, (int)size, &w, &h, &comp)) {
        return 0;
    }
    if (info) {
        uint32_t wh[2] = {(uint32_t)w, (uint32_t)h};
        memcpy(info, wh, 8);
        const uint16_t space = png[25] == 3 ? 4 : comp == 1 ? 2 : comp == 2 ? 18 : comp == 3 ? 3 : 19;
        const uint16_t depth = png[24];
        memcpy(info + 8, &space, 2);
        memcpy(info + 10, &depth, 2);
        memset(info + 12, 0, 4);
    }
    return 1;
}

HLE(scePngDecParseHeader) {
    const uint8_t* p = ARGP(c, 0);
    uint64_t png;
    uint32_t size;
    memcpy(&png, p, 8);
    memcpy(&size, p + 8, 4);
    RET(c, png_info(G(png), size, ARGP(c, 1)) ? ORBIS_OK : (int64_t)(int32_t)PNG_ERROR_INVALID_DATA);
}

HLE(scePngDecDecode) {
    const uint8_t* p = ARGP(c, 1);
    uint64_t png, image;
    uint32_t png_size, image_size, pitch;
    uint16_t format;
    memcpy(&png, p, 8);
    memcpy(&image, p + 8, 8);
    memcpy(&png_size, p + 16, 4);
    memcpy(&image_size, p + 20, 4);
    memcpy(&format, p + 24, 2);
    memcpy(&pitch, p + 28, 4);
    int w, h, comp;
    uint8_t* rgba = stbi_load_from_memory(G(png), (int)png_size, &w, &h, &comp, 4);
    if (!rgba) {
        LOG("png: %s", stbi_failure_reason());
        RET(c, (int64_t)(int32_t)PNG_ERROR_INVALID_DATA);
        return;
    }
    if (ARG(c, 2)) {
        png_info(G(png), png_size, ARGP(c, 2));
    }
    if (!pitch) {
        pitch = (uint32_t)w * 4;
    }
    if ((uint64_t)pitch * (uint32_t)h <= image_size) {
        put_rgba(G(image), pitch, rgba, w, h, format == 1);
    }
    stbi_image_free(rgba);
    RET(c, (w > 32767 || h > 32767) ? 0 : ((uint32_t)w << 16) | (uint32_t)h);
}

static int jpeg_info(const uint8_t* jpeg, uint32_t size, uint8_t* info) {
    int w, h, comp;
    if (!stbi_info_from_memory(jpeg, (int)size, &w, &h, &comp)) {
        return 0;
    }
    if (info) {
        const uint32_t v[4] = {(uint32_t)w, (uint32_t)h, (uint32_t)w, (uint32_t)h};
        memset(info, 0, 32);
        memcpy(info, v, 16);
    }
    return 1;
}

HLE(sceJpegDecParseHeader) {
    const uint8_t* p = ARGP(c, 0);
    uint64_t jpeg;
    uint32_t size;
    memcpy(&jpeg, p, 8);
    memcpy(&size, p + 8, 4);
    RET(c, jpeg_info(G(jpeg), size, ARGP(c, 1)) ? ORBIS_OK : (int64_t)(int32_t)JPEG_ERROR_INVALID_DATA);
}

HLE(sceJpegDecDecode) {
    const uint8_t* p = ARGP(c, 1);
    uint64_t jpeg, image;
    uint32_t jpeg_size, image_size, pitch;
    uint16_t format;
    memcpy(&format, p + 38, 2);
    memcpy(&jpeg, p, 8);
    memcpy(&image, p + 8, 8);
    memcpy(&jpeg_size, p + 24, 4);
    memcpy(&image_size, p + 28, 4);
    memcpy(&pitch, p + 44, 4);
    int w, h, comp;
    uint8_t* rgba = stbi_load_from_memory(G(jpeg), (int)jpeg_size, &w, &h, &comp, 4);
    if (!rgba) {
        LOG("jpeg: %s", stbi_failure_reason());
        RET(c, (int64_t)(int32_t)JPEG_ERROR_INVALID_DATA);
        return;
    }
    if (ARG(c, 2)) {
        jpeg_info(G(jpeg), jpeg_size, ARGP(c, 2));
    }
    if (!pitch) {
        pitch = (uint32_t)w * 4;
    }
    if ((uint64_t)pitch * (uint32_t)h <= image_size) {
        put_rgba(G(image), pitch, rgba, w, h, format == 1);
    }
    stbi_image_free(rgba);
    RET(c, ORBIS_OK);
}

const HleFunc hle_image_funcs[] = {
    HLE_FUNC_AS("scePngDecQueryMemorySize", dec_query_memory), HLE_FUNC_AS("scePngDecCreate", dec_create),
    HLE_FUNC_AS("scePngDecDelete", dec_delete), HLE_FUNC(scePngDecParseHeader), HLE_FUNC(scePngDecDecode),
    HLE_FUNC_AS("sceJpegDecQueryMemorySize", dec_query_memory), HLE_FUNC_AS("sceJpegDecCreate", dec_create),
    HLE_FUNC_AS("sceJpegDecDelete", dec_delete), HLE_FUNC(sceJpegDecParseHeader), HLE_FUNC(sceJpegDecDecode),
    {NULL, NULL},
};
