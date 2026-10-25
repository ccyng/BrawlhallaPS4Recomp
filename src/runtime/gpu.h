#pragma once

#include <stdint.h>

enum {
    PM4_NOP = 0x10,
    PM4_SET_BASE = 0x11,
    PM4_CLEAR_STATE = 0x12,
    PM4_INDEX_BUFFER_SIZE = 0x13,
    PM4_DISPATCH_DIRECT = 0x15,
    PM4_DISPATCH_INDIRECT = 0x16,
    PM4_ATOMIC_MEM = 0x1E,
    PM4_OCCLUSION_QUERY = 0x1F,
    PM4_SET_PREDICATION = 0x20,
    PM4_INDEX_BASE = 0x26,
    PM4_DRAW_INDEX_2 = 0x27,
    PM4_CONTEXT_CONTROL = 0x28,
    PM4_INDEX_TYPE = 0x2A,
    PM4_DRAW_INDIRECT = 0x24,
    PM4_DRAW_INDEX_INDIRECT = 0x25,
    PM4_DRAW_INDEX_AUTO = 0x2D,
    PM4_NUM_INSTANCES = 0x2F,
    PM4_DRAW_INDEX_MULTI_AUTO = 0x30,
    PM4_INDIRECT_BUFFER_CONST = 0x33,
    PM4_STRMOUT_BUFFER_UPDATE = 0x34,
    PM4_DRAW_INDEX_OFFSET_2 = 0x35,
    PM4_WRITE_DATA = 0x37,
    PM4_MEM_SEMAPHORE = 0x39,
    PM4_WAIT_REG_MEM = 0x3C,
    PM4_INDIRECT_BUFFER = 0x3F,
    PM4_COPY_DATA = 0x40,
    PM4_PFP_SYNC_ME = 0x42,
    PM4_SURFACE_SYNC = 0x43,
    PM4_EVENT_WRITE = 0x46,
    PM4_EVENT_WRITE_EOP = 0x47,
    PM4_EVENT_WRITE_EOS = 0x48,
    PM4_RELEASE_MEM = 0x49,
    PM4_DMA_DATA = 0x50,
    PM4_ACQUIRE_MEM = 0x58,
    PM4_REWIND = 0x59,
    PM4_LOAD_UCONFIG_REG = 0x5E,
    PM4_LOAD_SH_REG = 0x5F,
    PM4_LOAD_CONFIG_REG = 0x60,
    PM4_LOAD_CONTEXT_REG = 0x61,
    PM4_SET_CONFIG_REG = 0x68,
    PM4_SET_CONTEXT_REG = 0x69,
    PM4_SET_CONTEXT_REG_INDIRECT = 0x73,
    PM4_SET_SH_REG = 0x76,
    PM4_SET_SH_REG_OFFSET = 0x77,
    PM4_SET_QUEUE_REG = 0x78,
    PM4_SET_UCONFIG_REG = 0x79,
    PM4_WRITE_CONST_RAM = 0x81,
    PM4_DUMP_CONST_RAM = 0x83,
    PM4_INCREMENT_CE_COUNTER = 0x84,
    PM4_INCREMENT_DE_COUNTER = 0x85,
    PM4_WAIT_ON_CE_COUNTER = 0x86,
    PM4_WAIT_ON_DE_COUNTER_DIFF = 0x88,
};

#define PM4_TYPE3(op, n) (0xC0000000u | ((uint32_t)(n) - 1) << 16 | (uint32_t)(op) << 8)

typedef struct GpuSubmit {
    uint32_t count;
    const uint64_t* dcb;
    const uint32_t* dcb_size;
    const uint64_t* ccb;
    const uint32_t* ccb_size;
    int flip, flip_buffer;
    int64_t flip_arg;
} GpuSubmit;

void gpu_submit(const GpuSubmit* s);

void gpu_init(void);
int gpu_service(void);
void gpu_present(int w, int h);
int gpu_read_frame(uint8_t** rgba, int* w, int* h);
void gpu_flip_shown(void);

void gpu_set_display_buffers(int first, int count, const uint64_t* addrs, uint32_t width, uint32_t height,
                             uint32_t pitch, uint32_t format, uint32_t tiling);
void gpu_set_flip_event(uint64_t equeue, uint64_t udata);
void gpu_register_embedded(uint64_t vs, uint64_t ps0, uint64_t ps1);

void* rt_gpu_alloc(uint64_t size, uint64_t align);
