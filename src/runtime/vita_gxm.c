#ifdef __vita__
#include <stdlib.h>
#include <string.h>

#include <psp2/display.h>
#include <psp2/gxm.h>
#include <psp2/kernel/sysmem.h>

#include "runtime.h"
#include "vita_gxm.h"

extern const SceGxmProgram texture_v_gxp_start, texture_f_gxp_start;

#define FB_W 960
#define FB_H 544
#define BUFFERS 2
#define TEX_MAX_W 1280
#define TEX_MAX_H 720

typedef struct Vertex {
    float x, y, z, u, v;
} Vertex;

typedef struct DisplayData {
    void* addr;
} DisplayData;

static SceGxmContext* context;
static SceGxmRenderTarget* target;
static SceGxmShaderPatcher* patcher;
static SceGxmVertexProgram* vertex_program;
static SceGxmFragmentProgram* fragment_program;
static const SceGxmProgramParameter* wvp;
static void* fb[BUFFERS];
static SceGxmColorSurface surface[BUFFERS];
static SceGxmSyncObject* sync[BUFFERS];
static SceGxmDepthStencilSurface depth;
static Vertex* quad;
static uint16_t* indices;
static uint16_t* texels;
static int back, front;

static void* gpu_alloc(SceKernelMemBlockType type, size_t size, SceGxmMemoryAttribFlags attr) {
    const size_t unit = type == SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW ? 0x40000 : 0x1000;
    size = (size + unit - 1) & ~(unit - 1);
    const SceUID uid = sceKernelAllocMemBlock("mania_gpu", type, size, NULL);
    void* p = NULL;
    if (uid < 0 || sceKernelGetMemBlockBase(uid, &p) < 0 || sceGxmMapMemory(p, size, attr) < 0) {
        rt_fatal("GPU memory: %zu bytes of type %#x (%#x)", size, (unsigned)type, (unsigned)uid);
    }
    return p;
}

static void* usse_alloc(size_t size, int fragment, unsigned* offset) {
    size = (size + 0xFFF) & ~(size_t)0xFFF;
    const SceUID uid = sceKernelAllocMemBlock("mania_usse", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, size, NULL);
    void* p = NULL;
    if (uid < 0 || sceKernelGetMemBlockBase(uid, &p) < 0) {
        rt_fatal("USSE memory: %zu bytes (%#x)", size, (unsigned)uid);
    }
    const int r = fragment ? sceGxmMapFragmentUsseMemory(p, size, offset) : sceGxmMapVertexUsseMemory(p, size, offset);
    if (r < 0) {
        rt_fatal("USSE mapping (%#x)", (unsigned)r);
    }
    return p;
}

static void* patcher_alloc(void* user, SceSize size) {
    (void)user;
    return malloc(size);
}

static void patcher_free(void* user, void* mem) {
    (void)user;
    free(mem);
}

static void display_callback(const void* data) {
    const DisplayData* d = data;
    SceDisplayFrameBuf f = {sizeof f, d->addr, FB_W, SCE_DISPLAY_PIXELFORMAT_A8B8G8R8, FB_W, FB_H};
    sceDisplaySetFrameBuf(&f, SCE_DISPLAY_SETBUF_NEXTFRAME);
    sceDisplayWaitVblankStart();
}

#define CHECK(call)                                                   \
    do {                                                              \
        const int r_ = (call);                                        \
        if (r_ < 0) {                                                 \
            rt_fatal("%s failed (%#x)", #call, (unsigned)r_);         \
        }                                                             \
    } while (0)

void vita_display_init(void) {
    SceGxmInitializeParams init = {0};
    init.displayQueueMaxPendingCount = BUFFERS - 1;
    init.displayQueueCallback = display_callback;
    init.displayQueueCallbackDataSize = sizeof(DisplayData);
    init.parameterBufferSize = 4u << 20;
    CHECK(sceGxmInitialize(&init));

    SceGxmContextParams cp = {0};
    cp.hostMem = malloc(SCE_GXM_MINIMUM_CONTEXT_HOST_MEM_SIZE);
    cp.hostMemSize = SCE_GXM_MINIMUM_CONTEXT_HOST_MEM_SIZE;
    cp.vdmRingBufferMem = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, SCE_GXM_DEFAULT_VDM_RING_BUFFER_SIZE,
                                    SCE_GXM_MEMORY_ATTRIB_READ);
    cp.vdmRingBufferMemSize = SCE_GXM_DEFAULT_VDM_RING_BUFFER_SIZE;
    cp.vertexRingBufferMem = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE,
                                       SCE_GXM_DEFAULT_VERTEX_RING_BUFFER_SIZE, SCE_GXM_MEMORY_ATTRIB_READ);
    cp.vertexRingBufferMemSize = SCE_GXM_DEFAULT_VERTEX_RING_BUFFER_SIZE;
    cp.fragmentRingBufferMem = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE,
                                         SCE_GXM_DEFAULT_FRAGMENT_RING_BUFFER_SIZE, SCE_GXM_MEMORY_ATTRIB_READ);
    cp.fragmentRingBufferMemSize = SCE_GXM_DEFAULT_FRAGMENT_RING_BUFFER_SIZE;
    cp.fragmentUsseRingBufferMem =
        usse_alloc(SCE_GXM_DEFAULT_FRAGMENT_USSE_RING_BUFFER_SIZE, 1, &cp.fragmentUsseRingBufferOffset);
    cp.fragmentUsseRingBufferMemSize = SCE_GXM_DEFAULT_FRAGMENT_USSE_RING_BUFFER_SIZE;
    CHECK(sceGxmCreateContext(&cp, &context));

    SceGxmRenderTargetParams rt = {0};
    rt.width = FB_W;
    rt.height = FB_H;
    rt.scenesPerFrame = 1;
    rt.multisampleMode = SCE_GXM_MULTISAMPLE_NONE;
    rt.driverMemBlock = -1;
    CHECK(sceGxmCreateRenderTarget(&rt, &target));

    for (int i = 0; i < BUFFERS; i++) {
        fb[i] = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW, FB_W * FB_H * 4, SCE_GXM_MEMORY_ATTRIB_RW);
        memset(fb[i], 0, FB_W * FB_H * 4);
        CHECK(sceGxmColorSurfaceInit(&surface[i], SCE_GXM_COLOR_FORMAT_A8B8G8R8, SCE_GXM_COLOR_SURFACE_LINEAR,
                                     SCE_GXM_COLOR_SURFACE_SCALE_NONE, SCE_GXM_OUTPUT_REGISTER_SIZE_32BIT, FB_W, FB_H,
                                     FB_W, fb[i]));
        CHECK(sceGxmSyncObjectCreate(&sync[i]));
    }

    const unsigned depth_w = (FB_W + 31) & ~31u, depth_h = (FB_H + 31) & ~31u;
    void* depth_mem = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, 4 * depth_w * depth_h,
                                SCE_GXM_MEMORY_ATTRIB_RW);
    CHECK(sceGxmDepthStencilSurfaceInit(&depth, SCE_GXM_DEPTH_STENCIL_FORMAT_S8D24,
                                        SCE_GXM_DEPTH_STENCIL_SURFACE_TILED, depth_w, depth_mem, NULL));

    const size_t patcher_size = 64 * 1024;
    SceGxmShaderPatcherParams pp = {0};
    pp.hostAllocCallback = patcher_alloc;
    pp.hostFreeCallback = patcher_free;
    pp.bufferMem = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, patcher_size, SCE_GXM_MEMORY_ATTRIB_READ);
    pp.bufferMemSize = patcher_size;
    pp.vertexUsseMem = usse_alloc(patcher_size, 0, &pp.vertexUsseOffset);
    pp.vertexUsseMemSize = patcher_size;
    pp.fragmentUsseMem = usse_alloc(patcher_size, 1, &pp.fragmentUsseOffset);
    pp.fragmentUsseMemSize = patcher_size;
    CHECK(sceGxmShaderPatcherCreate(&pp, &patcher));

    SceGxmShaderPatcherId vid, fid;
    CHECK(sceGxmShaderPatcherRegisterProgram(patcher, &texture_v_gxp_start, &vid));
    CHECK(sceGxmShaderPatcherRegisterProgram(patcher, &texture_f_gxp_start, &fid));
    const SceGxmProgramParameter* pos = sceGxmProgramFindParameterByName(&texture_v_gxp_start, "aPosition");
    const SceGxmProgramParameter* uv = sceGxmProgramFindParameterByName(&texture_v_gxp_start, "aTexcoord");
    wvp = sceGxmProgramFindParameterByName(&texture_v_gxp_start, "wvp");
    if (!pos || !uv || !wvp) {
        rt_fatal("vita2d's texture shader lacks aPosition/aTexcoord/wvp");
    }
    SceGxmVertexAttribute attrs[2] = {
        {0, 0, SCE_GXM_ATTRIBUTE_FORMAT_F32, 3, (uint16_t)sceGxmProgramParameterGetResourceIndex(pos)},
        {0, 12, SCE_GXM_ATTRIBUTE_FORMAT_F32, 2, (uint16_t)sceGxmProgramParameterGetResourceIndex(uv)},
    };
    SceGxmVertexStream stream = {sizeof(Vertex), SCE_GXM_INDEX_SOURCE_INDEX_16BIT};
    CHECK(sceGxmShaderPatcherCreateVertexProgram(patcher, vid, attrs, 2, &stream, 1, &vertex_program));
    CHECK(sceGxmShaderPatcherCreateFragmentProgram(patcher, fid, SCE_GXM_OUTPUT_REGISTER_FORMAT_UCHAR4,
                                                   SCE_GXM_MULTISAMPLE_NONE, NULL, &texture_v_gxp_start,
                                                   &fragment_program));

    quad = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, 4 * sizeof(Vertex), SCE_GXM_MEMORY_ATTRIB_READ);
    const Vertex v[4] = {{-1, 1, 0.5f, 0, 0}, {1, 1, 0.5f, 1, 0}, {-1, -1, 0.5f, 0, 1}, {1, -1, 0.5f, 1, 1}};
    memcpy(quad, v, sizeof v);
    indices = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, 4 * sizeof(uint16_t), SCE_GXM_MEMORY_ATTRIB_READ);
    for (uint16_t i = 0; i < 4; i++) {
        indices[i] = i;
    }
    texels = gpu_alloc(SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE, TEX_MAX_W * TEX_MAX_H * 2,
                       SCE_GXM_MEMORY_ATTRIB_READ);
    front = BUFFERS - 1;
    back = 0;
    LOG("GXM: %dx%d, %d buffers", FB_W, FB_H, BUFFERS);
}

void vita_display_present(const uint16_t* pixels, int width, int height) {
    if (width > TEX_MAX_W || height > TEX_MAX_H || (width & 7)) {
        return;
    }
    memcpy(texels, pixels, (size_t)width * height * 2);
    SceGxmTexture tex;
    sceGxmTextureInitLinear(&tex, texels, SCE_GXM_TEXTURE_FORMAT_R5G6B5, (unsigned)width, (unsigned)height, 0);
    sceGxmTextureSetMinFilter(&tex, SCE_GXM_TEXTURE_FILTER_POINT);
    sceGxmTextureSetMagFilter(&tex, SCE_GXM_TEXTURE_FILTER_POINT);

    sceGxmBeginScene(context, 0, target, NULL, NULL, sync[back], &surface[back], &depth);
    sceGxmSetVertexProgram(context, vertex_program);
    sceGxmSetFragmentProgram(context, fragment_program);
    void* uniforms;
    sceGxmReserveVertexDefaultUniformBuffer(context, &uniforms);
    static const float identity[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    sceGxmSetUniformDataF(uniforms, wvp, 0, 16, identity);
    sceGxmSetFragmentTexture(context, 0, &tex);
    sceGxmSetVertexStream(context, 0, quad);
    sceGxmDraw(context, SCE_GXM_PRIMITIVE_TRIANGLE_STRIP, SCE_GXM_INDEX_FORMAT_U16, indices, 4);
    sceGxmEndScene(context, NULL, NULL);
    sceGxmPadHeartbeat(&surface[back], sync[back]);

    DisplayData d = {fb[back]};
    sceGxmDisplayQueueAddEntry(sync[front], sync[back], &d);
    sceGxmFinish(context);
    front = back;
    back = (back + 1) % BUFFERS;
}
#endif
