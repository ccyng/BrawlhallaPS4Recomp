#include <string.h>

#include "../gpu.h"
#include "hle.h"

#define ORBIS_OK 0

typedef struct Pm4Writer {
    uint32_t *at, *end;
} Pm4Writer;

static void put_packet(Pm4Writer* w, uint32_t op, int shader_type, const uint32_t* body, uint32_t n) {
    if (w->at + 1 + n > w->end) {
        return;
    }
    *w->at++ = PM4_TYPE3(op, n) | (uint32_t)shader_type << 1;
    memcpy(w->at, body, n * 4);
    w->at += n;
}

#define PACKET(w, op, ...) \
    put_packet((w), (op), 0, (const uint32_t[]){__VA_ARGS__}, sizeof((uint32_t[]){__VA_ARGS__}) / 4)
#define PACKET_CS(w, op, ...) \
    put_packet((w), (op), 1, (const uint32_t[]){__VA_ARGS__}, sizeof((uint32_t[]){__VA_ARGS__}) / 4)

static void finish(Pm4Writer* w) {
    const uint32_t left = (uint32_t)(w->end - w->at);
    if (!left) {
        return;
    }
    if (left == 1) {
        *w->at = 0x80000000u;
        return;
    }
    w->at[0] = PM4_TYPE3(PM4_NOP, left - 1);
    memset(w->at + 1, 0, (left - 1) * 4);
}

static Pm4Writer writer(OgCtx* c) {
    uint32_t* cmd = ARGP(c, 0);
    Pm4Writer w = {cmd, cmd + (uint32_t)ARG(c, 1)};
    return w;
}

HLE(sceGnmSetVsShader) {
    Pm4Writer w = writer(c);
    const uint32_t* r = ARGP(c, 2);
    const uint32_t mod = (uint32_t)ARG(c, 3);
    if (!r) {
        RET(c, -1);
        return;
    }
    const uint32_t rsrc1 = mod ? (r[2] & 0xFCFFFC3Fu) | mod : r[2];
    PACKET(&w, PM4_SET_SH_REG, 0x48, r[0], r[1]);
    PACKET(&w, PM4_SET_SH_REG, 0x4A, rsrc1, r[3]);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x207, r[6]);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x1B1, r[4]);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x1C3, r[5]);
    finish(&w);
    RET(c, ORBIS_OK);
}

static void set_ps(Pm4Writer* w, const uint32_t* r) {
    if (!r) {
        PACKET(w, PM4_SET_SH_REG, 0x08, 0, 0);
        PACKET(w, PM4_SET_CONTEXT_REG, 0x203, 0);
        PACKET(w, PM4_SET_CONTEXT_REG, 0x8F, 0xF);
        return;
    }
    PACKET(w, PM4_SET_SH_REG, 0x08, r[0], r[1]);
    PACKET(w, PM4_SET_SH_REG, 0x0A, r[2], r[3]);
    PACKET(w, PM4_SET_CONTEXT_REG, 0x1C4, r[4], r[5]);
    PACKET(w, PM4_SET_CONTEXT_REG, 0x1B3, r[6], r[7]);
    PACKET(w, PM4_SET_CONTEXT_REG, 0x1B6, r[8]);
    PACKET(w, PM4_SET_CONTEXT_REG, 0x1B8, r[9]);
    PACKET(w, PM4_SET_CONTEXT_REG, 0x203, r[10]);
    PACKET(w, PM4_SET_CONTEXT_REG, 0x8F, r[11]);
}

HLE(sceGnmSetPsShader350) {
    Pm4Writer w = writer(c);
    set_ps(&w, ARGP(c, 2));
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmSetCsShaderWithModifier) {
    Pm4Writer w = writer(c);
    const uint32_t* r = ARGP(c, 2);
    const uint32_t mod = (uint32_t)ARG(c, 3);
    if (!r) {
        RET(c, -1);
        return;
    }
    PACKET_CS(&w, PM4_SET_SH_REG, 0x20C, r[0], r[1]);
    PACKET_CS(&w, PM4_SET_SH_REG, 0x212, mod ? (r[2] & 0xFFFFFC3Fu) | mod : r[2], r[3]);
    PACKET_CS(&w, PM4_SET_SH_REG, 0x207, r[4], r[5], r[6]);
    finish(&w);
    RET(c, ORBIS_OK);
}

static uint32_t *embedded_vs, *embedded_ps[2];

static void embedded_init(void) {
    if (embedded_vs) {
        return;
    }
    static const uint32_t vs[] = {0xbeeb03ffu, 0x00000007u, 0x36020081u, 0x34020281u, 0x360000c2u, 0x4a0202c1u,
                                  0x4a0000c1u, 0x7e020b01u, 0x7e000b00u, 0x7e040280u, 0x7e0602f2u, 0xf80008cfu,
                                  0x03020001u, 0xf800020fu, 0x03030303u, 0xbf810000u};
    static const uint32_t ps0[] = {0xbeeb03ffu, 0x00000003u, 0x7e000280u, 0x5e000100u, 0xbf800000u, 0xf8001c0fu,
                                   0x00000000u, 0xbf810000u};
    static const uint32_t ps1[] = {0xbeeb03ffu, 0x00000003u, 0x7e040280u, 0xf8001803u, 0x02020202u, 0xbf810000u};
    embedded_vs = rt_gpu_alloc(256, 256);
    memcpy(embedded_vs, vs, sizeof vs);
    embedded_ps[0] = rt_gpu_alloc(256, 256);
    memcpy(embedded_ps[0], ps0, sizeof ps0);
    embedded_ps[1] = rt_gpu_alloc(256, 256);
    memcpy(embedded_ps[1], ps1, sizeof ps1);
    gpu_register_embedded(H(embedded_vs), H(embedded_ps[0]), H(embedded_ps[1]));
}

HLE(sceGnmSetEmbeddedVsShader) {
    embedded_init();
    Pm4Writer w = writer(c);
    const uint64_t a = H(embedded_vs);
    PACKET(&w, PM4_SET_SH_REG, 0x48, (uint32_t)(a >> 8), (uint32_t)(a >> 40));
    PACKET(&w, PM4_SET_SH_REG, 0x4A, 0xC0000u, 4);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x207, 7);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x1B1, 0);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x1C3, 4);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmSetEmbeddedPsShader) {
    embedded_init();
    const uint32_t id = (uint32_t)ARG(c, 2);
    if (id > 1) {
        RET(c, -1);
        return;
    }
    const uint64_t a = H(embedded_ps[id]);
    const uint32_t r0[] = {(uint32_t)(a >> 8), (uint32_t)(a >> 40), 0xC0000u, 4, 0, 4, 2, 2, 0, 0, 0x10, 0xF};
    const uint32_t r1[] = {(uint32_t)(a >> 8), (uint32_t)(a >> 40), 0x2000u, 0, 0, 2, 2, 2, 0, 0, 0x10, 3};
    Pm4Writer w = writer(c);
    set_ps(&w, id ? r1 : r0);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmDrawIndex) {
    Pm4Writer w = writer(c);
    const uint64_t addr = ARG(c, 3);
    const uint32_t n = (uint32_t)ARG(c, 2);
    PACKET(&w, PM4_DRAW_INDEX_2, n, (uint32_t)addr, (uint32_t)(addr >> 32), n, 0);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmDrawIndexAuto) {
    Pm4Writer w = writer(c);
    PACKET(&w, PM4_DRAW_INDEX_AUTO, (uint32_t)ARG(c, 2), 2);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmDrawIndexOffset) {
    Pm4Writer w = writer(c);
    const uint32_t n = (uint32_t)ARG(c, 3);
    PACKET(&w, PM4_DRAW_INDEX_OFFSET_2, n, (uint32_t)ARG(c, 2), n, 0);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmDispatchDirect) {
    Pm4Writer w = writer(c);
    PACKET_CS(&w, PM4_DISPATCH_DIRECT, (uint32_t)ARG(c, 2), (uint32_t)ARG(c, 3), (uint32_t)ARG(c, 4),
              ((uint32_t)ARG(c, 5) & 0x18) + 1);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmSetVgtControl) {
    Pm4Writer w = writer(c);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x2AA, (((uint32_t)ARG(c, 3) & 1) << 16) | ((uint32_t)ARG(c, 2) & 0xFFFF));
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(sceGnmResetVgtControl) {
    Pm4Writer w = writer(c);
    PACKET(&w, PM4_SET_CONTEXT_REG, 0x2AA, 0xFF);
    finish(&w);
    RET(c, ORBIS_OK);
}

HLE(gnm_nop) {
    Pm4Writer w = writer(c);
    finish(&w);
    RET(c, ORBIS_OK);
}

static const uint32_t init_sequence_350[] = {
    0xc0017600u, 0x216u, 0xffffffffu, 0xc0017600u, 0x217u, 0xffffffffu, 0xc0017600u, 0x215u,
    0x0u, 0xc0016900u, 0x2f9u, 0x2du, 0xc0016900u, 0x282u, 0x8u, 0xc0016900u,
    0x280u, 0x80008u, 0xc0016900u, 0x281u, 0xffff0000u, 0xc0016900u, 0x204u, 0x0u,
    0xc0016900u, 0x206u, 0x43fu, 0xc0016900u, 0x83u, 0xffffu, 0xc0016900u, 0x317u,
    0x10u, 0xc0016900u, 0x2fau, 0x3f800000u, 0xc0016900u, 0x2fcu, 0x3f800000u, 0xc0016900u,
    0x2fbu, 0x3f800000u, 0xc0016900u, 0x2fdu, 0x3f800000u, 0xc0016900u, 0x202u, 0xcc0010u,
    0xc0016900u, 0x30eu, 0xffffffffu, 0xc0016900u, 0x30fu, 0xffffffffu, 0xc0002f00u, 0x1u,
    0xc0017600u, 0x7u, 0x1701ffu, 0xc0017600u, 0x46u, 0x1701fdu, 0xc0017600u, 0x87u,
    0x1701ffu, 0xc0017600u, 0xc7u, 0x1701fdu, 0xc0017600u, 0x107u, 0x17u, 0xc0017600u,
    0x147u, 0x1701fdu, 0xc0017600u, 0x47u, 0x1cu, 0xc0016900u, 0x1b1u, 0x2u,
    0xc0016900u, 0x101u, 0x0u, 0xc0016900u, 0x100u, 0xffffffffu, 0xc0016900u, 0x103u,
    0x0u, 0xc0016900u, 0x284u, 0x0u, 0xc0016900u, 0x290u, 0x0u, 0xc0016900u,
    0x2aeu, 0x0u, 0xc0016900u, 0x102u, 0x0u, 0xc0016900u, 0x292u, 0x0u,
    0xc0016900u, 0x293u, 0x6020000u, 0xc0016900u, 0x2f8u, 0x0u, 0xc0016900u, 0x2deu,
    0x1e9u, 0xc0036900u, 0x295u, 0x100u, 0x100u, 0x4u, 0xc0017900u, 0x200u,
    0xe0000000u, 0xc0016900u, 0x2aau, 0xffu,
};
static const uint32_t ctx_init_sequence_400[] = {
    0xc0012800u, 0x80000000u, 0x80000000u, 0xc0001200u, 0x0u, 0xc0016900u, 0x2f9u, 0x2du,
    0xc0016900u, 0x282u, 0x8u, 0xc0016900u, 0x280u, 0x80008u, 0xc0016900u, 0x281u,
    0xffff0000u, 0xc0016900u, 0x204u, 0x0u, 0xc0016900u, 0x206u, 0x43fu, 0xc0016900u,
    0x83u, 0xffffu, 0xc0016900u, 0x317u, 0x10u, 0xc0016900u, 0x2fau, 0x3f800000u,
    0xc0016900u, 0x2fcu, 0x3f800000u, 0xc0016900u, 0x2fbu, 0x3f800000u, 0xc0016900u, 0x2fdu,
    0x3f800000u, 0xc0016900u, 0x202u, 0xcc0010u, 0xc0016900u, 0x30eu, 0xffffffffu, 0xc0016900u,
    0x30fu, 0xffffffffu, 0xc0002f00u, 0x1u, 0xc0016900u, 0x1b1u, 0x2u, 0xc0016900u,
    0x101u, 0x0u, 0xc0016900u, 0x100u, 0xffffffffu, 0xc0016900u, 0x103u, 0x0u,
    0xc0016900u, 0x284u, 0x0u, 0xc0016900u, 0x290u, 0x0u, 0xc0016900u, 0x2aeu,
    0x0u, 0xc0016900u, 0x102u, 0x0u, 0xc0016900u, 0x292u, 0x0u, 0xc0016900u,
    0x293u, 0x6020000u, 0xc0016900u, 0x2f8u, 0x0u, 0xc0016900u, 0x2deu, 0x1e9u,
    0xc0036900u, 0x295u, 0x100u, 0x100u, 0x4u, 0xc0016900u, 0x2aau, 0xffu,
    0xc09e1000u, 0x0u,
};

static void put_sequence(OgCtx* c, const uint32_t* seq, uint32_t n, uint32_t total, int clear_state) {
    uint32_t* cmd = ARGP(c, 0);
    Pm4Writer w = {cmd, cmd + total};
    if (clear_state) {
        PACKET(&w, PM4_CLEAR_STATE, 0);
    }
    memcpy(w.at, seq, n * 4);
    w.at += n;
    finish(&w);
    RET(c, total);
}

HLE(sceGnmDrawInitDefaultHardwareState350) {
    if ((uint32_t)ARG(c, 1) < 0x100) {
        RET(c, 0);
        return;
    }
    put_sequence(c, init_sequence_350, sizeof init_sequence_350 / 4, 0x100, 1);
}
HLE(sceGnmDrawInitToDefaultContextState400) {
    if ((uint32_t)ARG(c, 1) < 0x100) {
        RET(c, 0);
        return;
    }
    put_sequence(c, ctx_init_sequence_400, sizeof ctx_init_sequence_400 / 4, 0x100, 0);
}
HLE(gnm_init_state) {
    const uint32_t size = (uint32_t)ARG(c, 1);
    if (size < 0x100) {
        RET(c, 0);
        return;
    }
    uint32_t* cmd = ARGP(c, 0);
    Pm4Writer w = {cmd, cmd + 0x100};
    finish(&w);
    RET(c, 0x100);
}

static uint64_t eop_queue, eop_ident, eop_udata;

HLE(sceGnmAddEqEvent) {
    eop_queue = ARG(c, 0);
    eop_ident = ARG(c, 1);
    eop_udata = ARG(c, 2);
    RET(c, ORBIS_OK);
}
HLE(sceGnmDeleteEqEvent) {
    eop_queue = 0;
    RET(c, ORBIS_OK);
}
HLE(sceGnmGetEqEventType) { RET(c, 0x40);   }

static void submit(OgCtx* c, int flip) {
    GpuSubmit s;
    s.count = (uint32_t)ARG(c, 0);
    s.dcb = ARGP(c, 1);
    s.dcb_size = ARGP(c, 2);
    s.ccb = ARGP(c, 3);
    s.ccb_size = ARGP(c, 4);
    s.flip = flip;
    s.flip_buffer = flip ? (int)ARGS(c, 6) : -1;
    s.flip_arg = flip ? (int64_t)ARGS(c, 8) : 0;
    gpu_submit(&s);
    if (eop_queue) {
        hle_equeue_trigger(eop_queue, eop_ident, -14  , eop_udata);
    }
}

HLE(sceGnmSubmitCommandBuffers) {
    submit(c, 0);
    RET(c, ORBIS_OK);
}
HLE(sceGnmSubmitAndFlipCommandBuffers) {
    submit(c, 1);
    RET(c, ORBIS_OK);
}
HLE(sceGnmSubmitCommandBuffersForWorkload) {
    const uint64_t saved[6] = {ARG(c, 0), ARG(c, 1), ARG(c, 2), ARG(c, 3), ARG(c, 4), ARG(c, 5)};
    for (int i = 0; i < 5; i++) {
        ARG(c, i) = saved[i + 1];
    }
    submit(c, 0);
    for (int i = 0; i < 6; i++) {
        ARG(c, i) = saved[i];
    }
    RET(c, ORBIS_OK);
}
HLE(sceGnmSubmitDone) { RET(c, ORBIS_OK); }
HLE(sceGnmAreSubmitsAllowed) { RET(c, 1); }
HLE(sceGnmFlushGarlic) { (void)c; }
HLE(sceGnmIsUserPaEnabled) { RET(c, 0); }
HLE(sceGnmDriverCaptureInProgress) { RET(c, 0); }
HLE(sceGnmDriverTraceInProgress) { RET(c, 0); }
HLE(sceGnmGetGpuInfoStatus) { RET(c, 0); }
HLE(sceGnmRegisterOwner) {
    if (ARG(c, 0)) {
        *(uint32_t*)ARGP(c, 0) = 1;
    }
    RET(c, ORBIS_OK);
}
HLE(sceGnmRegisterResource) {
    if (ARG(c, 0)) {
        *(uint32_t*)ARGP(c, 0) = 1;
    }
    RET(c, ORBIS_OK);
}
HLE(sceGnmGetTheTessellationFactorRingBufferBaseAddress) {
    static void* ring;
    if (!ring) {
        ring = rt_gpu_alloc(0x20000, 0x10000);
    }
    RET(c, H(ring));
}

HLE(sceGnmGetNumTcaUnits) { RET(c, 0); }
HLE(sceGnmLogicalTcaUnitToPhysical) { RET(c, (int64_t)(int32_t)ARG(c, 0)); }
HLE(sceGnmGetPhysicalCounterFromVirtualized) { RET(c, ORBIS_OK); }
HLE(sceGnmMapComputeQueue) {
    static int next = 1;
    RET(c, next++);
}
HLE(sceGnmDingDong) { (void)c; }

const HleFunc hle_gnm_funcs[] = {
    HLE_FUNC(sceGnmGetNumTcaUnits), HLE_FUNC(sceGnmLogicalTcaUnitToPhysical), HLE_FUNC(sceGnmGetPhysicalCounterFromVirtualized),
    HLE_FUNC(sceGnmMapComputeQueue), HLE_FUNC_AS("sceGnmMapComputeQueueWithPriority", sceGnmMapComputeQueue),
    HLE_FUNC(sceGnmDingDong), HLE_FUNC_AS("sceGnmDingDongForWorkload", sceGnmDingDong),
    HLE_FUNC_AS("sceGnmValidateDisableDiagnostics", sceGnmGetPhysicalCounterFromVirtualized),
    HLE_FUNC(sceGnmSetVsShader), HLE_FUNC(sceGnmSetPsShader350), HLE_FUNC(sceGnmSetCsShaderWithModifier),
    HLE_FUNC_AS("sceGnmUpdateVsShader", sceGnmSetVsShader), HLE_FUNC_AS("sceGnmUpdatePsShader350", sceGnmSetPsShader350),
    HLE_FUNC(sceGnmSetEmbeddedVsShader), HLE_FUNC(sceGnmSetEmbeddedPsShader),
    HLE_FUNC(sceGnmDrawIndex), HLE_FUNC(sceGnmDrawIndexAuto), HLE_FUNC(sceGnmDrawIndexOffset),
    HLE_FUNC(sceGnmDispatchDirect), HLE_FUNC(sceGnmSetVgtControl), HLE_FUNC(sceGnmResetVgtControl),
    HLE_FUNC_AS("sceGnmDispatchIndirect", gnm_nop),
    HLE_FUNC_AS("sceGnmDispatchIndirectOnMec", gnm_nop),
    HLE_FUNC_AS("sceGnmDrawIndexIndirect", gnm_nop),
    HLE_FUNC_AS("sceGnmDrawIndexIndirectCountMulti", gnm_nop),
    HLE_FUNC_AS("sceGnmDrawIndexMultiInstanced", gnm_nop),
    HLE_FUNC_AS("sceGnmDrawIndirect", gnm_nop),
    HLE_FUNC_AS("sceGnmDrawIndirectCountMulti", gnm_nop),
    HLE_FUNC_AS("sceGnmDrawOpaqueAuto", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertPopMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertPushColorMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertPushMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertSetColorMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertSetMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertThreadTraceMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertDingDongMarker", gnm_nop),
    HLE_FUNC_AS("sceGnmInsertWaitFlipDone", gnm_nop),
    HLE_FUNC_AS("sceGnmComputeWaitOnAddress", gnm_nop),
    HLE_FUNC_AS("sceGnmComputeWaitSemaphore", gnm_nop),
    HLE_FUNC_AS("sceGnmSetHsShader", gnm_nop),
    HLE_FUNC_AS("sceGnmSetEsShader", gnm_nop),
    HLE_FUNC_AS("sceGnmSetGsShader", gnm_nop),
    HLE_FUNC_AS("sceGnmSetLsShader", gnm_nop),
    HLE_FUNC_AS("sceGnmUpdateGsShader", gnm_nop),
    HLE_FUNC_AS("sceGnmUpdateHsShader", gnm_nop),
    HLE_FUNC_AS("sceGnmSetWaveLimitMultipliers", gnm_nop),
    HLE_FUNC(sceGnmDrawInitDefaultHardwareState350),
    HLE_FUNC_AS("sceGnmDispatchInitDefaultHardwareState", gnm_init_state),
    HLE_FUNC(sceGnmDrawInitToDefaultContextState400),
    HLE_FUNC(sceGnmAddEqEvent), HLE_FUNC(sceGnmDeleteEqEvent), HLE_FUNC(sceGnmGetEqEventType),
    HLE_FUNC(sceGnmSubmitCommandBuffers), HLE_FUNC(sceGnmSubmitAndFlipCommandBuffers),
    HLE_FUNC(sceGnmSubmitCommandBuffersForWorkload),
    HLE_FUNC(sceGnmSubmitDone), HLE_FUNC(sceGnmAreSubmitsAllowed), HLE_FUNC(sceGnmFlushGarlic),
    HLE_FUNC(sceGnmIsUserPaEnabled), HLE_FUNC(sceGnmDriverCaptureInProgress), HLE_FUNC(sceGnmDriverTraceInProgress),
    HLE_FUNC(sceGnmGetGpuInfoStatus), HLE_FUNC(sceGnmRegisterOwner), HLE_FUNC(sceGnmRegisterResource),
    HLE_FUNC(sceGnmGetTheTessellationFactorRingBufferBaseAddress),
    {NULL, NULL},
};
