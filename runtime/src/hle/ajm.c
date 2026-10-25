#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <SDL.h>

#include "libatrac9.h"

#include "hle.h"

#define ORBIS_OK 0
#define AJM_ERROR_INVALID_INSTANCE 0x80930006u

enum { CODEC_AT9 = 1 };
enum { FMT_S16, FMT_S32, FMT_FLOAT };
enum { AT9_PARSE_RIFF = 1, AT9_NON_INTERLEAVED = 1 << 8 };
enum { CONTROL_RESET = 1, CONTROL_INIT = 2, CONTROL_RESAMPLE = 4 };
enum { RUN_CODEC_INFO = 1, RUN_MULTIPLE_FRAMES = 2 };
enum { SIDEBAND_GAPLESS = 1, SIDEBAND_FORMAT = 2, SIDEBAND_STREAM = 4 };
enum {
    RESULT_NOT_INITIALIZED = 1,
    RESULT_INVALID_PARAMETER = 4,
    RESULT_PARTIAL_INPUT = 8,
    RESULT_NOT_ENOUGH_ROOM = 0x10,
    RESULT_CODEC_ERROR = 0x40000000,
    RESULT_FATAL = (int)0x80000000,
};

typedef struct Gapless {
    uint32_t total_samples;
    uint16_t skip_samples, skipped_samples;
} Gapless;

typedef struct Instance {
    int used, codec, format, channels, at9_flags, gapless_loop;
    void* at9;
    Atrac9CodecInfo info;
    uint8_t config[4];
    int initialized;
    uint32_t superframe_left, frames;
    uint64_t total_samples;
    Gapless g_init, g_cur;
    float pcm[256 * 8 * 2];
} Instance;

#define MAX_INSTANCES 256
static Instance instances[MAX_INSTANCES];
static SDL_mutex* lock;
static SDL_cond* queued;
static SDL_cond* finished;

static int pcm_size(int format) {
    return format == FMT_S16 ? 2 : 4;
}

static uint32_t channel_mask(int ch) {
    switch (ch) {
    case 1: return 0x4;
    case 2: return 0x3;
    case 4: return 0x33;
    case 6: return 0x60F;
    default: return 0x63F;
    }
}

static int gapless_end(const Instance* in) {
    return in->g_init.total_samples && !in->g_cur.total_samples;
}

static void gapless_reset(Instance* in) {
    in->g_cur.total_samples = in->g_init.total_samples;
    in->g_cur.skip_samples = in->g_init.skip_samples;
    in->g_cur.skipped_samples = 0;
}

static void at9_reset(Instance* in) {
    if (in->at9) {
        Atrac9ReleaseHandle(in->at9);
    }
    in->at9 = Atrac9GetHandle();
    Atrac9InitDecoder(in->at9, in->config);
    Atrac9GetCodecInfo(in->at9, &in->info);
    in->frames = 0;
    in->superframe_left = (uint32_t)in->info.superframeSize;
}

static void at9_init(Instance* in, const uint8_t config[4]) {
    memcpy(in->config, config, 4);
    at9_reset(in);
    in->initialized = 1;
}

static int parse_riff(Instance* in, const uint8_t** p, uint32_t* n) {
    const uint8_t* d = *p;
    uint32_t left = *n;
    if (left < 20 || memcmp(d, "RIFF", 4) || memcmp(d + 8, "WAVE", 4)) {
        return 0;
    }
    d += 12;
    left -= 12;
    int ok = 0;
    while (left >= 8) {
        uint32_t len;
        memcpy(&len, d + 4, 4);
        const int is_data = !memcmp(d, "data", 4);
        const uint8_t* body = d + 8;
        d += 8;
        left -= 8;
        if (is_data) {
            break;
        }
        if (left < len) {
            return 0;
        }
        if (!memcmp(body - 8, "fmt ", 4) && len >= 52) {
            at9_init(in, body + 44);
            ok = 1;
        } else if (!memcmp(body - 8, "fact", 4) && len >= 12) {
            memcpy(&in->g_init.total_samples, body, 4);
            uint32_t delay;
            memcpy(&delay, body + 4, 4);
            in->g_init.skip_samples = (uint16_t)delay;
            gapless_reset(in);
        }
        const uint32_t adv = (len + 1) & ~1u;
        d += adv < left ? adv : left;
        left -= adv < left ? adv : left;
    }
    *p = d;
    *n = left;
    return ok;
}

static uint32_t next_frame_bytes(const Instance* in) {
    const uint32_t fs = (uint32_t)in->info.frameSamples;
    const uint32_t skip = in->g_cur.skip_samples < fs ? in->g_cur.skip_samples : fs;
    uint32_t samples = fs - skip;
    if (in->g_init.total_samples && in->g_cur.total_samples < samples) {
        samples = in->g_cur.total_samples;
    }
    return samples * (uint32_t)in->info.channels * (uint32_t)pcm_size(in->format);
}

typedef struct Out {
    uint64_t addr[8], size[8];
    int n, i;
    uint64_t at;
} Out;

static uint64_t out_room(const Out* o) {
    uint64_t r = 0;
    for (int k = o->i; k < o->n; k++) {
        r += o->size[k] - (k == o->i ? o->at : 0);
    }
    return r;
}

static void out_put(Out* o, const void* src, uint64_t n) {
    const uint8_t* s = src;
    while (n && o->i < o->n) {
        const uint64_t room = o->size[o->i] - o->at;
        const uint64_t k = n < room ? n : room;
        memcpy((uint8_t*)G(o->addr[o->i]) + o->at, s, k);
        s += k;
        n -= k;
        o->at += k;
        if (o->at == o->size[o->i]) {
            o->i++;
            o->at = 0;
        }
    }
}

static int decode_frame(Instance* in, const uint8_t** p, uint32_t* n, Out* out, int* frames) {
    const int ch = in->info.channels, fs = in->info.frameSamples;
    int used = 0, ret;
    void* pcm = in->pcm;
    const int ni = (in->at9_flags & AT9_NON_INTERLEAVED) != 0;
    if (in->format == FMT_S16) {
        ret = Atrac9Decode(in->at9, *p, (int)*n, pcm, &used, ni);
    } else if (in->format == FMT_S32) {
        ret = Atrac9DecodeS32(in->at9, *p, (int)*n, pcm, &used, ni);
    } else {
        ret = Atrac9DecodeF32(in->at9, *p, (int)*n, pcm, &used, ni);
    }
    if (ret) {
        return -1;
    }
    (*frames)++;
    *p += used;
    *n -= (uint32_t)used;
    in->superframe_left -= (uint32_t)used;
    uint32_t skip = 0;
    if (in->g_cur.skip_samples) {
        skip = in->g_cur.skip_samples < (uint32_t)fs ? in->g_cur.skip_samples : (uint32_t)fs;
        in->g_cur.skip_samples -= (uint16_t)skip;
    }
    uint32_t samples = (uint32_t)fs - skip;
    if (in->g_init.total_samples && in->g_cur.total_samples < samples) {
        samples = in->g_cur.total_samples;
    }
    const int bps = pcm_size(in->format);
    out_put(out, (uint8_t*)pcm + (size_t)skip * ch * bps, (uint64_t)samples * ch * bps);
    in->g_cur.skipped_samples += (uint16_t)((uint32_t)fs - samples);
    if (in->g_init.total_samples) {
        in->g_cur.total_samples -= samples;
    }
    in->frames++;
    if (in->frames % (uint32_t)in->info.framesInSuperframe == 0) {
        const uint32_t skip_bytes = in->superframe_left < *n ? in->superframe_left : *n;
        *p += skip_bytes;
        *n -= skip_bytes;
        in->superframe_left = (uint32_t)in->info.superframeSize;
        in->frames = 0;
    } else if (gapless_end(in)) {
        while (in->frames % (uint32_t)in->info.framesInSuperframe && *n) {
            if (Atrac9Decode(in->at9, *p, (int)*n, (short*)in->pcm, &used, 0)) {
                break;
            }
            *p += used;
            *n -= (uint32_t)used;
            in->superframe_left -= (uint32_t)used;
            in->frames++;
            (*frames)++;
        }
        const uint32_t skip_bytes = in->superframe_left < *n ? in->superframe_left : *n;
        *p += skip_bytes;
        *n -= skip_bytes;
        in->superframe_left = (uint32_t)in->info.superframeSize;
        in->frames = 0;
    }
    return (int)samples;
}

#define JOB_CONTROL 0x4A4D4A43u
#define JOB_RUN 0x4A4D4A52u

typedef struct Job {
    uint32_t magic, instance;
    uint64_t flags;
    uint64_t sb_in, sb_in_size, sb_out, sb_out_size;
    uint32_t n_in, n_out;
    uint64_t buf[];
} Job;

#define BUILT_MAX 1024
static uint64_t built[BUILT_MAX];
static int built_count;
static SDL_SpinLock built_lock;

static size_t job_size(const Job* j) {
    return sizeof *j + 16u * (j->n_in + j->n_out);
}

static void job_built(const Job* j) {
    SDL_AtomicLock(&built_lock);
    if (built_count == BUILT_MAX) {
        memmove(built, built + 1, sizeof *built * (BUILT_MAX - 1));
        built_count--;
    }
    built[built_count++] = H(j);
    SDL_AtomicUnlock(&built_lock);
}

static uint8_t* take_built(uint64_t addr, uint64_t size, uint32_t* out_size) {
    SDL_AtomicLock(&built_lock);
    size_t total = 0;
    for (int i = 0; i < built_count; i++) {
        if (built[i] >= addr && built[i] < addr + size) {
            total += job_size(G(built[i]));
        }
    }
    uint8_t* jobs = malloc(total ? total : 1);
    size_t at = 0;
    int kept = 0;
    for (int i = 0; i < built_count; i++) {
        if (built[i] >= addr && built[i] < addr + size) {
            const Job* j = G(built[i]);
            memcpy(jobs + at, j, job_size(j));
            at += job_size(j);
        } else {
            built[kept++] = built[i];
        }
    }
    built_count = kept;
    SDL_AtomicUnlock(&built_lock);
    *out_size = (uint32_t)total;
    return jobs;
}

static void* take(uint64_t* at, uint64_t* left, size_t n) {
    if (!*at || *left < n) {
        return NULL;
    }
    void* p = G(*at);
    *at += n;
    *left -= n;
    return p;
}

static void run_job(const Job* j) {
    Instance* in = j->instance < MAX_INSTANCES ? &instances[j->instance] : NULL;
    const uint32_t control = (uint32_t)(j->flags >> 13) & 7, run = (uint32_t)(j->flags >> 11) & 3;
    const uint32_t sideband = (uint32_t)(j->flags >> 45) & 7;

    uint64_t at = j->sb_out, left = j->sb_out_size;
    int32_t* result = take(&at, &left, 8);
    uint8_t* stream = (sideband & SIDEBAND_STREAM) ? take(&at, &left, 16) : NULL;
    uint8_t* format = (sideband & SIDEBAND_FORMAT) ? take(&at, &left, 24) : NULL;
    Gapless* gapless_out = (sideband & SIDEBAND_GAPLESS) ? take(&at, &left, 8) : NULL;
    uint32_t* mframe = (run & RUN_MULTIPLE_FRAMES) ? take(&at, &left, 8) : NULL;
    uint32_t* codec_info = (run & RUN_CODEC_INFO) ? take(&at, &left, 16) : NULL;
    if (result) {
        result[0] = result[1] = 0;
    }
    if (!in || !in->used) {
        if (result) {
            result[0] = RESULT_FATAL;
        }
        return;
    }
    int r = 0;
    if (control & CONTROL_RESET) {
        in->total_samples = 0;
        gapless_reset(in);
        if (in->initialized) {
            at9_reset(in);
        }
    }
    uint64_t ia = j->sb_in, il = j->sb_in_size;
    if ((sideband & SIDEBAND_FORMAT) && il) {
        take(&ia, &il, 24);
    }
    if ((sideband & SIDEBAND_GAPLESS) && il) {
        const Gapless* g = take(&ia, &il, 8);
        if (g) {
            const uint32_t processed = in->g_init.total_samples - in->g_cur.total_samples;
            if (g->total_samples || !g->skip_samples) {
                if (g->total_samples >= processed) {
                    const int64_t diff = (int64_t)in->g_init.total_samples - g->total_samples;
                    in->g_init.total_samples = g->total_samples;
                    in->g_cur.total_samples = (uint32_t)((int64_t)in->g_cur.total_samples - diff);
                } else {
                    r |= RESULT_INVALID_PARAMETER;
                }
            }
            const uint32_t skipped = (uint32_t)(in->g_init.skip_samples - in->g_cur.skip_samples);
            if (g->skip_samples || !g->total_samples) {
                if (g->skip_samples >= skipped) {
                    const int diff = (int)in->g_init.skip_samples - g->skip_samples;
                    in->g_init.skip_samples = g->skip_samples;
                    in->g_cur.skip_samples = (uint16_t)(in->g_cur.skip_samples - diff);
                } else {
                    r |= RESULT_INVALID_PARAMETER;
                }
            }
        }
    }
    if (control & CONTROL_RESAMPLE) {
        take(&ia, &il, 8);
    }
    if (control & CONTROL_INIT) {
        const uint8_t* init = take(&ia, &il, 8);
        if (init) {
            at9_init(in, init);
        }
    }

    int frames = 0;
    const uint64_t* bufs = j->buf;
    uint64_t in_total = 0;
    for (uint32_t k = 0; k < j->n_in; k++) {
        in_total += bufs[2 * k + 1];
    }
    uint8_t* input = NULL;
    if (j->magic == JOB_RUN && in_total) {
        input = malloc(in_total);
        uint64_t o = 0;
        for (uint32_t k = 0; k < j->n_in; k++) {
            memcpy(input + o, G(bufs[2 * k]), bufs[2 * k + 1]);
            o += bufs[2 * k + 1];
        }
    }
    Out out = {.n = 0};
    for (uint32_t k = 0; k < j->n_out && out.n < 8; k++) {
        if (bufs[2 * (j->n_in + k)] && bufs[2 * (j->n_in + k) + 1]) {
            out.addr[out.n] = bufs[2 * (j->n_in + k)];
            out.size[out.n++] = bufs[2 * (j->n_in + k) + 1];
        }
    }
    const uint64_t out_total = out_room(&out);
    const uint8_t* p = input;
    uint32_t n = (uint32_t)in_total;
    if (input) {
        for (;;) {
            if (in->gapless_loop && gapless_end(in)) {
                gapless_reset(in);
                in->total_samples = 0;
            }
            if ((in->at9_flags & AT9_PARSE_RIFF) && n >= 12 && !memcmp(p, "RIFF", 4)) {
                if (!parse_riff(in, &p, &n)) {
                    r |= RESULT_CODEC_ERROR | RESULT_FATAL;
                    break;
                }
                in->total_samples = 0;
            }
            if (!in->initialized) {
                r |= RESULT_NOT_INITIALIZED;
                break;
            }
            if (!n) {
                break;
            }
            if (!gapless_end(in) && out_room(&out) < next_frame_bytes(in)) {
                r |= RESULT_NOT_ENOUGH_ROOM;
            }
            if (n < in->superframe_left) {
                r |= RESULT_PARTIAL_INPUT;
            }
            if (r) {
                break;
            }
            const int s = decode_frame(in, &p, &n, &out, &frames);
            if (s < 0) {
                r |= RESULT_CODEC_ERROR | RESULT_FATAL;
                break;
            }
            in->total_samples += (uint64_t)s;
            if (!(run & RUN_MULTIPLE_FRAMES)) {
                break;
            }
        }
    }
    if (result) {
        result[0] = r;
    }
    if (r && getenv("BH_TRACE_AJM")) {
        LOG("ajm instance %u: result %#x (in %llu, %d frames)", j->instance, (unsigned)r, (unsigned long long)in_total, frames);
    }
    if (mframe) {
        mframe[0] = (uint32_t)frames;
        mframe[1] = 0;
    }
    if (stream) {
        const int32_t consumed = (int32_t)(in_total - n), written = (int32_t)(out_total - out_room(&out));
        memcpy(stream, &consumed, 4);
        memcpy(stream + 4, &written, 4);
        memcpy(stream + 8, &in->total_samples, 8);
    }
    if (format) {
        const uint32_t f[6] = {(uint32_t)in->info.channels, channel_mask(in->info.channels),
                               (uint32_t)in->info.samplingRate, (uint32_t)in->format,
                               in->info.frameSamples ? (uint32_t)((int64_t)in->info.samplingRate * in->info.superframeSize * 8 /
                                                                  (in->info.framesInSuperframe * in->info.frameSamples))
                                                     : 0,
                               0};
        memcpy(format, f, sizeof f);
    }
    if (gapless_out) {
        *gapless_out = in->g_cur;
    }
    if (codec_info) {
        codec_info[0] = (uint32_t)in->info.superframeSize;
        codec_info[1] = (uint32_t)in->info.framesInSuperframe;
        codec_info[2] = in->superframe_left;
        codec_info[3] = (uint32_t)in->info.frameSamples;
    }
    free(input);
}

HLE(sceAjmInitialize) {
    if (!lock) {
        lock = SDL_CreateMutex();
        queued = SDL_CreateCond();
        finished = SDL_CreateCond();
    }
    *(uint32_t*)ARGP(c, 1) = 1;
    RET(c, ORBIS_OK);
}
HLE(ajm_ok) { RET(c, ORBIS_OK); }

HLE(sceAjmInstanceCreate) {
    const uint64_t f = ARG(c, 2);
    SDL_LockMutex(lock);
    int i = 1;
    while (i < MAX_INSTANCES && instances[i].used) {
        i++;
    }
    if (i == MAX_INSTANCES) {
        SDL_UnlockMutex(lock);
        RET(c, (int64_t)(int32_t)0x80930005u);
        return;
    }
    Instance* in = &instances[i];
    memset(in, 0, sizeof *in);
    in->used = 1;
    in->codec = (int)ARG(c, 1);
    in->channels = (int)((f >> 3) & 0xF);
    in->format = (int)((f >> 7) & 7);
    in->gapless_loop = (int)((f >> 10) & 1);
    in->at9_flags = (int)(f >> 32);
    SDL_UnlockMutex(lock);
    if (in->codec != CODEC_AT9) {
        LOG("ajm: codec %d not handled", in->codec);
    }
    *(uint32_t*)ARGP(c, 3) = (uint32_t)i;
    RET(c, ORBIS_OK);
}
HLE(sceAjmInstanceDestroy) {
    const uint32_t i = (uint32_t)ARG(c, 1);
    if (i < MAX_INSTANCES && instances[i].used) {
        SDL_LockMutex(lock);
        if (instances[i].at9) {
            Atrac9ReleaseHandle(instances[i].at9);
        }
        instances[i].used = 0;
        instances[i].at9 = NULL;
        SDL_UnlockMutex(lock);
    }
    RET(c, ORBIS_OK);
}

HLE(sceAjmBatchJobControlBufferRa) {
    Job* j = ARGP(c, 0);
    memset(j, 0, sizeof *j);
    j->magic = JOB_CONTROL;
    j->instance = (uint32_t)ARG(c, 1);
    j->flags = ARG(c, 2);
    j->sb_in = ARG(c, 3);
    j->sb_in_size = ARG(c, 4);
    j->sb_out = ARG(c, 5);
    j->sb_out_size = ARGS(c, 6);
    if (getenv("BH_TRACE_AJM")) {
        LOG("ajm control job at %#llx: instance %u flags %#llx", (unsigned long long)H(j), j->instance,
            (unsigned long long)j->flags);
    }
    job_built(j);
    RET(c, (H(j) + sizeof *j + 15) & ~15ull);
}
HLE(sceAjmBatchJobRunSplitBufferRa) {
    Job* j = ARGP(c, 0);
    memset(j, 0, sizeof *j);
    j->magic = JOB_RUN;
    j->instance = (uint32_t)ARG(c, 1);
    j->flags = ARG(c, 2);
    const uint64_t* ins = ARGP(c, 3);
    j->n_in = (uint32_t)ARG(c, 4);
    const uint64_t* outs = ARGP(c, 5);
    j->n_out = (uint32_t)ARGS(c, 6);
    j->sb_out = ARGS(c, 7);
    j->sb_out_size = ARGS(c, 8);
    for (uint32_t k = 0; k < j->n_in; k++) {
        j->buf[2 * k] = ins[2 * k];
        j->buf[2 * k + 1] = ins[2 * k + 1];
    }
    for (uint32_t k = 0; k < j->n_out; k++) {
        j->buf[2 * (j->n_in + k)] = outs[2 * k];
        j->buf[2 * (j->n_in + k) + 1] = outs[2 * k + 1];
    }
    if (getenv("BH_TRACE_AJM")) {
        LOG("ajm run job at %#llx: instance %u flags %#llx, %u in, %u out", (unsigned long long)H(j), j->instance,
            (unsigned long long)j->flags, j->n_in, j->n_out);
    }
    job_built(j);
    RET(c, (H(j) + sizeof *j + 16ull * (j->n_in + j->n_out) + 15) & ~15ull);
}

typedef struct Batch {
    struct Batch* next;
    uint32_t id;
    uint8_t* jobs;
    uint32_t size;
} Batch;

typedef struct Worker {
    SDL_Thread* thread;
    Batch *head, *tail;
} Worker;

static Worker workers[MAX_INSTANCES];
static uint32_t next_batch = 1;
#define DONE_RING 1024
static uint32_t done_ids[DONE_RING];

static void run_batch(const uint8_t* p, uint32_t size) {
    const uint8_t* end = p + size;
    while (p + sizeof(Job) <= end) {
        const Job* j = (const Job*)p;
        run_job(j);
        p += job_size(j);
    }
}

static int worker_main(void* arg) {
    Worker* w = arg;
    SDL_LockMutex(lock);
    for (;;) {
        while (!w->head) {
            SDL_CondWait(queued, lock);
        }
        Batch* b = w->head;
        w->head = b->next;
        if (!w->head) {
            w->tail = NULL;
        }
        SDL_UnlockMutex(lock);
        run_batch(b->jobs, b->size);
        SDL_LockMutex(lock);
        done_ids[b->id % DONE_RING] = b->id;
        SDL_CondBroadcast(finished);
        free(b->jobs);
        free(b);
    }
    return 0;
}

HLE(sceAjmBatchStartBuffer) {
    if (getenv("BH_TRACE_AJM")) {
        LOG("ajm batch %#llx, %u bytes", (unsigned long long)ARG(c, 1), (unsigned)ARG(c, 2));
    }
    Batch* b = calloc(1, sizeof *b);
    b->jobs = take_built(ARG(c, 1), (uint32_t)ARG(c, 2), &b->size);
    if (getenv("BH_TRACE_AJM")) {
        int n = 0;
        char kinds[64] = {0};
        for (const uint8_t* q = b->jobs; q + sizeof(Job) <= b->jobs + b->size && n < 60; q += job_size((const Job*)q)) {
            kinds[n++] = ((const Job*)q)->magic == JOB_RUN ? 'R' : 'C';
        }
        LOG("ajm start %#llx +%u: %d jobs %s", (unsigned long long)ARG(c, 1), (unsigned)ARG(c, 2), n, kinds);
    }
    const uint32_t instance = b->size >= sizeof(Job) ? ((const Job*)b->jobs)->instance : 0;
    Worker* w = &workers[instance < MAX_INSTANCES ? instance : 0];
    SDL_LockMutex(lock);
    b->id = next_batch++;
    const uint32_t id = b->id;
    if (!w->thread) {
        char name[32];
        snprintf(name, sizeof name, "ajm instance %u", instance);
        w->thread = SDL_CreateThread(worker_main, name, w);
    }
    if (w->tail) {
        w->tail->next = b;
    } else {
        w->head = b;
    }
    w->tail = b;
    SDL_CondBroadcast(queued);

    while (done_ids[id % DONE_RING] != id) {
        SDL_CondWait(finished, lock);
    }
    SDL_UnlockMutex(lock);
    if (ARG(c, 5)) {
        *(uint32_t*)ARGP(c, 5) = id;
    }
    RET(c, ORBIS_OK);
}

HLE(sceAjmBatchWait) {
    const uint32_t id = (uint32_t)ARG(c, 1), timeout = (uint32_t)ARG(c, 2);
    SDL_LockMutex(lock);
    const uint64_t until = SDL_GetTicks64() + (timeout == 0xFFFFFFFFu ? 0 : (timeout + 999) / 1000);
    while (done_ids[id % DONE_RING] != id) {
        if (timeout != 0xFFFFFFFFu) {
            const uint64_t now = SDL_GetTicks64();
            if (now >= until) {
                SDL_UnlockMutex(lock);
                RET(c, (int64_t)(int32_t)0x8093000Du);
                return;
            }
            SDL_CondWaitTimeout(finished, lock, (Uint32)(until - now));
        } else {
            SDL_CondWait(finished, lock);
        }
    }
    SDL_UnlockMutex(lock);
    RET(c, ORBIS_OK);
}

const HleFunc hle_ajm_funcs[] = {
    HLE_FUNC(sceAjmInitialize), HLE_FUNC_AS("sceAjmFinalize", ajm_ok), HLE_FUNC_AS("sceAjmModuleRegister", ajm_ok),
    HLE_FUNC_AS("sceAjmModuleUnregister", ajm_ok), HLE_FUNC(sceAjmInstanceCreate), HLE_FUNC(sceAjmInstanceDestroy),
    HLE_FUNC(sceAjmBatchJobControlBufferRa), HLE_FUNC(sceAjmBatchJobRunSplitBufferRa), HLE_FUNC(sceAjmBatchStartBuffer),
    HLE_FUNC(sceAjmBatchWait),
    {NULL, NULL},
};
