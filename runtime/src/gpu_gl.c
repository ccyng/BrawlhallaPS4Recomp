#define GL_GLEXT_PROTOTYPES
#include <GL/gl.h>
#include <GL/glext.h>
#include <stdlib.h>
#include <string.h>

#include "gpu_backend.h"
#include "runtime.h"
#include "memwatch.h"
#include "tiling.h"

static const char* vs_src =
    "#version 330 core\n"
    "layout(location = 0) in vec4 a_pos;\n"
    "layout(location = 1) in vec4 a_param;\n"
    "uniform float u_flip;\n"
    "out vec4 v_param;\n"
    "void main() { gl_Position = vec4(a_pos.x, a_pos.y * u_flip, a_pos.z, a_pos.w); v_param = a_param; }\n";

static const char* ps_head =
    "#version 330 core\n"
    "in vec4 v_param;\n"
    "uniform vec4 k[3];\n"
    "uniform sampler2D tex;\n"
    "out vec4 o;\n";

static const char* ps_body[PS_COUNT] = {
    [PS_NONE] = "void main() { o = vec4(0); }\n",
    [PS_ZERO] = "void main() { o = vec4(0); }\n",
    [PS_TEX_MUL] = "void main() { o = texture(tex, v_param.xy) * k[0].x; }\n",
    [PS_TEX_XFORM] = "void main() {\n"
                     "  vec4 t = texture(tex, v_param.xy) * k[2].x;\n"
                     "  float a = t.a * k[0].w;\n"
                     "  o = clamp(vec4(t.rgb * k[0].rgb + k[1].rgb * a, a + k[1].w * a), 0.0, 1.0);\n"
                     "}\n",
    [PS_CONST] = "void main() { o = k[0]; }\n",
    [PS_COPY] = "void main() { o = texelFetch(tex, ivec2(gl_FragCoord.xy), 0); }\n",
    [PS_TEX_COORD] = "void main() { o = texture(tex, gl_FragCoord.xy * k[0].xy + k[1].xy); }\n",
};

static GLuint programs[PS_COUNT];
static GLint u_flip[PS_COUNT], u_k[PS_COUNT];
static GLuint vao, vbo;

static GLuint compile(GLenum type, const char* a, const char* b) {
    GLuint s = glCreateShader(type);
    const char* src[2] = {a, b ? b : ""};
    glShaderSource(s, 2, src, NULL);
    glCompileShader(s);
    GLint ok;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[2048];
        glGetShaderInfoLog(s, sizeof log, NULL, log);
        rt_fatal("gl: shader: %s", log);
    }
    return s;
}

void gb_init(void) {
    const GLuint vs = compile(GL_VERTEX_SHADER, vs_src, NULL);
    for (int i = 0; i < PS_COUNT; i++) {
        const GLuint fs = compile(GL_FRAGMENT_SHADER, ps_head, ps_body[i]);
        GLuint p = glCreateProgram();
        glAttachShader(p, vs);
        glAttachShader(p, fs);
        glLinkProgram(p);
        GLint ok;
        glGetProgramiv(p, GL_LINK_STATUS, &ok);
        if (!ok) {
            rt_fatal("gl: program %d does not link", i);
        }
        programs[i] = p;
        u_flip[i] = glGetUniformLocation(p, "u_flip");
        u_k[i] = glGetUniformLocation(p, "k");
        glUseProgram(p);
        glUniform1i(glGetUniformLocation(p, "tex"), 0);
        glDeleteShader(fs);
    }
    glDeleteShader(vs);
    glGenVertexArrays(1, &vao);
    glBindVertexArray(vao);
    glGenBuffers(1, &vbo);
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glEnableVertexAttribArray(0);
    glEnableVertexAttribArray(1);
    glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, sizeof(GpuVertex), (void*)offsetof(GpuVertex, pos));
    glVertexAttribPointer(1, 4, GL_FLOAT, GL_FALSE, sizeof(GpuVertex), (void*)offsetof(GpuVertex, param));
    LOG("gl: %s, %s", (const char*)glGetString(GL_RENDERER), (const char*)glGetString(GL_VERSION));
    memwatch_init();
}

typedef struct Target {
    uint64_t addr;
    uint32_t width, height;
    GLuint tex, fbo;
} Target;

#define MAX_TARGETS 64
static Target targets[MAX_TARGETS];
static int target_count;

static Target* find_target(uint64_t addr) {
    for (int i = 0; i < target_count; i++) {
        if (targets[i].addr == addr) {
            return &targets[i];
        }
    }
    return NULL;
}

static Target* get_target(const GpuTarget* g) {
    Target* t = find_target(g->addr);
    if (t && (t->width != g->width || t->height != g->height)) {
        glDeleteFramebuffers(1, &t->fbo);
        glDeleteTextures(1, &t->tex);
        *t = targets[--target_count];
        t = NULL;
    }
    if (t) {
        return t;
    }
    if (target_count == MAX_TARGETS) {
        rt_fatal("gl: more than %d colour targets", MAX_TARGETS);
    }
    t = &targets[target_count++];
    t->addr = g->addr;
    t->width = g->width;
    t->height = g->height;
    glGenTextures(1, &t->tex);
    glBindTexture(GL_TEXTURE_2D, t->tex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, (GLsizei)g->width, (GLsizei)g->height, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glGenFramebuffers(1, &t->fbo);
    glBindFramebuffer(GL_FRAMEBUFFER, t->fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t->tex, 0);
    glClearColor(0, 0, 0, 0);
    glDisable(GL_SCISSOR_TEST);
    glColorMask(1, 1, 1, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    LOG("gl: colour target %d at %#llx, %ux%u, format %u, tiling %u", target_count - 1,
        (unsigned long long)g->addr, g->width, g->height, g->format, g->tiling);
    return t;
}

void gb_target_flush(uint64_t addr, uint64_t size) {
    (void)addr;
    (void)size;
}

typedef struct Texture {
    uint64_t addr;
    uint32_t width, height, pitch, dfmt, nfmt, tiling;
    GLuint tex;
    size_t size;
    uint32_t watch;
} Texture;

#define MAX_TEXTURES 1024
static Texture textures[MAX_TEXTURES];
static int texture_count;
void gb_new_frame(void) {}

typedef struct GlFormat {
    GLenum internal, format, type;
    uint32_t bpp;
    int block;
} GlFormat;

static int gl_format(uint32_t dfmt, uint32_t nfmt, GlFormat* f) {
    const int srgb = nfmt == 9;
    switch (dfmt) {
    case 1: *f = (GlFormat){GL_R8, GL_RED, GL_UNSIGNED_BYTE, 1, 0}; return 1;
    case 3: *f = (GlFormat){GL_RG8, GL_RG, GL_UNSIGNED_BYTE, 2, 0}; return 1;
    case 10: *f = (GlFormat){srgb ? GL_SRGB8_ALPHA8 : GL_RGBA8, GL_RGBA, GL_UNSIGNED_BYTE, 4, 0}; return 1;
    case 12: *f = (GlFormat){GL_RGBA16F, GL_RGBA, nfmt == 7 ? GL_HALF_FLOAT : GL_UNSIGNED_SHORT, 8, 0}; return 1;
    case 14: *f = (GlFormat){GL_RGBA32F, GL_RGBA, GL_FLOAT, 16, 0}; return 1;
    case 35: *f = (GlFormat){srgb ? GL_COMPRESSED_SRGB_ALPHA_S3TC_DXT1_EXT : GL_COMPRESSED_RGBA_S3TC_DXT1_EXT, 0, 0, 8, 1}; return 1;
    case 36: *f = (GlFormat){srgb ? GL_COMPRESSED_SRGB_ALPHA_S3TC_DXT3_EXT : GL_COMPRESSED_RGBA_S3TC_DXT3_EXT, 0, 0, 16, 1}; return 1;
    case 37: *f = (GlFormat){srgb ? GL_COMPRESSED_SRGB_ALPHA_S3TC_DXT5_EXT : GL_COMPRESSED_RGBA_S3TC_DXT5_EXT, 0, 0, 16, 1}; return 1;
    default: return 0;
    }
}

static void upload(Texture* t, const GlFormat* f) {
    const uint32_t ew = f->block ? (t->width + 3) / 4 : t->width, eh = f->block ? (t->height + 3) / 4 : t->height;
    const uint32_t epitch = f->block ? (t->pitch + 3) / 4 : t->pitch;
    const size_t size = (size_t)epitch * eh * f->bpp;
    const uint8_t* src = G(t->addr);
    uint8_t* linear = NULL;
    if (tile_is_tiled(t->tiling)) {
        linear = malloc((size_t)ew * eh * f->bpp);
        if (!tile_detile(t->tiling, src, linear, ew, eh, epitch, f->bpp)) {
            static uint32_t warned;
            if (warned != t->tiling + 1) {
                warned = t->tiling + 1;
                LOG("gl: tile mode %u is not detiled", t->tiling);
            }
        }
        src = linear;
        glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    } else {
        glPixelStorei(GL_UNPACK_ROW_LENGTH, f->block ? 0 : (GLint)t->pitch);
    }
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glBindTexture(GL_TEXTURE_2D, t->tex);
    if (f->block) {
        glCompressedTexImage2D(GL_TEXTURE_2D, 0, f->internal, (GLsizei)t->width, (GLsizei)t->height, 0,
                               (GLsizei)((size_t)ew * eh * f->bpp), src);
    } else {
        glTexImage2D(GL_TEXTURE_2D, 0, (GLint)f->internal, (GLsizei)t->width, (GLsizei)t->height, 0, f->format, f->type,
                     src);
    }
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    free(linear);
    (void)size;
}

static GLuint get_texture(const GpuImage* img) {
    Target* rt = find_target(img->addr);
    if (rt) {
        return rt->tex;
    }
    GlFormat f;
    if (!gl_format(img->dfmt, img->nfmt, &f)) {
        static uint32_t warned;
        if (warned != (img->dfmt << 8 | img->nfmt) + 1) {
            warned = (img->dfmt << 8 | img->nfmt) + 1;
            LOG("gl: image format %u/%u not handled", img->dfmt, img->nfmt);
        }
        return 0;
    }
    Texture* t = NULL;
    for (int i = 0; i < texture_count; i++) {
        Texture* x = &textures[i];
        if (x->addr == img->addr && x->width == img->width && x->height == img->height && x->dfmt == img->dfmt &&
            x->nfmt == img->nfmt && x->pitch == img->pitch && x->tiling == img->tiling) {
            t = x;
            break;
        }
    }
    const uint32_t eh = f.block ? (img->height + 3) / 4 : img->height;
    const uint32_t epitch = f.block ? (img->pitch + 3) / 4 : img->pitch;
    const size_t size = tile_size(img->tiling, epitch, eh, f.bpp);
    if (!t) {
        if (texture_count == MAX_TEXTURES) {
            glDeleteTextures(1, &textures[0].tex);
            textures[0] = textures[--texture_count];
        }
        t = &textures[texture_count++];
        memset(t, 0, sizeof *t);
        t->addr = img->addr;
        t->width = img->width;
        t->height = img->height;
        t->pitch = img->pitch;
        t->dfmt = img->dfmt;
        t->nfmt = img->nfmt;
        t->tiling = img->tiling;
        glGenTextures(1, &t->tex);
        t->size = size;
        t->watch = memwatch_watch(t->addr, size);
        upload(t, &f);
        return t->tex;
    }
    if (memwatch_written(t->addr, t->size, t->watch)) {
        t->watch = memwatch_watch(t->addr, t->size);
        upload(t, &f);
    }
    return t->tex;
}

static GLenum wrap(uint32_t clamp) {
    switch (clamp) {
    case 0: return GL_REPEAT;
    case 1: return GL_MIRRORED_REPEAT;
    default: return GL_CLAMP_TO_EDGE;
    }
}

static GLint swizzle(uint32_t sel) {
    switch (sel) {
    case 0: return GL_ZERO;
    case 1: return GL_ONE;
    case 4: return GL_RED;
    case 5: return GL_GREEN;
    case 6: return GL_BLUE;
    default: return GL_ALPHA;
    }
}

static GLenum blend_factor(uint32_t f) {
    static const GLenum map[] = {GL_ZERO, GL_ONE, GL_SRC_COLOR, GL_ONE_MINUS_SRC_COLOR, GL_SRC_ALPHA,
                                 GL_ONE_MINUS_SRC_ALPHA, GL_DST_ALPHA, GL_ONE_MINUS_DST_ALPHA, GL_DST_COLOR,
                                 GL_ONE_MINUS_DST_COLOR, GL_SRC_ALPHA_SATURATE, GL_ONE, GL_ONE, GL_CONSTANT_COLOR,
                                 GL_ONE_MINUS_CONSTANT_COLOR, GL_SRC1_COLOR, GL_ONE_MINUS_SRC1_COLOR, GL_SRC1_ALPHA,
                                 GL_ONE_MINUS_SRC1_ALPHA, GL_CONSTANT_ALPHA, GL_ONE_MINUS_CONSTANT_ALPHA};
    return f < sizeof map / sizeof *map ? map[f] : GL_ONE;
}

static GLenum blend_op(uint32_t f) {
    static const GLenum map[] = {GL_FUNC_ADD, GL_FUNC_SUBTRACT, GL_MIN, GL_MAX, GL_FUNC_REVERSE_SUBTRACT};
    return f < 5 ? map[f] : GL_FUNC_ADD;
}

void gb_draw(const GpuDrawState* s, const GpuVertex* v, uint32_t count) {
    Target* t = get_target(&s->target);
    glBindFramebuffer(GL_FRAMEBUFFER, t->fbo);
    glViewport(s->vp_x, s->vp_y, s->vp_w, s->vp_h);
    glEnable(GL_SCISSOR_TEST);
    glScissor(s->sc_x0, s->sc_y0, s->sc_x1 > s->sc_x0 ? s->sc_x1 - s->sc_x0 : 0,
              s->sc_y1 > s->sc_y0 ? s->sc_y1 - s->sc_y0 : 0);
    glColorMask(s->write_mask & 1, (s->write_mask >> 1) & 1, (s->write_mask >> 2) & 1, (s->write_mask >> 3) & 1);
    const uint32_t b = s->blend;
    if (b & (1u << 30)) {
        glEnable(GL_BLEND);
        const uint32_t cs = b & 0x1F, cop = (b >> 5) & 7, cd = (b >> 8) & 0x1F;
        uint32_t as = cs, aop = cop, ad = cd;
        if (b & (1u << 29)) {
            as = (b >> 16) & 0x1F;
            aop = (b >> 21) & 7;
            ad = (b >> 24) & 0x1F;
        }
        glBlendFuncSeparate(blend_factor(cs), blend_factor(cd), blend_factor(as), blend_factor(ad));
        glBlendEquationSeparate(blend_op(cop), blend_op(aop));
        glBlendColor(s->blend_color[0], s->blend_color[1], s->blend_color[2], s->blend_color[3]);
    } else {
        glDisable(GL_BLEND);
    }
    glUseProgram(programs[s->ps]);
    glUniform1f(u_flip[s->ps], s->flip_y ? -1.0f : 1.0f);
    glUniform4fv(u_k[s->ps], 3, s->k);
    if (s->has_image) {
        const GLuint tex = get_texture(&s->image);
        if (!tex) {
            return;
        }
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, tex);
        const uint32_t* sm = s->image.sampler;
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, (GLint)wrap(sm[0] & 7));
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, (GLint)wrap((sm[0] >> 3) & 7));
        const int linear = ((sm[2] >> 20) & 3) != 0;
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, linear ? GL_LINEAR : GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, ((sm[2] >> 22) & 3) ? GL_LINEAR : GL_NEAREST);
        if (!find_target(s->image.addr)) {
            const GLint sw[4] = {swizzle(s->image.swizzle & 7), swizzle((s->image.swizzle >> 3) & 7),
                                 swizzle((s->image.swizzle >> 6) & 7), swizzle((s->image.swizzle >> 9) & 7)};
            glTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_SWIZZLE_RGBA, sw);
        }
    }
    glBindVertexArray(vao);
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr)(sizeof *v * count), v, GL_STREAM_DRAW);
    glDrawArrays(GL_TRIANGLES, 0, (GLsizei)count);
}

void gb_present(const GpuTarget* g, int w, int h) {
    Target* t = find_target(g->addr);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
    glDisable(GL_SCISSOR_TEST);
    glColorMask(1, 1, 1, 1);
    glViewport(0, 0, w, h);
    glClearColor(0, 0, 0, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    if (!t) {
        return;
    }
    const int sw = 1920 < (int)t->width ? 1920 : (int)t->width, sh = (int)t->height;
    int dw = w, dh = w * sh / sw;
    if (dh > h) {
        dh = h;
        dw = h * sw / sh;
    }
    const int dx = (w - dw) / 2, dy = (h - dh) / 2;
    glBindFramebuffer(GL_READ_FRAMEBUFFER, t->fbo);
    glBlitFramebuffer(0, 0, sw, sh, dx, dy + dh, dx + dw, dy, GL_COLOR_BUFFER_BIT, GL_LINEAR);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
}

int gb_read(const GpuTarget* g, uint8_t* rgba) {
    Target* t = find_target(g->addr);
    if (!t) {
        return 0;
    }
    glBindFramebuffer(GL_READ_FRAMEBUFFER, t->fbo);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    const GLsizei w = (GLsizei)(g->width < t->width ? g->width : t->width);
    const GLsizei h = (GLsizei)(g->height < t->height ? g->height : t->height);
    glReadPixels(0, 0, w, h, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
    return 1;
}
