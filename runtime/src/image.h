#pragma once

#include <stdint.h>

enum { OG_SLOT_FUNC, OG_SLOT_ADDR };

typedef struct OgSegment {
    uint64_t vaddr, memsz;
    uint32_t filesz, offset;
    uint32_t flags;
} OgSegment;

typedef struct OgRelative {
    uint64_t offset;
    int64_t addend;
} OgRelative;

typedef struct OgImport {
    const char* name;
    const char* library;
    const char* nid;
    int is_data;
} OgImport;

typedef struct OgSlot {
    uint64_t offset;
    uint32_t import;
    uint32_t kind;
    int64_t addend;
} OgSlot;

typedef struct OgPlt {
    uint64_t stub;
    uint32_t import;
} OgPlt;

typedef struct OgExport {
    const char* name;
    uint64_t value;
    int is_data;
} OgExport;

typedef struct OgTls {
    uint64_t vaddr, filesz, memsz, align;
} OgTls;

typedef struct OgModule {
    const char* name;
    const uint8_t* bytes;
    uint64_t image_size, entry, init, fini, procparam;
    OgTls tls;
    unsigned segment_count;
    const OgSegment* segments;
    unsigned relative_count;
    const OgRelative* relative;
    unsigned import_count;
    const OgImport* imports;
    unsigned slot_count;
    const OgSlot* slots;
    unsigned plt_count;
    const OgPlt* plt;
    unsigned export_count;
    const OgExport* exports;
    unsigned tls_module_slot_count;
    const uint64_t* tls_module_slots;
    unsigned init_count;
    const uint64_t* init_array;
    const void* (*entries)(const void* host, unsigned* count);
} OgModule;
