import os
import re
import struct

PT_LOAD, PT_DYNAMIC, PT_TLS = 1, 2, 7
PT_SCE_RELRO, PT_SCE_DYNLIBDATA, PT_SCE_PROCPARAM = 0x61000010, 0x61000000, 0x61000001
PT_GNU_EH_FRAME = 0x6474E550

DT_NULL, DT_NEEDED, DT_INIT, DT_FINI = 0, 1, 12, 13
DT_INIT_ARRAY, DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ = 25, 26, 27, 28
DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ = 32, 33
DT_SCE_NEEDED_MODULE, DT_SCE_IMPORT_LIB, DT_SCE_EXPORT_LIB = 0x6100000F, 0x61000015, 0x61000013
DT_SCE_MODULE_INFO = 0x6100000D
DT_SCE_PLTGOT, DT_SCE_JMPREL, DT_SCE_PLTRELSZ = 0x61000027, 0x61000029, 0x6100002D
DT_SCE_RELA, DT_SCE_RELASZ = 0x6100002F, 0x61000031
DT_SCE_STRTAB, DT_SCE_STRSZ, DT_SCE_SYMTAB, DT_SCE_SYMTABSZ = 0x61000035, 0x61000037, 0x61000039, 0x6100003F

R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE = 1, 6, 7, 8
R_X86_64_DTPMOD64, R_X86_64_DTPOFF64, R_X86_64_TPOFF64 = 16, 17, 18

AEROLIB = os.environ.get('MANIA_AEROLIB',
                         '/home/ven17b/Documents/VS/OrbisGlue/src/core/aerolib/aerolib.inl')
CODES = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-'

def encode_id(v):
    if v < 0x40:
        return CODES[v]
    if v < 0x1000:
        return CODES[(v >> 6) & 0x3F] + CODES[v & 0x3F]
    return CODES[(v >> 12) & 0x3F] + CODES[(v >> 6) & 0x3F] + CODES[v & 0x3F]

_nids = None

def nid_name(nid):
    global _nids
    if _nids is None:
        _nids = {}
        if os.path.exists(AEROLIB):
            for m in re.finditer(r'STUB\("([^"]+)",\s*([^)]+)\)', open(AEROLIB, encoding='utf-8').read()):
                _nids[m.group(1)] = m.group(2).strip()
    return _nids.get(nid)

class Ps4Elf:
    def __init__(self, path):
        d = open(path, 'rb').read()
        if d[:4] == b'\x7fELF':
            eo, self.file_segs = 0, None
        else:
            n, = struct.unpack_from('<H', d, 0x18)
            ents = [struct.unpack_from('<QQQQ', d, 0x20 + i * 0x20) for i in range(n)]
            eo = 0x20 + n * 0x20
            self.file_segs = {}
            for e in ents:
                if e[0] & 0x800:
                    self.file_segs[(e[0] >> 20) & 0xFFF] = d[e[1]:e[1] + e[2]]
        self.e_type, = struct.unpack_from('<H', d, eo + 0x10)
        self.entry, = struct.unpack_from('<Q', d, eo + 0x18)
        phoff, = struct.unpack_from('<Q', d, eo + 0x20)
        phnum, = struct.unpack_from('<H', d, eo + 0x38)
        self.ph = [struct.unpack_from('<IIQQQQQQ', d, eo + phoff + i * 0x38) for i in range(phnum)]
        self.segs = {}
        for i, p in enumerate(self.ph):
            if self.file_segs is None:
                self.segs[i] = d[p[2]:p[2] + p[5]]
            elif i in self.file_segs:
                self.segs[i] = self.file_segs[i]
        for i, p in enumerate(self.ph):
            if i in self.segs or p[5] == 0:
                continue
            for j, data in (self.file_segs or {}).items():
                q = self.ph[j]
                if q[2] <= p[2] < q[2] + q[5]:
                    self.segs[i] = data[p[2] - q[2]:p[2] - q[2] + p[5]]
                    break
        self._dynamic()

    def seg_of_type(self, t):
        for i, p in enumerate(self.ph):
            if p[0] == t:
                return i, p
        return None, None

    def read(self, va, size):
        for i, p in enumerate(self.ph):
            if p[0] in (PT_LOAD, PT_SCE_RELRO) and p[3] <= va < p[3] + p[6]:
                data = self.segs.get(i, b'')
                off = va - p[3]
                chunk = data[off:off + size]
                return chunk + bytes(size - len(chunk))
        raise ValueError(f'{va:#x} is in no loaded segment')

    def _dynamic(self):
        di, _ = self.seg_of_type(PT_DYNAMIC)
        li, _ = self.seg_of_type(PT_SCE_DYNLIBDATA)
        dyn, lib = self.segs[di], self.segs[li]
        self.dyn = {}
        self.needed_modules, self.import_libs, self.export_libs, self.modules = [], [], [], []
        tags = []
        for k in range(0, len(dyn), 16):
            tag, val = struct.unpack_from('<qQ', dyn, k)
            if tag == DT_NULL:
                break
            tags.append((tag, val))
            self.dyn.setdefault(tag, val)
        strtab = lib[self.dyn[DT_SCE_STRTAB]:self.dyn[DT_SCE_STRTAB] + self.dyn[DT_SCE_STRSZ]]

        def cstr(off):
            return strtab[off:strtab.index(b'\0', off)].decode()

        for tag, val in tags:
            if tag not in (DT_SCE_NEEDED_MODULE, DT_SCE_MODULE_INFO, DT_SCE_IMPORT_LIB, DT_SCE_EXPORT_LIB):
                continue
            name, idv = cstr(val & 0xFFFFFFFF), val >> 48
            if tag in (DT_SCE_NEEDED_MODULE, DT_SCE_MODULE_INFO):
                (self.needed_modules if tag == DT_SCE_NEEDED_MODULE else self.modules).append(
                    (name, encode_id(idv)))
            elif tag in (DT_SCE_IMPORT_LIB, DT_SCE_EXPORT_LIB):
                (self.import_libs if tag == DT_SCE_IMPORT_LIB else self.export_libs).append(
                    (name, encode_id(idv), (val >> 32) & 0xFFFF))
        libs = {enc: name for name, enc, _ in self.import_libs + self.export_libs}
        mods = {enc: name for name, enc in self.needed_modules + self.modules}

        symtab = lib[self.dyn[DT_SCE_SYMTAB]:self.dyn[DT_SCE_SYMTAB] + self.dyn[DT_SCE_SYMTABSZ]]
        self.symbols = []
        for k in range(0, len(symtab), 24):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', symtab, k)
            raw = cstr(st_name)
            parts = raw.split('#')
            nid, lib_name, mod_name = (parts[0], libs.get(parts[1], parts[1]), mods.get(parts[2], parts[2])) \
                if len(parts) == 3 else (raw, None, None)
            self.symbols.append({'raw': raw, 'nid': nid, 'name': nid_name(nid) if lib_name else raw,
                                 'library': lib_name, 'module': mod_name, 'bind': st_info >> 4,
                                 'type': st_info & 0xF, 'value': st_value, 'size': st_size})

        def relas(off, size):
            for k in range(off, off + size, 24):
                r_offset, r_info, r_addend = struct.unpack_from('<QQq', lib, k)
                yield r_offset, r_info & 0xFFFFFFFF, r_info >> 32, r_addend

        self.relocs = list(relas(self.dyn[DT_SCE_RELA], self.dyn[DT_SCE_RELASZ]))
        self.plt_relocs = list(relas(self.dyn[DT_SCE_JMPREL], self.dyn[DT_SCE_PLTRELSZ]))

    def imports(self):
        out = []
        for r_offset, rtype, sym, addend in self.relocs + self.plt_relocs:
            if sym and self.symbols[sym]['library'] is not None and self.symbols[sym]['value'] == 0:
                out.append((r_offset, rtype, self.symbols[sym], addend))
        return out

    def plt_stubs(self):
        slots = {r[0] for r in self.plt_relocs}
        ci = next(i for i, p in enumerate(self.ph) if p[0] == PT_LOAD and (p[1] & 1))
        code, base = self.segs[ci], self.ph[ci][3]
        stubs = {}
        for m in re.finditer(rb'\xff\x25', code):
            at = m.start()
            disp, = struct.unpack_from('<i', code, at + 2)
            target = base + at + 6 + disp
            if target in slots:
                stubs[base + at] = target
        return stubs
