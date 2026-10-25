import argparse
import collections
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import lift64

DEFAULT = [
    'vbroadcastsd ymm2, qword ptr [rsi + 8]', 'vbroadcastsd ymm0, xmm1',
    'vcvtdq2pd ymm2, xmm3', 'vcvtdq2pd ymm0, xmmword ptr [rsi]',
    'vcvtps2pd ymm1, xmm0', 'vcvtps2pd ymm1, xmmword ptr [rsi + 16]',
    'vptest xmm0, xmm1', 'vptest xmm0, xmm0', 'vptest ymm2, ymm3', 'vptest xmm5, xmmword ptr [rsi]',
    'ptest xmm1, xmm2',
    'vmaskmovps xmm6, xmm8, xmmword ptr [rsi + 0x24]', 'vmaskmovps ymm6, ymm8, ymmword ptr [rsi]',
    'vmaskmovps ymmword ptr [rsi + 0x18], ymm1, ymm4', 'vmaskmovps xmmword ptr [rsi], xmm1, xmm4',
    'vroundpd ymm1, ymm2, 0', 'vroundpd ymm1, ymm2, 1', 'vroundpd ymm1, ymm2, 2', 'vroundpd ymm1, ymm2, 3',
    'vroundpd ymm1, ymm2, 9', 'vroundpd ymm3, ymmword ptr [rsi + 32], 11',
    'vblendvpd ymm1, ymm2, ymm3, ymm4', 'vblendvpd ymm1, ymm2, ymmword ptr [rsi], ymm4',
    'vcvttpd2dq xmm1, ymm2', 'vcvttpd2dq xmm1, ymmword ptr [rsi + 64]', 'vcvtpd2dq xmm1, ymm2',
]

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "og64.h"
const OgHost* og_host; uint64_t og_base; uint8_t og_off[1];
uint64_t native_ctx, native_flags;
static uint64_t s = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static uint64_t lane64(void) {
    static const double dv[] = {0.0, -0.0, 0.5, -0.5, 1.5, 2.5, -2.5, 1e300, -1e300, 2147483647.5,
                                -2147483648.5, 2147483648.0, -2147483649.0, 4294967296.0, 1e-310};
    uint64_t v;
    switch (rnd() % 6) {
    case 0: { double d = dv[rnd() % (sizeof dv / sizeof *dv)]; memcpy(&v, &d, 8); return v; }
    case 1: { double d = (double)(int64_t)(rnd() % 2000001 - 1000000) / 8.0; memcpy(&v, &d, 8); return v; }
    case 2: { float f[2] = {(float)(int)(rnd() % 20001 - 10000) / 64.0f, (float)(int)(rnd() % 201 - 100)};
              memcpy(&v, f, 8); return v; }
    case 3: return rnd() % 3 ? 0x7FF8000000000000ull : 0xFFF0000000000000ull;
    case 4: return rnd() & 0x8000000080000000ull;
    default: return rnd();
    }
}
@decls@
typedef void (*Native)(OgCtx*);
typedef void (*Lifted)(OgCtx*);
int main(int argc, char** argv) {
    int trials = argc > 1 ? atoi(argv[1]) : 20000, failed = 0;
    static const char* names[] = {@names@};
    static const Native natives[] = {@natives@};
    static const Lifted lifteds[] = {@lifteds@};
    static const int undefined[] = {@undefined@};
    static uint8_t buf_seed[256], buf_n[256], buf_l[256];
    static uint8_t mem[256] __attribute__((aligned(64)));
    for (unsigned k = 0; k < sizeof names / sizeof *names; k++) {
        int bad = 0;
        for (int t = 0; t < trials && !bad; t++) {
            OgCtx base __attribute__((aligned(32)));
            memset(&base, 0, sizeof base);
            for (int r = 0; r < 16; r++) base.r[r] = rnd();
            base.r[RSP] = 0;
            base.r[RSI] = (uint64_t)(uintptr_t)mem;
            for (int x = 0; x < 16; x++) for (int q = 0; q < 4; q++) base.y[x].q[q] = lane64();
            for (int i = 0; i < 256; i += 8) { uint64_t v = lane64(); memcpy(buf_seed + i, &v, 8); }
            uint64_t fl = rnd();
            base.cf = fl & 1; base.pf = (fl >> 2) & 1; base.af = (fl >> 4) & 1; base.zf = (fl >> 6) & 1;
            base.sf = (fl >> 7) & 1; base.of = (fl >> 11) & 1;
            base.mxcsr = 0x1F80;

            OgCtx n = base, l = base;
            memcpy(mem, buf_seed, 256);
            native_flags = (uint64_t)base.cf | (uint64_t)base.pf << 2 | (uint64_t)base.af << 4 |
                           (uint64_t)base.zf << 6 | (uint64_t)base.sf << 7 | (uint64_t)base.of << 11 | 2;
            natives[k](&n);
            memcpy(buf_n, mem, 256);
            n.cf = native_flags & 1; n.pf = (native_flags >> 2) & 1; n.af = (native_flags >> 4) & 1;
            n.zf = (native_flags >> 6) & 1; n.sf = (native_flags >> 7) & 1; n.of = (native_flags >> 11) & 1;

            memcpy(mem, buf_seed, 256);
            lifteds[k](&l);
            memcpy(buf_l, mem, 256);
            l.r[RSP] = 0;

            const char* why = NULL;
            for (int r = 0; r < 16 && !why; r++) if (n.r[r] != l.r[r]) why = "gpr";
            for (int x = 0; x < 16 && !why; x++) if (memcmp(n.y[x].b, l.y[x].b, 32)) why = "vector";
            const int u = undefined[k];
            if (!why && ((!(u & 1) && n.cf != l.cf) || (!(u & 2) && n.pf != l.pf) || (!(u & 4) && n.af != l.af) ||
                         (!(u & 8) && n.zf != l.zf) || (!(u & 16) && n.sf != l.sf) || (!(u & 32) && n.of != l.of)))
                why = "flags";
            if (!why && memcmp(buf_n, buf_l, 256)) why = "memory";
            if (why) {
                bad = 1;
                printf("FAIL %-50s %s (trial %d)\n", names[k], why, t);
                for (int r = 0; r < 16; r++) if (n.r[r] != l.r[r])
                    printf("  r%-2d in %016llx native %016llx lifted %016llx\n", r, (unsigned long long)base.r[r],
                           (unsigned long long)n.r[r], (unsigned long long)l.r[r]);
                for (int x = 0; x < 16; x++) if (memcmp(n.y[x].b, l.y[x].b, 32))
                    printf("  ymm%-2d native %016llx %016llx %016llx %016llx\n         lifted %016llx %016llx %016llx %016llx\n"
                           "         in     %016llx %016llx %016llx %016llx\n", x,
                           (unsigned long long)n.y[x].q[0], (unsigned long long)n.y[x].q[1], (unsigned long long)n.y[x].q[2], (unsigned long long)n.y[x].q[3],
                           (unsigned long long)l.y[x].q[0], (unsigned long long)l.y[x].q[1], (unsigned long long)l.y[x].q[2], (unsigned long long)l.y[x].q[3],
                           (unsigned long long)base.y[x].q[0], (unsigned long long)base.y[x].q[1], (unsigned long long)base.y[x].q[2], (unsigned long long)base.y[x].q[3]);
                printf("  flags native cf%d pf%d af%d zf%d sf%d of%d lifted cf%d pf%d af%d zf%d sf%d of%d\n",
                       n.cf, n.pf, n.af, n.zf, n.sf, n.of, l.cf, l.pf, l.af, l.zf, l.sf, l.of);
            }
        }
        if (!bad) printf("ok   %s\n", names[k]);
        failed += bad;
    }
    printf("%d of %u forms differ\n", failed, (unsigned)(sizeof names / sizeof *names));
    return failed != 0;
}
'''

UNDEFINED = {}
for m in ('imul', 'mul'):
    UNDEFINED[m] = 2 | 4 | 8 | 16
for m in ('shl', 'sal', 'shr', 'sar', 'shld', 'shrd'):
    UNDEFINED[m] = 4 | 32
for m in ('rol', 'ror', 'rcl', 'rcr'):
    UNDEFINED[m] = 32
for m in ('bsf', 'bsr'):
    UNDEFINED[m] = 1 | 2 | 4 | 16 | 32
for m in ('lzcnt', 'tzcnt'):
    UNDEFINED[m] = 2 | 4 | 16 | 32
for m in ('bt', 'bts', 'btr', 'btc'):
    UNDEFINED[m] = 2 | 4 | 16 | 32
for m in ('and', 'or', 'xor', 'test'):
    UNDEFINED[m] = 4
UNDEFINED['andn'] = 2 | 4
UNDEFINED['bextr'] = 2 | 4 | 16
for m in ('bzhi', 'blsr', 'blsi', 'blsmsk'):
    UNDEFINED[m] = 2 | 4
for m in ('div', 'idiv'):
    UNDEFINED[m] = 63

GPRS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

def native_asm(k, insn):
    y = 192
    L = [f'.globl native_{k}', f'native_{k}:',
         'push rbx', 'push rbp', 'push r12', 'push r13', 'push r14', 'push r15',
         'mov qword ptr [rip + native_ctx], rdi']
    L += [f'vmovdqu ymm{i}, ymmword ptr [rdi + {y + 32 * i}]' for i in range(16)]
    L += ['push qword ptr [rip + native_flags]', 'popfq']
    L += [f'mov {GPRS[i]}, qword ptr [rdi + {8 * i}]' for i in range(16) if i not in (4, 7)]
    L += ['mov rdi, qword ptr [rdi + 56]', insn,
          'push rax', 'pushfq', 'mov rax, qword ptr [rip + native_ctx]']
    L += [f'mov qword ptr [rax + {8 * i}], {GPRS[i]}' for i in range(1, 16) if i != 4]
    L += ['pop rcx', 'mov qword ptr [rip + native_flags], rcx', 'pop rcx', 'mov qword ptr [rax], rcx']
    L += [f'vmovdqu ymmword ptr [rax + {y + 32 * i}], ymm{i}' for i in range(16)]
    L += ['vzeroupper', 'pop r15', 'pop r14', 'pop r13', 'pop r12', 'pop rbp', 'pop rbx', 'ret']
    return '\n'.join(L)

class OneInsn:

    def __init__(self, code):
        self.code, self.code_va, self.base = code, 0x1000, 0

    def read(self, va, size):
        return self.code[va - self.code_va:va - self.code_va + size]

    def read_va(self, va, size):
        return self.read(va, size)

    def noreturn(self):
        return set()

def assemble(insn, work):
    src, obj = os.path.join(work, 'one.s'), os.path.join(work, 'one.o')
    open(src, 'w').write(f'.intel_syntax noprefix\n.text\n{insn}\nret\n')
    subprocess.run(['as', '--64', '-o', obj, src], check=True)
    raw = os.path.join(work, 'one.bin')
    subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', obj, raw], check=True)
    return open(raw, 'rb').read()

SKIP = ('j', 'call', 'ret', 'push', 'pop', 'leave', 'enter', 'loop', 'rep', 'movs', 'stos', 'lods', 'cmps',
        'scas', 'div', 'idiv', 'cpuid', 'rdtsc', 'syscall', 'int', 'ud2', 'hlt', 'nop', 'pause', 'lfence',
        'mfence', 'sfence', 'prefetch', 'clflush', 'xgetbv', 'fx', 'xsave', 'xrstor', 'f', 'wait', 'emms',
        'vzero', 'ldmxcsr', 'stmxcsr', 'cqo', 'cdq', 'cwd', 'bsf', 'bsr')
MEM = re.compile(r'((?:byte|word|dword|qword|tbyte|xmmword|ymmword) ptr )?(?:[a-z]s:)?\[[^\]]*\]')

def eboot_forms(path):
    eb = lift64.Eboot(path, 0)
    forms = set()
    for start, size in eb.funcs:
        fl = lift64.FuncLifter(eb, start, size, set())
        try:
            fl.decode()
        except lift64.Unsupported:
            continue
        for ins in fl.insns:
            mn, ops = ins.mnemonic, ins.op_str
            if mn.startswith(SKIP) or 'rsp' in ops or 'esp' in ops or 'rip' in ops and 'lea' == mn:
                continue
            if re.search(r'\b(rsi|esi|si|sil)\b', MEM.sub('', ops)):
                continue
            forms.add(f'{mn} {MEM.sub(lambda m: (m.group(1) or "") + "[rsi + 32]", ops)}'.strip())
    def shape(f):
        k = re.sub(r'\b(r(?:ax|bx|cx|dx|si|di|bp)|r\d+)\b', 'G64', f)
        k = re.sub(r'\b(e(?:ax|bx|cx|dx|si|di|bp)|r\d+d)\b', 'G32', k)
        k = re.sub(r'\b((?:ax|bx|cx|dx|si|di|bp)|r\d+w)\b', 'G16', k)
        k = re.sub(r'\b((?:al|ah|bl|bh|cl|ch|dl|dh|sil|dil|bpl)|r\d+b)\b', 'G8', k)
        k = re.sub(r'\b(xmm|ymm)\d+\b', r'\1', k)
        return re.sub(r'\b(0x[0-9a-f]+|\d+)\b', 'I', k)
    picked = collections.defaultdict(list)
    for f in sorted(forms):
        if len(picked[shape(f)]) < 3:
            picked[shape(f)].append(f)
    return [f for fs in picked.values() for f in fs]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('insns', nargs='*')
    ap.add_argument('--trials', type=int, default=20000)
    ap.add_argument('--eboot')
    ap.add_argument('--batch', type=int, default=300)
    a = ap.parse_args()
    insns = a.insns or (eboot_forms(a.eboot) if a.eboot else DEFAULT)
    failed = 0
    for b in range(0, len(insns), a.batch):
        failed += run(insns[b:b + a.batch], a.trials)
    print(f'{failed} of {len(insns)} forms differ in all')
    sys.exit(1 if failed else 0)

def run(insns, trials):
    with tempfile.TemporaryDirectory() as work:
        lifted_c, native_s, names = [], ['.intel_syntax noprefix', '.text'], []
        for k, insn in enumerate(insns):
            try:
                code = assemble(insn, work)
            except subprocess.CalledProcessError:
                print(f'NOASM {insn}')
                continue
            fl = lift64.FuncLifter(OneInsn(code), 0x1000, len(code), set())
            try:
                body, _ = fl.lift()
            except lift64.Unsupported as ex:
                print(f'UNSUPPORTED {insn}: {ex}')
                continue
            lifted_c.append(body.replace('og_f_1000(', f'lifted_{k}('))
            native_s.append(native_asm(k, insn))
            names.append(k)
        decls = '\n'.join(f'void native_{k}(OgCtx*);' for k in names) + '\n' + lift64.HEADER.split('\n', 2)[2] + \
            '\n'.join(lifted_c)
        c = HARNESS.replace('@decls@', decls) \
            .replace('@names@', ', '.join('"' + insns[k].replace('"', '') + '"' for k in names)) \
            .replace('@natives@', ', '.join(f'native_{k}' for k in names)) \
            .replace('@lifteds@', ', '.join(f'lifted_{k}' for k in names)) \
            .replace('@undefined@', ', '.join(str(UNDEFINED.get(insns[k].split()[0], 0)) for k in names))
        open(os.path.join(work, 'h.c'), 'w').write(c)
        open(os.path.join(work, 'n.s'), 'w').write('\n'.join(native_s) + '\n')
        exe = os.path.join(work, 'h')
        r = subprocess.run(['clang', '-O1', '-w', '-mavx2', '-mbmi', '-mbmi2', '-mlzcnt', '-mpopcnt', '-mf16c', '-mfma',
                            '-I', HERE, '-o', exe, os.path.join(work, 'h.c'), os.path.join(work, 'n.s'), '-lm'],
                           capture_output=True, text=True)
        if r.returncode:
            print(r.stderr[-4000:])
            return len(names)
        out = subprocess.run([exe, str(trials)], capture_output=True, text=True)
        print('\n'.join(l for l in out.stdout.splitlines() if not l.startswith('ok ')))
        if out.returncode not in (0, 1):
            print(f'harness died ({out.returncode}) in this batch')
            return len(names)
        return sum(1 for l in out.stdout.splitlines() if l.startswith('FAIL'))

if __name__ == '__main__':
    main()
