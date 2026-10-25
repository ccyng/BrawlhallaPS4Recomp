#include <math.h>

#include "hle.h"

HLE(pow) { RETD(c, pow(ARGD(c, 0), ARGD(c, 1))); }
HLE(exp) { RETD(c, exp(ARGD(c, 0))); }
HLE(exp2) { RETD(c, exp2(ARGD(c, 0))); }
HLE(ldexp) { RETD(c, ldexp(ARGD(c, 0), (int)ARG(c, 0))); }
HLE(acosf) { RETF(c, acosf(ARGF(c, 0))); }
HLE(asinf) { RETF(c, asinf(ARGF(c, 0))); }
HLE(tanf) { RETF(c, tanf(ARGF(c, 0))); }
HLE(atan2f) { RETF(c, atan2f(ARGF(c, 0), ARGF(c, 1))); }

HLE(_Sin) { RETD(c, (ARG(c, 0) & 1) ? cos(ARGD(c, 0)) : sin(ARGD(c, 0))); }
HLE(_FSin) { RETF(c, (ARG(c, 0) & 1) ? cosf(ARGF(c, 0)) : sinf(ARGF(c, 0))); }
HLE(_Log) {
    const double x = ARGD(c, 0);
    const int base = (int)ARG(c, 0);
    RETD(c, base == 0 ? log(x) : base > 0 ? log10(x) : log2(x));
}

const HleFunc hle_math_funcs[] = {
    HLE_FUNC(pow), HLE_FUNC(exp), HLE_FUNC(exp2), HLE_FUNC(ldexp), HLE_FUNC(acosf), HLE_FUNC(asinf),
    HLE_FUNC(tanf), HLE_FUNC(atan2f), HLE_FUNC(_Sin), HLE_FUNC(_FSin), HLE_FUNC(_Log),
    {NULL, NULL},
};
