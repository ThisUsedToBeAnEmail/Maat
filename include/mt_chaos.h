#ifndef MT_CHAOS_H
#define MT_CHAOS_H

/* MAAT_CHAOS, in C.
 *
 * The injection points live here rather than in a Perl wrapper for one
 * reason: a fail-open path that is only exercised through a wrapper is
 * not the path that runs in production. These fire inside mt_serve, at
 * the same instants the real failures would.
 *
 *   freed      the compiled spec handle is gone for this request
 *   match      routing dies
 *   alloc      buffering the request body fails
 *   validate   the validator dies
 *   record     the violation reporter dies
 *   block      the reporter blocks until the watchdog abandons it
 *   response   the response check dies
 *
 * Each point takes a rate: `validate:0.1` fires on one request in ten.
 */

#define MT_CHAOS_POINTS 7

typedef enum {
    MT_CH_FREED = 0, MT_CH_MATCH, MT_CH_ALLOC, MT_CH_VALIDATE,
    MT_CH_RECORD, MT_CH_BLOCK, MT_CH_RESPONSE
} mt_chaos_point;

static const char *const MT_CHAOS_NAME[MT_CHAOS_POINTS] = {
    "freed", "match", "alloc", "validate", "record", "block", "response"
};

/* The parsed form is a plain Perl hash - name => rate - so it stays
 * inspectable from Perl and the tests can build one by hand. */
static SV *mt_chaos_parse(pTHX_ SV *spec) {
    HV *out;
    const char *p, *end;
    STRLEN len;
    if (!spec || !SvOK(spec)) return &PL_sv_undef;
    p = SvPV_const(spec, len);
    if (!len) return &PL_sv_undef;
    out = newHV();
    end = p + len;

    while (p < end) {
        const char *comma, *colon, *name_end;
        STRLEN nl;
        NV rate = 1.0;
        while (p < end && (*p == ' ' || *p == ',')) p++;
        if (p >= end) break;
        comma = (const char *)memchr(p, ',', (size_t)(end - p));
        if (!comma) comma = end;
        colon = (const char *)memchr(p, ':', (size_t)(comma - p));
        name_end = colon ? colon : comma;
        while (name_end > p && name_end[-1] == ' ') name_end--;
        nl = (STRLEN)(name_end - p);
        if (colon && colon + 1 < comma) {
            char buf[32];
            STRLEN rl = (STRLEN)(comma - colon - 1);
            if (rl >= sizeof buf) rl = sizeof buf - 1;
            memcpy(buf, colon + 1, rl);
            buf[rl] = '\0';
            rate = Atof(buf);
        }
        if (nl == 3 && strnEQ(p, "all", 3)) {
            int i;
            for (i = 0; i < MT_CHAOS_POINTS; i++)
                (void)hv_store(out, MT_CHAOS_NAME[i],
                               (I32)strlen(MT_CHAOS_NAME[i]), newSVnv(rate), 0);
        }
        else if (nl) {
            char lc[32];
            STRLEN k, n = nl < sizeof lc - 1 ? nl : sizeof lc - 1;
            for (k = 0; k < n; k++) lc[k] = (char)toLOWER((U8)p[k]);
            (void)hv_store(out, lc, (I32)n, newSVnv(rate), 0);
        }
        p = comma + 1;
    }
    return newRV_noinc((SV *)out);
}

/* Is this point armed for this request? Rate 1 always, otherwise a
 * draw. Reads the same hash mt_chaos_parse built. */
static int mt_chaos_on(pTHX_ HV *chaos, mt_chaos_point pt) {
    SV **e;
    NV rate;
    if (!chaos) return 0;
    e = hv_fetch(chaos, MT_CHAOS_NAME[pt],
                 (I32)strlen(MT_CHAOS_NAME[pt]), 0);
    if (!e || !*e || !SvOK(*e)) return 0;
    rate = SvNV(*e);
    if (rate >= 1.0) return 1;
    if (rate <= 0.0) return 0;
    return Drand01() < rate ? 1 : 0;
}

#endif /* MT_CHAOS_H */
