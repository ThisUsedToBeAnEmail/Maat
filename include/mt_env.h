#ifndef MT_ENV_H
#define MT_ENV_H

/* The PSGI environment, and the counters, reached the short way. */

/* $env->{$key}, or NULL when absent or undef. */
static SV *mt_env_get(pTHX_ HV *env, const char *k, STRLEN kl) {
    SV **e = hv_fetch(env, k, (I32)kl, 0);
    return (e && *e && SvOK(*e)) ? *e : NULL;
}
#define MT_ENV(env, k) mt_env_get(aTHX_ (env), "" k "", sizeof(k) - 1)

/* One counter, in place. The counters are an ordinary Perl hash so that
 * $gw->counters keeps working and the tests keep reading it; what this
 * removes is the method call and the second hash lookup, not the hash. */
static void mt_count_hv(pTHX_ HV *counters, const char *name, STRLEN nl, IV n) {
    SV **slot;
    if (!counters) return;
    slot = hv_fetch(counters, name, (I32)nl, 1);
    if (!slot || !*slot) return;
    if (SvIOK(*slot)) SvIV_set(*slot, SvIVX(*slot) + n);
    else              sv_setiv(*slot, SvIV(*slot) + n);
    SvIOK_on(*slot);
}
#define MT_COUNT(c, name) mt_count_hv(aTHX_ (c), "" name "", sizeof(name) - 1, 1)

static void mt_count(pTHX_ SV *counters, SV *name, IV n) {
    STRLEN nl;
    const char *np;
    HV *hv = MT_HV(counters);
    if (!hv || !name) return;
    np = SvPV_const(name, nl);
    mt_count_hv(aTHX_ hv, np, nl, n);
}

#endif /* MT_ENV_H */
