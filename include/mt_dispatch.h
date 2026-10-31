#ifndef MT_DISPATCH_H
#define MT_DISPATCH_H

/*
 * mt_dispatch.h - the fleet edge, in C (phase 12c).
 *
 * What Maat::Router::_dispatch does per request, done without Perl for
 * the case that is every request in a healthy fleet: a known host, a
 * published tenant, caps not breached, an array response. Everything
 * else falls back to _dispatch in Perl, which remains the definition of
 * the semantics and the path the tests can force with
 * MAAT_FLEET_DISPATCH=perl.
 *
 * bench/edge.pl says what this is worth: a request end to end is 18.9us
 * on one worker, of which ~8.1us is the server and the kernel, ~4.5us is
 * the compiled request path, and ~6.3us is the Perl this file replaces.
 * That is ~45% of end-to-end throughput per worker - not the 141% the
 * in-process benchmark suggests, because the in-process number leaves
 * the kernel out and the kernel does not go away.
 *
 * THE COLD PATH IS HERE TOO
 *
 * This file answers everything: the ACME probe, an unknown host, an
 * expired tenant, every cap breach, an app that died. It was not always
 * so - the first cut handed all of those back to Maat::Router::_dispatch
 * - and leaving them there would have meant two implementations of one
 * behaviour, which is how they drift. The Perl is deleted, not bypassed.
 *
 * Two calls back into Perl remain, and both are calls to code that is
 * NOT a second implementation of anything here:
 *
 *   _c_miss  - a host this worker has never served. Compiling is
 *              Maat::Registry's whole job (fetch, digest, budget, LRU,
 *              poison) and belongs nowhere near a request path in C.
 *              Once per host per version; every request after it is
 *              answered here.
 *   _c_async - a streamed responder or a future, wrapped so the
 *              concurrency slot is released when it completes rather
 *              than when it is returned.
 *
 * The rule this file keeps: what it answers must be byte for byte what
 * the Perl answered before it was deleted. t/30 holds the wording of
 * every refusal as a literal, since there is no longer a Perl edge to
 * compare against.
 */

#include "mt_compat.h"
#include "mt_env.h"
#include "mt_fleet.h"
#include "mt_problem.h"

static const char MT_ACME_PREFIX[] = "/.well-known/acme-challenge/";

/* The two paths an MCP tenant answers itself. The endpoint is one path, not
 * a prefix: everything below it belongs to the customer's API. */
static const char MT_MCP_PATH[]     = "/mcp";
static const char MT_MCP_METADATA[] = "/.well-known/oauth-protected-resource";

/* The request headers' total size, the same sum Maat::Router::_header_bytes
 * makes: every HTTP_* key plus CONTENT_TYPE and CONTENT_LENGTH, names and
 * values both. A hash walk either way - what this saves is the Perl ops
 * around it, not the walk. */
static IV mt_header_bytes(pTHX_ HV *env) {
    HE *he;
    IV total = 0;
    hv_iterinit(env);
    while ((he = hv_iternext(env))) {
        I32 klen;
        const char *k = hv_iterkey(he, &klen);
        SV *v;
        if (!(klen > 5 && strnEQ(k, "HTTP_", 5))
            && !(klen == 12 && strEQ(k, "CONTENT_TYPE"))
            && !(klen == 14 && strEQ(k, "CONTENT_LENGTH")))
            continue;
        total += klen;
        v = hv_iterval(env, he);
        if (v && SvOK(v)) { STRLEN vl; (void)SvPV_const(v, vl); total += vl; }
    }
    return total;
}

/* Add X-Maat-Version and X-Maat-Proxy to a response, ONLY if the tenant's
 * own document did not set them - the same only-if-absent rule
 * Maat::Router::_stamp follows, so a customer who stamps their own
 * markers keeps theirs. */
/* A fixed-length, case-insensitive name match - the only kind of header
 * comparison this file needs. */
static int mt_hdr_is(const char *kp, STRLEN kl, const char *want, STRLEN wl) {
    STRLEN i;
    if (kl != wl) return 0;
    for (i = 0; i < wl; i++)
        if (toLOWER((U8)kp[i]) != (U8)want[i]) return 0;
    return 1;
}

static void mt_stamp_tenant(pTHX_ SV *res, mt_entry *e) {
    AV *trip = MT_AV(res), *hdrs;
    SV **h;
    SSize_t i, n;
    int have_v = 0, have_p = 0;

    if (!trip || av_len(trip) < 1) return;
    h = av_fetch(trip, 1, 0);
    hdrs = h ? MT_AV(*h) : NULL;
    if (!hdrs) return;

    n = av_len(hdrs) + 1;
    for (i = 0; i + 1 < n; i += 2) {
        SV **k = av_fetch(hdrs, i, 0);
        STRLEN kl;
        const char *kp;
        if (!k || !*k || !SvOK(*k)) continue;
        kp = SvPV_const(*k, kl);
        if (mt_hdr_is(kp, kl, "x-maat-version", 14)) have_v = 1;
        else if (mt_hdr_is(kp, kl, "x-maat-proxy",  12)) have_p = 1;
    }

    if (!have_v && e->version) {
        av_push(hdrs, newSVpvs("X-Maat-Version"));
        av_push(hdrs, newSVsv(e->version));
    }
    if (!have_p && e->proxy) {
        av_push(hdrs, newSVpvs("X-Maat-Proxy"));
        av_push(hdrs, newSViv(e->proxy));
    }
}

/* Call the tenant. DIRECT means a bare Maat::Gateway, whose C entry
 * point is called with no Perl frame at all - the whole reason the table
 * carries the gateway SV. Anything else (a portal wrap, a poison 503, an
 * injected test app) is a closure and is called as one. */
/* Call a PSGI closure. The non-direct half of mt_call_tenant, factored out
 * because the MCP branch calls an app of its own exactly this way. NULL when
 * the app died, which every caller turns into a 502. */
static SV *mt_call_closure(pTHX_ SV *app, SV *env_rv) {
    SV *res = NULL;
    dSP;
    int count;
    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 1);
    PUSHs(env_rv);
    PUTBACK;
    count = call_sv(app, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) { SV *r = POPs; res = newSVsv(r); }
    PUTBACK; FREETMPS; LEAVE;
    if (SvTRUE(ERRSV)) { if (res) SvREFCNT_dec(res); return NULL; }
    return res;
}

/* An exact PATH_INFO match: a length compare and a memcmp. */
static int mt_path_is(pTHX_ HV *env, const char *want, STRLEN wl) {
    SV *p = MT_ENV(env, "PATH_INFO");
    STRLEN pl;
    const char *pp;
    if (!p || !SvOK(p)) return 0;
    pp = SvPV_const(p, pl);
    return (pl == wl && memEQ(pp, want, wl)) ? 1 : 0;
}

static SV *mt_call_tenant(pTHX_ mt_entry *e, SV *env_rv) {
    if (e->flags & MT_E_DIRECT) return mt_serve(aTHX_ e->gw, env_rv);
    return mt_call_closure(aTHX_ e->app, env_rv);
}

/* Ask Perl to compile and publish a host we have never served.
 *
 * The one thing the C path cannot do for itself: a compile is
 * Maat::Registry's - the fetch, the digest check, the budget, the LRU,
 * the poison - and none of that belongs on a request path in C. So the
 * miss calls back once per host per version, and every request after it
 * is answered here.
 *
 * Maat::Router::_c_miss returns:
 *   a scalar ref  - published; look the host up again and carry on
 *   a response    - Perl answered it (a portal tenant, a poisoned host)
 *   undef         - nobody serves this host
 */
static SV *mt_miss(pTHX_ SV *router, SV *env_rv, int *published) {
    dSP;
    SV *ret = NULL;
    int count;

    *published = 0;
    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 2);
    PUSHs(router);
    PUSHs(env_rv);
    PUTBACK;
    count = call_method("_c_miss", G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) {
        SV *r = POPs;
        if (SvOK(r)) {
            if (SvROK(r) && SvTYPE(SvRV(r)) <= SVt_PVMG) *published = 1;
            else ret = newSVsv(r);
        }
    }
    PUTBACK; FREETMPS; LEAVE;
    return ret;
}

/* An async response - a streamed responder or a future - keeps the
 * concurrency slot until it completes, and getting that wrong leaks a
 * slot until the tenant is wrongly 429ed hours later. The wrapping is
 * Perl's, and it is handed the token so it can release the exact entry
 * this request took. See Maat::Router::_c_async. */
static SV *mt_async(pTHX_ SV *router, SV *res, mt_entry *e, IV token) {
    dSP;
    SV *ret = NULL;
    int count;

    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 5);
    PUSHs(router);
    PUSHs(res);
    PUSHs(sv_2mortal(newSViv(e->proxy)));
    PUSHs(e->version ? e->version : &PL_sv_undef);
    PUSHs(sv_2mortal(newSViv(token)));
    PUTBACK;
    count = call_method("_c_async", G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) { SV *r = POPs; if (SvOK(r)) ret = newSVsv(r); }
    PUTBACK; FREETMPS; LEAVE;
    return ret;
}

/*
 * One request, answered here. Always returns a response: the cold cases
 * are C's too now, and the only call back into Perl is the compile a
 * miss needs and the wrapping an async response needs.
 */
static SV *mt_dispatch(pTHX_ SV *router, mt_fleet *f, HV *metrics, SV *env_rv) {
    HV *env = MT_HV(env_rv);
    mt_entry *e;
    SV *host_sv, *cl_sv, *res;
    STRLEN hl;
    const char *hp;
    IV token;

    if (!f || !env) return mt_problem_unknown_host(aTHX);

    /* The ACME probe, before routing: the domain being validated has no
     * tenant entry yet, by definition, so it is answered for any host. */
    {
        SV *path = MT_ENV(env, "PATH_INFO");
        if (path) {
            STRLEN pl;
            const char *pp = SvPV_const(path, pl);
            STRLEN plen = sizeof(MT_ACME_PREFIX) - 1;
            if (pl >= plen && strnEQ(pp, MT_ACME_PREFIX, plen)) {
                SV **slot = hv_fetch(f->challenges, pp + plen,
                                     (I32)(pl - plen), 0);
                if (slot && *slot && SvOK(*slot)) {
                    if (metrics) MT_COUNT(metrics, "acme_hit");
                    return mt_text(aTHX_ 200, newSVsv(*slot));
                }
                if (metrics) MT_COUNT(metrics, "acme_miss");
                return mt_text(aTHX_ 404, NULL);
            }
        }
    }

    host_sv = MT_ENV(env, "HTTP_HOST");
    if (!host_sv) {
        if (metrics) MT_COUNT(metrics, "unknown");
        return mt_problem_unknown_host(aTHX);
    }
    hp = SvPV_const(host_sv, hl);

    e = mt_fleet_lookup(aTHX_ f, hp, hl);
    if (!e) {
        int published = 0;
        SV *answered = mt_miss(aTHX_ router, env_rv, &published);
        if (answered) return answered;            /* Perl had its own answer */
        if (published) {
            hp = SvPV_const(host_sv, hl);         /* the SV may have moved */
            e = mt_fleet_lookup(aTHX_ f, hp, hl);
        }
        if (!e) {
            if (metrics) MT_COUNT(metrics, "unknown");
            return mt_problem_unknown_host(aTHX);
        }
    }

    /* Defence in depth against a stale bundle: an expired tenant is an
     * unknown host, exactly as resolve treats it. */
    if (e->expires > 0 && (IV)time(NULL) > e->expires) {
        if (metrics) MT_COUNT(metrics, "unknown");
        return mt_problem_unknown_host(aTHX);
    }

    e->requests++;
    if (metrics) MT_COUNT(metrics, "routed");

    /* ---- isolation, before the tenant app is entered ------------------ */
    cl_sv = MT_ENV(env, "CONTENT_LENGTH");
    if (cl_sv) {
        STRLEN cl_len;
        const char *cp = SvPV_const(cl_sv, cl_len);
        STRLEN i;
        int digits = cl_len > 0;
        for (i = 0; i < cl_len; i++)
            if (cp[i] < '0' || cp[i] > '9') { digits = 0; break; }
        if (digits && SvIV(cl_sv) > e->max_body) {
            e->rejected_body++;
            if (metrics) MT_COUNT(metrics, "rejected");
            return mt_problem_too_large(aTHX_ e->max_body);
        }
    }
    if (mt_header_bytes(aTHX_ env) > e->max_header_bytes) {
        e->rejected_header++;
        if (metrics) MT_COUNT(metrics, "rejected");
        return mt_problem_headers(aTHX);
    }
    if (e->inflight >= e->concurrency) {
        /* The ceiling is the confinement: a tenant with a hung upstream
         * piles up against ITS OWN ceiling while every neighbour's slots
         * are untouched. */
        e->rejected_concurrency++;
        if (metrics) MT_COUNT(metrics, "rejected");
        return mt_problem_busy(aTHX_ e->concurrency);
    }

    /* The tenant's CURRENT keys, from the entry rather than baked into
     * the compiled app: a revocation republishes here without touching
     * the spec, so the app must read them per request (gate 4 keeps a
     * keyless tenant's env untouched). */
    if (e->keys) (void)hv_stores(env, "maat.keys", newSVsv(e->keys));

    /* And the authorization server's keys, for an OAuth tool call. Only
     * when a bundle carried some, so a fleet that has never seen OAuth
     * builds exactly the environment it always did. */
    if (f->jwks) (void)hv_stores(env, "maat.jwks", newSVsv(f->jwks));

    /* The MCP endpoint, answered before the tenant app is entered at all.
     *
     * The ACME branch above is the model, but this one runs AFTER the host is
     * resolved, because /mcp is a tenant's own surface rather than the edge's
     * - and after the isolation checks, because it is a request like any
     * other and takes a slot like one. e->concurrency is what confines a
     * tenant with a hung upstream to its own share of the worker, so a
     * surface that skipped it would be a way around that confinement.
     *
     * `maat.keys` is already on the env above, which is what lets the
     * endpoint authenticate without a second lookup. */
    if ((e->flags & MT_E_MCP) && e->mcp
        && (mt_path_is(aTHX_ env, MT_MCP_PATH, sizeof(MT_MCP_PATH) - 1)
         || mt_path_is(aTHX_ env, MT_MCP_METADATA, sizeof(MT_MCP_METADATA) - 1)))
    {
        SV *res;
        mt_entry_acquire(e);
        res = mt_call_closure(aTHX_ e->mcp, env_rv);
        mt_entry_done(aTHX_ f, e);
        if (metrics) MT_COUNT(metrics, "mcp");
        return res ? res : mt_problem_bad_gateway(aTHX);
    }

    mt_entry_acquire(e);
    token = PTR2IV(e);
    res = mt_call_tenant(aTHX_ e, env_rv);

    if (!res) {                       /* the tenant app died */
        mt_entry_done(aTHX_ f, e);
        return mt_problem_bad_gateway(aTHX);
    }

    if (!MT_AV(res)) {
        /* Streamed or deferred: Perl wraps it and releases the slot when
         * it completes, using the token for this exact entry. */
        SV *wrapped = mt_async(aTHX_ router, res, e, token);
        SvREFCNT_dec(res);
        if (wrapped) return wrapped;
        mt_entry_done(aTHX_ f, e);    /* the wrap failed - do not leak */
        return mt_problem_bad_gateway(aTHX);
    }

    mt_stamp_tenant(aTHX_ res, e);
    mt_entry_done(aTHX_ f, e);
    return res;
}

#endif /* MT_DISPATCH_H */
