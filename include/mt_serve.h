#ifndef MT_SERVE_H
#define MT_SERVE_H

/* The request path.
 *
 * One function, because the cost of the Perl version was its shape - a
 * dozen ops and four crossings for two calls' worth of work - and not
 * any line in it. The order of operations, the counters and every
 * fail-open branch are identical to the Perl this replaces; t/02, t/03,
 * t/04, t/05 and t/06 are the contract and none of them changed.
 *
 * Calls that must still reach Perl, all under G_EVAL:
 *   $api->match / $api->validate_env   Open::API's router and validator
 *   $proxy->($env)                     Reverse::Proxy's forward
 *   $v->record(...) / _problem(...)    only when a request has violated
 *
 * Everything else - the id, the counters, the header stamp, the chaos
 * points, the branching - stays here.
 */

/* Slots on the gateway, fetched once per request from $self. */
typedef struct mt_gw {
    SV *api;
    SV *proxy;
    HV *counters;
    SV *violation;
    HV *chaos;
    IV  enforce;
    IV  max_body;
    IV  has_auth;
    IV  observe;      /* observe-only drift on: report undeclared paths */
    SV *self;
} mt_gw;

static int mt_load(pTHX_ SV *self, mt_gw *g) {
    HV *h = MT_HV(self), *conf;
    SV **e;
    if (!h) return 0;
    Zero(g, 1, mt_gw);
    g->self = self;
    if ((e = hv_fetchs(h, "api", 0)))       g->api   = *e;
    if ((e = hv_fetchs(h, "proxy", 0)))     g->proxy = *e;
    if ((e = hv_fetchs(h, "violation", 0))) {
        HV *v = MT_HV(*e);
        g->violation = *e;
        if (v && (e = hv_fetchs(v, "counters", 0))) g->counters = MT_HV(*e);
    }
    if ((e = hv_fetchs(h, "chaos", 0))) g->chaos = MT_HV(*e);
    /* Spec-driven auth is off unless _build_auth armed it (keys issued
     * AND the document declares a security scheme). When off the request
     * path below never enters the auth step, so a keyless gateway is the
     * phase-1 path byte for byte. */
    if ((e = hv_fetchs(h, "auth", 0)) && *e && SvTRUE(*e)) g->has_auth = 1;
    /* Observe-only drift reporting for the two path-level categories an
     * undeclared/wrong-method request produces. Precomputed in Perl
     * (Maat::Gateway::new): on unless the tenant turned it off, and always
     * off in mock mode, so the branches below need only read the flag. */
    if ((e = hv_fetchs(h, "observe", 0)) && *e && SvTRUE(*e)) g->observe = 1;
    if ((e = hv_fetchs(h, "config", 0)) && (conf = MT_HV(*e))) {
        SV **m = hv_fetchs(conf, "mode", 0);
        SV **b = hv_fetchs(conf, "max_body", 0);
        if (m && *m && SvOK(*m)) {
            /* mock shares enforce's rejection path: a mock has no
             * upstream to forward a non-conforming request to, so the
             * 400 with its pointers is the only honest answer */
            const char *mv = SvPV_nolen(*m);
            g->enforce = (strEQ(mv, "enforce") || strEQ(mv, "mock")) ? 1 : 0;
        }
        g->max_body = (b && *b && SvOK(*b)) ? SvIV(*b) : 1048576;
    }
    return (g->api && g->proxy) ? 1 : 0;
}

/* ---- the request id --------------------------------------------------------
 * The client's if it brought one, ours otherwise. Horus's uuid_v7 is an
 * XSUB; its CV is looked up once and called directly, so this is one
 * call with no argument marshalling rather than a method dispatch. */
static SV *mt_request_id(pTHX_ HV *env) {
    static CV *uuid_cv = NULL;
    SV *rid = MT_ENV(env, "HTTP_X_REQUEST_ID");
    dSP;
    int count;

    if (rid && SvCUR(rid)) return rid;

    if (!uuid_cv) uuid_cv = get_cv("Horus::uuid_v7", 0);
    if (!uuid_cv) {                       /* Horus gone: still answerable */
        rid = newSVpvf("%d-%d", (int)time(NULL), (int)PerlProc_getpid());
        (void)hv_stores(env, "HTTP_X_REQUEST_ID", rid);
        return rid;
    }

    PUSHMARK(SP);
    PUTBACK;
    count = call_sv((SV *)uuid_cv, G_SCALAR | G_EVAL);
    SPAGAIN;
    rid = (count > 0 && !SvTRUE(ERRSV)) ? newSVsv(POPs) : NULL;
    PUTBACK;
    if (!rid)
        rid = newSVpvf("%d-%d", (int)time(NULL), (int)PerlProc_getpid());
    (void)hv_stores(env, "HTTP_X_REQUEST_ID", rid);
    return rid;
}

/* ---- the header stamp ------------------------------------------------------
 * X-Request-Id on the way out, unless the upstream set its own. */
static void mt_stamp(pTHX_ SV *res, SV *rid) {
    AV *trip = MT_AV(res), *hdrs;
    SV **h;
    SSize_t i, n;
    if (!trip || av_len(trip) < 1) return;
    h = av_fetch(trip, 1, 0);
    hdrs = h ? MT_AV(*h) : NULL;
    if (!hdrs) return;
    n = av_len(hdrs) + 1;
    for (i = 0; i + 1 < n; i += 2) {
        SV **k = av_fetch(hdrs, i, 0);
        if (k && *k && SvOK(*k)) {
            STRLEN kl;
            const char *kp = SvPV_const(*k, kl);
            if (kl == 14 && strnEQ(kp, "X-Request-Id", 12)) return;  /* len guard */
            if (kl == 12) {
                STRLEN j;
                int same = 1;
                for (j = 0; j < 12; j++)
                    if (toLOWER((U8)kp[j]) != "x-request-id"[j]) { same = 0; break; }
                if (same) return;
            }
        }
    }
    av_push(hdrs, newSVpvs("X-Request-Id"));
    av_push(hdrs, newSVsv(rid));
}

/* ---- calling out -----------------------------------------------------------
 * Every one of these is G_EVAL: a die inside Open::API, inside the
 * proxy, or injected by chaos, must land in the caller's failure branch
 * and never propagate. */

/* $api->match($method, $path) -> (op, caps|allow). Returns the op SV
 * (mortal, may be undef), fills *extra with the second return. */
static int mt_match(pTHX_ SV *api, HV *env, SV **op_out, SV **extra_out) {
    dSP;
    int count;
    SV *m = MT_ENV(env, "REQUEST_METHOD");
    SV *p = MT_ENV(env, "PATH_INFO");

    *op_out = NULL;
    *extra_out = NULL;

    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 3);
    PUSHs(api);
    PUSHs(m ? m : &PL_sv_undef);
    PUSHs(p ? p : &PL_sv_undef);
    PUTBACK;
    count = call_method("match", G_LIST | G_EVAL);
    SPAGAIN;
    if (SvTRUE(ERRSV)) { while (count-- > 0) (void)POPs; PUTBACK; FREETMPS; LEAVE; return 0; }
    if (count >= 2) { SV *x = POPs; SV *o = POPs;
                      *extra_out = newSVsv(x); *op_out = newSVsv(o); count -= 2; }
    else if (count == 1) { SV *o = POPs; *op_out = newSVsv(o); count--; }
    while (count-- > 0) (void)POPs;
    PUTBACK;
    FREETMPS; LEAVE;
    if (*op_out)    sv_2mortal(*op_out);
    if (*extra_out) sv_2mortal(*extra_out);
    return 1;
}

/* $api->validate_env($op, $env, $caps, $body) -> ($ok, $result) */
static int mt_validate(pTHX_ SV *api, SV *op, SV *env_rv, SV *caps, SV *body,
                       int *valid, SV **result) {
    dSP;
    int count;
    *valid = 0;
    *result = NULL;

    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 5);
    PUSHs(api);
    PUSHs(op);
    PUSHs(env_rv);
    PUSHs(caps ? caps : &PL_sv_undef);
    PUSHs(body ? body : &PL_sv_undef);
    PUTBACK;
    count = call_method("validate_env", G_LIST | G_EVAL);
    SPAGAIN;
    if (SvTRUE(ERRSV)) { while (count-- > 0) (void)POPs; PUTBACK; FREETMPS; LEAVE; return 0; }
    if (count >= 2) { SV *r = POPs; SV *o = POPs;
                      *result = newSVsv(r); *valid = SvTRUE(o) ? 1 : 0; count -= 2; }
    /* POP into a temporary, exactly as the two-value branch above does.
     * SvTRUE evaluated its argument more than once before perl 5.32, so
     * SvTRUE(POPs) pops repeatedly and walks SP below the stack base. */
    else if (count == 1) { SV *o = POPs; *valid = SvTRUE(o) ? 1 : 0; count--; }
    while (count-- > 0) (void)POPs;
    PUTBACK;
    FREETMPS; LEAVE;
    if (*result) sv_2mortal(*result);
    return 1;
}

/* Maat::Gateway::_forward($proxy, $env, $rid, $seen) - still Perl: it
 * owns the three response shapes and the response-check hook, which is
 * phase 2's and changes independently of this file. */
static SV *mt_forward(pTHX_ mt_gw *g, SV *env_rv, SV *rid, SV *seen) {
    dSP;
    int count;
    SV *out = NULL;
    static CV *fwd = NULL;
    if (!fwd) fwd = get_cv("Maat::Gateway::_forward", 0);

    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 4);
    PUSHs(g->proxy);
    PUSHs(env_rv);
    PUSHs(rid);
    PUSHs(seen ? seen : &PL_sv_undef);
    PUTBACK;
    count = call_sv((SV *)fwd, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) { SV *r = POPs; if (!SvTRUE(ERRSV)) out = newSVsv(r); }
    PUTBACK;
    FREETMPS; LEAVE;
    return out ? out : newRV_noinc((SV *)newAV());   /* never NULL to PSGI */
}

/* The Perl helpers for the two rare paths. Rare by construction: a
 * violation is not the common case, and if it becomes the common case
 * the customer has a bigger problem than our microseconds. */
static SV *mt_call_perl(pTHX_ const char *name, SV **args, int nargs) {
    dSP;
    int i, count;
    SV *out = NULL;
    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, nargs);
    for (i = 0; i < nargs; i++) PUSHs(args[i] ? args[i] : &PL_sv_undef);
    PUTBACK;
    count = call_pv(name, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) { SV *r = POPs; if (!SvTRUE(ERRSV)) out = newSVsv(r); }
    PUTBACK;
    FREETMPS; LEAVE;
    return out;
}

/* ---- the path --------------------------------------------------------------- */

static SV *mt_serve(pTHX_ SV *self, SV *env_rv) {
    mt_gw g;
    HV *env = MT_HV(env_rv);
    SV *rid, *op = NULL, *extra = NULL, *body = NULL, *seen = NULL, *result = NULL;
    int valid = 0;

    if (!env || !mt_load(aTHX_ self, &g))
        croak("Maat::Gateway: _serve needs a gateway and a PSGI environment");

    MT_COUNT(g.counters, "request");

    rid = mt_request_id(aTHX_ env);
    (void)hv_stores(env, "maat.request_id", newSVsv(rid));

    /* ---- match ---------------------------------------------------------
     * `freed` takes the handle away for this request, so the failure is a
     * real method call on a gone object - the shape a use-after-free
     * reaches Perl as. */
    {
        SV *handle = mt_chaos_on(aTHX_ g.chaos, MT_CH_FREED) ? &PL_sv_undef : g.api;
        int ok;
        if (mt_chaos_on(aTHX_ g.chaos, MT_CH_MATCH)) ok = 0;
        else ok = mt_match(aTHX_ handle, env, &op, &extra);
        if (!ok) {
            MT_COUNT(g.counters, "failed");
            return mt_forward(aTHX_ &g, env_rv, rid, NULL);
        }
    }

    if (!op || !SvOK(op)) {
        AV *allow = MT_AV(extra);
        if (allow) {
            MT_COUNT(g.counters, "wrong_method");
            if (g.enforce) {
                SV *args[3];
                SV *res;
                MT_COUNT(g.counters, "rejected");
                args[0] = rid;
                args[1] = sv_2mortal(newSVsv(extra));
                args[2] = MT_ENV(env, "REQUEST_METHOD");
                res = mt_call_perl(aTHX_ "Maat::Gateway::_problem_405", args, 3);
                if (res) return res;
                /* even the rejection failed: forward rather than invent */
                MT_COUNT(g.counters, "failed");
            }
        }
        else {
            /* THE most important default in the product: a document that
             * does not cover everything is the normal case. */
            MT_COUNT(g.counters, "undeclared");
        }
        /* Observe-only: the API surface the contract does not cover is
         * drift a team wants to see, even though it is forwarded untouched.
         * `extra` is the allow list for a wrong-method and undef for a
         * plain undeclared path; the Perl side reads which from its shape.
         * Off in mock mode (g.observe is 0 there) - nothing is forwarded to
         * drift against. Enforced wrong-method already returned a 405
         * above and does not reach here. */
        if (g.observe) {
            SV *a[4], *r;
            a[0] = self;
            a[1] = rid;
            a[2] = env_rv;
            a[3] = extra ? extra : &PL_sv_undef;
            r = mt_call_perl(aTHX_ "Maat::Gateway::_record_undeclared", a, 4);
            if (r) SvREFCNT_dec(r);
        }
        return mt_forward(aTHX_ &g, env_rv, rid, NULL);
    }

    /* ---- spec-driven auth + rate limit --------------------------------
     * Only when the tenant configured keys AND the document declares a
     * security scheme (g.has_auth). This runs before the body is read or
     * the request validated - the same order the Plack dispatch checks
     * security in. _authorize returns undef to proceed (an unsecured
     * operation, or an authorized-and-within-limit one - the whole of the
     * off-by-default guarantee), or a PSGI response (401 unauthorized /
     * 429 rate limited) to answer here. It never dies: a bug in our own
     * auth falls through to proceed rather than becoming a 500. */
    if (g.has_auth) {
        SV *args[4];
        SV *deny;
        args[0] = self;
        args[1] = op;
        args[2] = env_rv;
        args[3] = rid;
        deny = mt_call_perl(aTHX_ "Maat::Gateway::_authorize", args, 4);
        if (deny) {
            if (SvOK(deny) && SvROK(deny)) return deny;   /* 401 / 429 */
            SvREFCNT_dec(deny);
        }
    }

    /* From here there is an operation, so the response can be weighed
     * against what the document declares whatever happens below. */
    {
        SV *args[4];
        args[0] = self;
        args[1] = op;
        args[2] = rid;
        args[3] = env_rv;
        seen = mt_call_perl(aTHX_ "Maat::Gateway::_seen", args, 4);
        if (seen) sv_2mortal(seen);
        if (seen && !SvOK(seen)) seen = NULL;
    }

    /* ---- the body ------------------------------------------------------ */
    {
        SV *len_sv = MT_ENV(env, "CONTENT_LENGTH");
        IV len = len_sv ? SvIV(len_sv) : 0;
        if (len > 0) {
            if (len > g.max_body) {
                MT_COUNT(g.counters, "skipped");
                return mt_forward(aTHX_ &g, env_rv, rid, seen);
            }
            if (mt_chaos_on(aTHX_ g.chaos, MT_CH_ALLOC)) {
                MT_COUNT(g.counters, "failed");
                return mt_forward(aTHX_ &g, env_rv, rid, seen);
            }
            {
                SV *args[2];
                args[0] = env_rv;
                args[1] = sv_2mortal(newSViv(len));
                body = mt_call_perl(aTHX_ "Maat::Gateway::_slurp_input", args, 2);
                if (body) sv_2mortal(body);
                if (!body || !SvOK(body)) {
                    MT_COUNT(g.counters, "failed");
                    return mt_forward(aTHX_ &g, env_rv, rid, seen);
                }
            }
        }
    }

    /* ---- validate ------------------------------------------------------ */
    {
        int ok;
        SV *caps = (extra && MT_HV(extra)) ? extra : NULL;
        if (mt_chaos_on(aTHX_ g.chaos, MT_CH_VALIDATE)) ok = 0;
        else ok = mt_validate(aTHX_ g.api, op, env_rv, caps, body, &valid, &result);
        if (!ok) {
            MT_COUNT(g.counters, "failed");
            return mt_forward(aTHX_ &g, env_rv, rid, seen);
        }
    }

    if (valid) {
        MT_COUNT(g.counters, "conforming");
        return mt_forward(aTHX_ &g, env_rv, rid, seen);
    }

    /* ---- a violation ---------------------------------------------------
     * Recording is bookkeeping, not the check: validation ran and
     * returned a verdict, and the verdict stands whether or not the
     * record survives. If a failing reporter downgraded enforcement,
     * anyone who could stall the violation pipeline could switch off
     * request validation. */
    {
        SV *args[6];
        SV *rec;
        args[0] = self;
        args[1] = rid;
        args[2] = op;
        args[3] = env_rv;
        args[4] = result ? result : &PL_sv_undef;
        args[5] = sv_2mortal(newSViv(
            mt_chaos_on(aTHX_ g.chaos, MT_CH_RECORD) ? 1 :
            mt_chaos_on(aTHX_ g.chaos, MT_CH_BLOCK)  ? 2 : 0));
        rec = mt_call_perl(aTHX_ "Maat::Gateway::_record_request", args, 6);
        if (rec) SvREFCNT_dec(rec);
    }

    if (g.enforce) {
        SV *args[3];
        SV *res;
        MT_COUNT(g.counters, "rejected");
        args[0] = rid;
        args[1] = result ? result : &PL_sv_undef;
        args[2] = NULL;
        res = mt_call_perl(aTHX_ "Maat::Gateway::_problem_400", args, 2);
        if (res) return res;
        MT_COUNT(g.counters, "failed");
    }
    return mt_forward(aTHX_ &g, env_rv, rid, seen);
}

#endif /* MT_SERVE_H */
