#ifndef MT_MCP_H
#define MT_MCP_H

/*
 * mt_mcp.h - the MCP endpoint's request path, in C.
 *
 * An agent's tool call is a request through this gateway, and it is framed,
 * dispatched and answered without unwinding into Perl - the same rule
 * mt_serve.h keeps for the API path, and for the same reason: a path that is
 * only C in places is a path whose cost nobody can state.
 *
 * What is NOT here is everything that happens once: the tool table, the
 * frozen tools/list bytes and this server's identity are built when the
 * tenant is compiled (lib/Maat/MCP.pm) and only read here.
 *
 * THE ONE THING THAT MATTERS ARCHITECTURALLY: a tools/call re-enters
 * mt_serve DIRECTLY. Not a copy of it, not a second validator - the same C
 * entry the customer's own clients reach. So a tool call is matched,
 * authorised, rate limited, validated, sampled, metered and forwarded exactly
 * as a request is, because it IS one. Everything this product already counts,
 * it counts for agents for free.
 *
 * Three C ABIs are used directly rather than through Perl, because all three
 * are on this path: File::Raw::JSON decodes the envelope and encodes the
 * reply, JSON::Schema::Fast validates a call's arguments against the tool's
 * schema, and Crypt::JWS hashes the presented key and compares it in constant
 * time. All three headers are vendored beside this one and all three are
 * resolved at runtime and version-gated; absent or too old, the endpoint
 * answers and says why.
 *
 * Needs mt_compat.h, mt_env.h and mt_serve.h (for mt_serve and mt_call_perl).
 */

#include "mt_compat.h"
#include "mt_env.h"
#include "frj_abi.h"
#include "jsf_abi.h"
#include "jws_abi.h"

#define MT_MCP_PROTO_CURRENT "2025-06-18"
#define MT_MCP_PROTO_PRIOR   "2025-03-26"

/* RFC 9728. The dispatcher routes this path here too, so the document that
 * tells a client HOW to authenticate is served by the thing it authenticates
 * against. */
#define MT_MCP_METADATA_PATH "/.well-known/oauth-protected-resource"

/* An MCP envelope is small. The tenant's own cap is for API bodies, and a
 * megabyte of JSON-RPC is not a request, it is an attack. */
#define MT_MCP_BODY_MAX 1048576

/* What a tool result may carry back to a model. A model cannot use more, and
 * a ceiling it cannot see is worse than one it can. */
#define MT_MCP_RESULT_MAX 262144

/* JSON-RPC 2.0 */
#define MT_RPC_PARSE    (-32700)
#define MT_RPC_REQUEST  (-32600)
#define MT_RPC_METHOD   (-32601)
#define MT_RPC_PARAMS   (-32602)
#define MT_RPC_INTERNAL (-32603)

/* ---- the two tables ------------------------------------------------------ */

static const frj_abi *MT_FRJ = NULL;
static int MT_FRJ_TRIED = 0;
static const jsf_abi *MT_JSF = NULL;
static int MT_JSF_TRIED = 0;
static const jws_abi *MT_JWS = NULL;
static int MT_JWS_TRIED = 0;

/* The pointer comes back as a UV, never an IV: a shared library mapped above
 * the sign bit hands back a negative integer otherwise, which is a real
 * failure on illumos and on any 32-bit build in the upper 2GB. */
static UV mt_abi_ptr(pTHX_ const char *require_name, const char *fn) {
    dSP;
    int count;
    UV p = 0;
    SV *req = newSVpvf("require %s;", require_name);

    eval_sv(req, G_DISCARD | G_EVAL);
    SvREFCNT_dec(req);
    /* The require ran arbitrary Perl, which may have reallocated the value
     * stack; the SP captured above would then point into freed memory. */
    SPAGAIN;
    if (SvTRUE(ERRSV)) return 0;

    ENTER; SAVETMPS; PUSHMARK(SP); PUTBACK;
    count = call_pv(fn, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) {
        SV *r = POPs;
        if (!SvTRUE(ERRSV)) p = SvUV(r);
    }
    PUTBACK; FREETMPS; LEAVE;
    return p;
}

static const frj_abi *mt_frj(pTHX) {
    if (!MT_FRJ && !MT_FRJ_TRIED) {
        UV p;
        MT_FRJ_TRIED = 1;
        p = mt_abi_ptr(aTHX_ "File::Raw::JSON", "File::Raw::JSON::_abi_ptr");
        if (p) {
            const frj_abi *a = INT2PTR(const frj_abi *, p);
            if (a && a->abi_version >= FRJ_ABI_VERSION) MT_FRJ = a;
        }
    }
    return MT_FRJ;
}

static const jsf_abi *mt_jsf(pTHX) {
    if (!MT_JSF && !MT_JSF_TRIED) {
        UV p;
        MT_JSF_TRIED = 1;
        p = mt_abi_ptr(aTHX_ "JSON::Schema::Fast", "JSON::Schema::Fast::_abi_ptr");
        if (p) {
            const jsf_abi *a = INT2PTR(const jsf_abi *, p);
            if (a && a->abi_version >= JSF_ABI_VERSION) MT_JSF = a;
        }
    }
    return MT_JSF;
}

/* Crypt::JWS. Note the version field here is `version`, not `abi_version` as
 * the other two spell it - reading the wrong one gives a function pointer
 * table that looks new enough and is not. */
static const jws_abi *mt_jws(pTHX) {
    if (!MT_JWS && !MT_JWS_TRIED) {
        UV p;
        MT_JWS_TRIED = 1;
        p = mt_abi_ptr(aTHX_ "Crypt::JWS", "Crypt::JWS::_abi_ptr");
        if (p) {
            const jws_abi *a = INT2PTR(const jws_abi *, p);
            if (a && a->version >= 1) MT_JWS = a;
        }
    }
    return MT_JWS;
}

/* ---- the endpoint's slots ------------------------------------------------ */

typedef struct mt_mcp {
    SV *self;
    SV *gw;            /* the gateway a tool call re-enters; may be NULL */
    HV *byname;        /* tool name -> the tool                          */
    SV *list_bytes;    /* the frozen tools/list result, page zero        */
    AV *pages;         /* every frozen page, MT_MCP_TOOLS_PAGE tools each */
    SV *title;
    SV *instructions;  /* may be NULL                                    */
    SV *challenge;     /* the WWW-Authenticate value, built at compile   */
    SV *metadata;      /* the frozen RFC 9728 document                   */
    SV *resource;      /* this endpoint's canonical URI, the token's aud */
    SV *issuer;        /* the authorization server a token must claim    */
    IV  proxy;         /* this tenant, for a token's apip_proxy claim    */
} mt_mcp;

static int mt_mcp_load(pTHX_ SV *self, mt_mcp *m) {
    HV *h = MT_HV(self);
    SV **e;
    if (!h) return 0;
    Zero(m, 1, mt_mcp);
    m->self = self;
    if ((e = hv_fetchs(h, "gw", 0))           && *e && SvOK(*e)) m->gw = *e;
    if ((e = hv_fetchs(h, "byname", 0))       && *e) m->byname = MT_HV(*e);
    if ((e = hv_fetchs(h, "list_bytes", 0))   && *e && SvOK(*e)) m->list_bytes = *e;
    if ((e = hv_fetchs(h, "list_pages", 0))   && *e && SvROK(*e)) m->pages = MT_AV(*e);
    if ((e = hv_fetchs(h, "title", 0))        && *e && SvOK(*e)) m->title = *e;
    if ((e = hv_fetchs(h, "instructions", 0)) && *e && SvOK(*e)) m->instructions = *e;
    if ((e = hv_fetchs(h, "challenge", 0))    && *e && SvOK(*e)) m->challenge = *e;
    if ((e = hv_fetchs(h, "metadata", 0))     && *e && SvOK(*e)) m->metadata = *e;
    if ((e = hv_fetchs(h, "resource", 0))     && *e && SvOK(*e)) m->resource = *e;
    if ((e = hv_fetchs(h, "issuer", 0))       && *e && SvOK(*e)) m->issuer = *e;
    if ((e = hv_fetchs(h, "proxy", 0))        && *e && SvOK(*e)) m->proxy = SvIV(*e);
    return 1;
}

/* Included here rather than at the top because it authenticates against the
 * endpoint's own identity - the resource a token must be audienced for, the
 * issuer it must claim - and so needs mt_mcp above it. */
#include "mt_mcp_auth.h"

/* ---- responses ----------------------------------------------------------- */

static SV *mt_mcp_psgi(pTHX_ int status, const char *ctype, SV *body) {
    AV *trip = newAV(), *hdrs = newAV(), *b = newAV();
    if (ctype) {
        av_push(hdrs, newSVpvs("Content-Type"));
        av_push(hdrs, newSVpv(ctype, 0));
    }
    if (body) {
        av_push(hdrs, newSVpvs("Content-Length"));
        av_push(hdrs, newSViv((IV)SvCUR(body)));
        av_push(b, body);
    }
    av_push(trip, newSViv(status));
    av_push(trip, newRV_noinc((SV *)hdrs));
    av_push(trip, newRV_noinc((SV *)b));
    return newRV_noinc((SV *)trip);
}

/* A refusal with one extra header (Allow, on a 405). */
static SV *mt_mcp_bare(pTHX_ int status, const char *k, const char *v) {
    AV *trip = newAV(), *hdrs = newAV(), *b = newAV();
    if (k && v) { av_push(hdrs, newSVpv(k, 0)); av_push(hdrs, newSVpv(v, 0)); }
    av_push(trip, newSViv(status));
    av_push(trip, newRV_noinc((SV *)hdrs));
    av_push(trip, newRV_noinc((SV *)b));
    return newRV_noinc((SV *)trip);
}

/* Canonical bytes, like every other body this dist emits. */
static SV *mt_mcp_encode(pTHX_ SV *value) {
    const frj_abi *J = mt_frj(aTHX);
    frj_opts o;
    if (!J) return NULL;
    J->opts_init(&o);
    o.sort_keys = 1;
    return J->encode(aTHX_ value, &o);
}

/* ---- JSON-RPC ------------------------------------------------------------ */

static HV *mt_rpc_envelope(pTHX_ SV *id) {
    HV *r = newHV();
    (void)hv_stores(r, "jsonrpc", newSVpvs("2.0"));
    /* An id is ECHOED, never rebuilt: JSON-RPC allows a string or a number,
     * the client matches its replies by it, and Perl will happily hand back
     * 1 as "1" if anything interpolates it on the way. */
    (void)hv_stores(r, "id", id ? newSVsv(id) : newSV(0));
    return r;
}

static SV *mt_rpc_result(pTHX_ SV *id, SV *result) {
    HV *r = mt_rpc_envelope(aTHX_ id);
    (void)hv_stores(r, "result", result ? result : newRV_noinc((SV *)newHV()));
    return newRV_noinc((SV *)r);
}

static SV *mt_rpc_error(pTHX_ SV *id, int code, const char *msg, SV *data) {
    HV *r = mt_rpc_envelope(aTHX_ id);
    HV *e = newHV();
    (void)hv_stores(e, "code", newSViv(code));
    (void)hv_stores(e, "message", newSVpv(msg, 0));
    if (data) (void)hv_stores(e, "data", data);
    (void)hv_stores(r, "error", newRV_noinc((SV *)e));
    return newRV_noinc((SV *)r);
}

/* ---- percent encoding ---------------------------------------------------- */

/* Everything outside RFC 3986's unreserved set is escaped. Deliberately
 * conservative: the same routine serves a path segment and a query value, and
 * over-escaping is always safe where under-escaping is a smuggled delimiter. */
static void mt_mcp_pct(pTHX_ SV *out, const char *s, STRLEN len) {
    static const char hex[] = "0123456789ABCDEF";
    STRLEN i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~') {
            sv_catpvn(out, (const char *)&c, 1);
        }
        else {
            char b[3];
            b[0] = '%'; b[1] = hex[(c >> 4) & 0xF]; b[2] = hex[c & 0xF];
            sv_catpvn(out, b, 3);
        }
    }
}

/* A scalar as it should appear on the wire. A JSON boolean is a ref to a
 * scalar and must not stringify as SCALAR(0x...). */
static void mt_mcp_pct_sv(pTHX_ SV *out, SV *v) {
    STRLEN l;
    const char *p;
    if (!v || !SvOK(v)) return;
    if (SvROK(v)) {
        SV *rv = SvRV(v);
        if (SvTYPE(rv) < SVt_PVAV) {
            mt_mcp_pct(aTHX_ out, SvTRUE(rv) ? "true" : "false",
                       SvTRUE(rv) ? 4 : 5);
            return;
        }
        return;
    }
    p = SvPV_const(v, l);
    mt_mcp_pct(aTHX_ out, p, l);
}

/* ---- the tool call ------------------------------------------------------- */

/* The MCP-only ceiling: at most this many tool calls per key per
 * minute, across every tool.
 *
 * The per-operation limit the gateway already applies is not enough by
 * itself. It buckets by (key, operation), so an agent calling sixty
 * different cheap tools once each a second never trips any of them
 * while still making sixty calls a second. This is one bucket for the
 * key under a fixed name, so those sixty land in the same place.
 *
 * The limiter is the gateway's own - the same flock-arbitrated bucket
 * the API path uses - rather than a second mechanism that could
 * disagree with it. No limiter configured means no limit, which is the
 * stance the rest of the gateway takes. */
#define MT_MCP_CALLS_PER_MIN 300

static int mt_mcp_over_limit(pTHX_ mt_mcp *m, HV *env, IV *retry) {
    HV *gwh, *keyh;
    SV **e, *rl, *kid;
    IV limit = MT_MCP_CALLS_PER_MIN;
    int over = 0, count;
    dSP;

    if (!m->gw || !env) return 0;
    if (!(gwh = MT_HV(m->gw))) return 0;
    e = hv_fetchs(gwh, "ratelimit", 0);
    if (!e || !*e || !SvOK(*e)) return 0;
    rl = *e;

    /* The key the endpoint already matched. No key means no bucket to
     * charge: a tenant that publishes none is open, as the API path is. */
    e = hv_fetchs(env, "maat.key", 0);
    if (!e || !*e || !SvROK(*e) || !(keyh = MT_HV(*e))) return 0;
    e = hv_fetchs(keyh, "id", 0);
    if (!e || !*e || !SvOK(*e)) return 0;
    kid = *e;

    /* A key may carry its own ceiling; 0 there means unlimited, the same
     * reading rate_per_min has on the API path. */
    {
        SV **o = hv_fetchs(keyh, "mcp_calls_per_min", 0);
        if (o && *o && SvOK(*o)) {
            limit = SvIV(*o);
            if (limit <= 0) return 0;
        }
    }

    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 4);
    PUSHs(rl);
    PUSHs(sv_2mortal(newSVsv(kid)));
    PUSHs(sv_2mortal(newSVpvs("mcp")));
    PUSHs(sv_2mortal(newSViv(limit)));
    PUTBACK;
    /* G_ARRAY, not G_LIST: allow() answers with four values and G_LIST
     * is 5.36 and later. A limiter that dies fails OPEN, which is what
     * the API path does with the same call. */
    count = call_method("allow", G_ARRAY | G_EVAL);
    SPAGAIN;
    if (count >= 4 && !SvTRUE(ERRSV)) {
        SV *reset = POPs, *remaining = POPs, *lim = POPs, *ok = POPs;
        PERL_UNUSED_VAR(remaining);
        PERL_UNUSED_VAR(lim);
        if (!SvTRUE(ok)) {
            over = 1;
            if (retry) {
                IV r = SvIV(reset) - (IV)time(NULL);
                *retry = r > 0 ? r : 0;
            }
        }
        count -= 4;
    }
    while (count-- > 0) (void)POPs;
    PUTBACK; FREETMPS; LEAVE;
    return over;
}

/* The refusal a rate-limited agent sees. A tool result rather than a
 * protocol error, for the same reason a 4xx is: the call was well formed
 * and this IS its answer, and the model is the one that has to learn to
 * wait. Without retry_after it retries at once and an agent in a loop
 * turns one limited key into a busy loop. */
static SV *mt_mcp_limited(pTHX_ IV retry) {
    HV *out = newHV();
    AV *content = newAV();
    HV *block = newHV();
    HV *meta = newHV();

    (void)hv_stores(block, "type", newSVpvs("text"));
    (void)hv_stores(block, "text",
        newSVpvf("this tool has been called too many times in the last "
                 "minute; wait %" IVdf " seconds and try again", retry));
    av_push(content, newRV_noinc((SV *)block));
    (void)hv_stores(out, "content", newRV_noinc((SV *)content));
    (void)hv_stores(out, "isError", newSViv(1));
    (void)hv_stores(meta, "status", newSViv(429));
    (void)hv_stores(meta, "retry_after", newSViv(retry));
    (void)hv_stores(out, "_meta", newRV_noinc((SV *)meta));
    return newRV_noinc((SV *)out);
}

/* Build the request a tool call means, and hand it to mt_serve.
 *
 * `where` was resolved when the tenant compiled, so nothing here asks the
 * document anything: an argument's location is a hash lookup. */
static SV *mt_mcp_call(pTHX_ mt_mcp *m, HV *tool, HV *args, SV *env_rv) {
    HV *env = MT_HV(env_rv);
    HV *nenv;
    SV **e;
    HV *where = NULL;
    SV *path = NULL, *query = newSVpvs(""), *body = NULL;
    const char *method = "GET";
    STRLEN tl;
    const char *tp;
    STRLEN i;
    int nq = 0;

    if ((e = hv_fetchs(tool, "where", 0)) && *e) where = MT_HV(*e);
    if ((e = hv_fetchs(tool, "method", 0)) && *e && SvOK(*e))
        method = SvPV_nolen(*e);

    /* The path template, with {name} replaced by the argument's value. */
    e = hv_fetchs(tool, "path", 0);
    if (!e || !*e || !SvOK(*e)) { SvREFCNT_dec(query); return NULL; }
    tp = SvPV_const(*e, tl);
    path = newSVpvs("");
    for (i = 0; i < tl; i++) {
        if (tp[i] == '{') {
            STRLEN j = i + 1;
            while (j < tl && tp[j] != '}') j++;
            if (j < tl) {
                SV **a = hv_fetch(args, tp + i + 1, (I32)(j - i - 1), 0);
                if (a && *a) mt_mcp_pct_sv(aTHX_ path, *a);
                i = j;
                continue;
            }
        }
        sv_catpvn(path, tp + i, 1);
    }

    /* Query, header and cookie arguments, plus the body. */
    nenv = newHV();
    if (args) {
        HE *he;
        hv_iterinit(args);
        while ((he = hv_iternext(args))) {
            I32 kl;
            const char *k = hv_iterkey(he, &kl);
            SV *v = hv_iterval(args, he);
            SV **w;
            HV *wh;
            const char *in;

            if (kl == 4 && memEQ(k, "body", 4)) { body = v; continue; }
            if (!where) continue;
            w = hv_fetch(where, k, kl, 0);
            if (!w || !*w || !(wh = MT_HV(*w))) continue;
            {
                SV **iv = hv_fetchs(wh, "in", 0);
                SV **nv = hv_fetchs(wh, "name", 0);
                const char *nm = (nv && *nv && SvOK(*nv)) ? SvPV_nolen(*nv) : k;
                STRLEN nml = strlen(nm);
                if (!iv || !*iv || !SvOK(*iv)) continue;
                in = SvPV_nolen(*iv);

                if (strEQ(in, "query")) {
                    /* An array argument repeats the key, which is what the
                     * client half of this stack emits for the same value. */
                    if (SvROK(v) && SvTYPE(SvRV(v)) == SVt_PVAV) {
                        AV *av = (AV *)SvRV(v);
                        SSize_t n = av_len(av) + 1, x;
                        for (x = 0; x < n; x++) {
                            SV **el = av_fetch(av, x, 0);
                            if (nq++) sv_catpvs(query, "&");
                            mt_mcp_pct(aTHX_ query, nm, nml);
                            sv_catpvs(query, "=");
                            if (el && *el) mt_mcp_pct_sv(aTHX_ query, *el);
                        }
                    }
                    else {
                        if (nq++) sv_catpvs(query, "&");
                        mt_mcp_pct(aTHX_ query, nm, nml);
                        sv_catpvs(query, "=");
                        mt_mcp_pct_sv(aTHX_ query, v);
                    }
                }
                else if (strEQ(in, "header")) {
                    SV *hk = newSVpvs("HTTP_");
                    STRLEN x;
                    for (x = 0; x < nml; x++) {
                        char c = nm[x];
                        if (c == '-') c = '_';
                        else if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
                        sv_catpvn(hk, &c, 1);
                    }
                    (void)hv_store_ent(nenv, hk, newSVsv(v), 0);
                    SvREFCNT_dec(hk);
                }
                /* A cookie argument would have to be folded into the cookie
                 * header; no document in front of this has used one, and
                 * inventing the fold untested would be worse than saying so. */
            }
        }
    }

    /* The synthetic environment. Everything the gateway reads, carried over
     * from the real request so attribution survives: the agent's address, the
     * tenant's host, and the keys the endpoint already matched. */
    {
        static const char *const carry[] = {
            "HTTP_HOST", "REMOTE_ADDR", "REMOTE_PORT", "SERVER_NAME",
            "SERVER_PORT", "psgi.url_scheme", "psgi.errors", "psgi.version",
            "maat.keys", "maat.key", NULL
        };
        int c;
        for (c = 0; carry[c]; c++) {
            SV **s = hv_fetch(env, carry[c], (I32)strlen(carry[c]), 0);
            if (s && *s) (void)hv_store(nenv, carry[c], (I32)strlen(carry[c]),
                                        newSVsv(*s), 0);
        }
    }
    (void)hv_stores(nenv, "REQUEST_METHOD", newSVpv(method, 0));
    (void)hv_stores(nenv, "PATH_INFO", path);
    (void)hv_stores(nenv, "QUERY_STRING", query);
    (void)hv_stores(nenv, "SCRIPT_NAME", newSVpvs(""));
    /* So a violation, a log line and a rate-limit decision can all say this
     * came from a tool rather than from the customer's own client. */
    (void)hv_stores(nenv, "maat.mcp", newSVsv(&PL_sv_yes));
    /* And WHICH tool, so a violation attributes to the tool an agent
     * called rather than only to the operation. An owner asking "which
     * of my tools is the agent actually using, and which one is
     * drifting" is asking about this field. */
    {
        SV **nm = hv_fetchs(tool, "name", 0);
        if (nm && *nm && SvOK(*nm))
            (void)hv_stores(nenv, "maat.mcp.tool", newSVsv(*nm));
    }

    if (body) {
        SV *bytes = mt_mcp_encode(aTHX_ body);
        if (bytes) {
            HV *in = newHV();
            (void)hv_stores(nenv, "CONTENT_TYPE", newSVpvs("application/json"));
            (void)hv_stores(nenv, "CONTENT_LENGTH", newSViv((IV)SvCUR(bytes)));
            /* mt_serve reads a body through psgi.input, exactly as it does for
             * a real request, so a tool call has to hand it something that
             * reads. Maat::MCP::Input is that something: a few bytes and an
             * offset behind a read() XSUB, so a call still crosses into no
             * Perl at all. */
            (void)hv_stores(in, "bytes", bytes);      /* owned from here */
            (void)hv_stores(in, "pos", newSViv(0));
            (void)hv_stores(nenv, "psgi.input",
                sv_bless(newRV_noinc((SV *)in),
                         gv_stashpv("Maat::MCP::Input", GV_ADD)));
        }
    }

    return mt_serve(aTHX_ m->gw, sv_2mortal(newRV_noinc((SV *)nenv)));
}

/* A header name compared without regard to case, which is what a PSGI
 * responder is entitled to vary. `want` is lower case. */
static int mt_mcp_hdr_is(pTHX_ SV *k, const char *want, STRLEN wl) {
    STRLEN kl, i;
    const char *kp;
    if (!k || !SvOK(k)) return 0;
    kp = SvPV_const(k, kl);
    if (kl != wl) return 0;
    for (i = 0; i < wl; i++) {
        char c = kp[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != want[i]) return 0;
    }
    return 1;
}

/* One header's value off a PSGI header list, or NULL. */
static SV *mt_mcp_hdr(pTHX_ AV *hdr, const char *want, STRLEN wl) {
    SSize_t n, i;
    if (!hdr) return NULL;
    n = av_len(hdr) + 1;
    for (i = 0; i + 1 < n; i += 2) {
        SV **k = av_fetch(hdr, i, 0);
        SV **v = av_fetch(hdr, i + 1, 0);
        if (!k || !*k || !v || !*v) continue;
        if (mt_mcp_hdr_is(aTHX_ *k, want, wl)) return *v;
    }
    return NULL;
}

/* The gateway's answer, as a tool result. */
static SV *mt_mcp_result_of(pTHX_ SV *res) {
    AV *trip = MT_AV(res);
    HV *out = newHV();
    AV *content = newAV();
    HV *block = newHV();
    SV *text = newSVpvs("");
    IV status = 0;
    int truncated = 0;

    if (!trip) {
        /* A streaming responder. Draining one means driving a writer from
         * here, which is a piece of work with its own failure modes; until it
         * is done a tool says so rather than returning half a body. */
        (void)hv_stores(block, "type", newSVpvs("text"));
        (void)hv_stores(block, "text",
            newSVpvs("this operation streams its response, which a tool call "
                     "cannot carry yet"));
        av_push(content, newRV_noinc((SV *)block));
        (void)hv_stores(out, "content", newRV_noinc((SV *)content));
        (void)hv_stores(out, "isError", newSViv(1));
        SvREFCNT_dec(text);
        return newRV_noinc((SV *)out);
    }

    {
        SV **s = av_fetch(trip, 0, 0);
        status = (s && *s) ? SvIV(*s) : 0;
    }
    {
        SV **b = av_fetch(trip, 2, 0);
        AV *body = (b && *b) ? MT_AV(*b) : NULL;
        if (body) {
            SSize_t n = av_len(body) + 1, i;
            for (i = 0; i < n; i++) {
                SV **c = av_fetch(body, i, 0);
                if (c && *c && SvOK(*c)) sv_catsv(text, *c);
                if (SvCUR(text) > MT_MCP_RESULT_MAX) break;
            }
        }
    }
    if (SvCUR(text) > MT_MCP_RESULT_MAX) {
        SvCUR_set(text, MT_MCP_RESULT_MAX);
        sv_catpvs(text, "\n... truncated");
        truncated = 1;
    }

    (void)hv_stores(block, "type", newSVpvs("text"));
    (void)hv_stores(block, "text", text);
    av_push(content, newRV_noinc((SV *)block));
    (void)hv_stores(out, "content", newRV_noinc((SV *)content));
    /* A 4xx or 5xx is the TOOL failing, not the protocol: the call was
     * well formed and got an answer, and the model is the one who needs to
     * know what the answer was. */
    (void)hv_stores(out, "isError", newSViv(status >= 400 ? 1 : 0));
    {
        HV *meta = newHV();
        (void)hv_stores(meta, "status", newSViv(status));
        if (truncated) (void)hv_stores(meta, "truncated", newSViv(1));
        /* A rate-limited call tells the model HOW LONG to wait. Without
         * it a model retries immediately, and an agent in a loop turns
         * one limited key into a busy loop against the limiter. The
         * value is the gateway's own Retry-After, not a second guess at
         * it. */
        if (status == 429) {
            SV *ra = mt_mcp_hdr(aTHX_
                (av_fetch(trip, 1, 0) && *av_fetch(trip, 1, 0))
                    ? MT_AV(*av_fetch(trip, 1, 0)) : NULL,
                "retry-after", 11);
            if (ra && SvOK(ra))
                (void)hv_stores(meta, "retry_after", newSViv(SvIV(ra)));
        }
        (void)hv_stores(out, "_meta", newRV_noinc((SV *)meta));
    }
    return newRV_noinc((SV *)out);
}

/* ---- method dispatch ----------------------------------------------------- */

/* Answer one JSON-RPC request. NULL for a notification (nothing is owed). */
static SV *mt_mcp_dispatch(pTHX_ mt_mcp *m, const char *method, STRLEN mlen,
                           SV *id, SV *params, SV *env_rv, int *served_frozen)
{
    HV *p = (params && SvROK(params)) ? MT_HV(params) : NULL;

    if (mlen == 10 && memEQ(method, "initialize", 10)) {
        HV *r = newHV(), *caps = newHV(), *tools = newHV(), *info = newHV();
        const char *proto = MT_MCP_PROTO_CURRENT;
        if (p) {
            SV **v = hv_fetchs(p, "protocolVersion", 0);
            if (v && *v && SvOK(*v)) {
                STRLEN l; const char *s = SvPV_const(*v, l);
                if (l == sizeof(MT_MCP_PROTO_PRIOR) - 1
                    && memEQ(s, MT_MCP_PROTO_PRIOR, l))
                    proto = MT_MCP_PROTO_PRIOR;
            }
        }
        (void)hv_stores(tools, "listChanged", newSViv(0));
        (void)hv_stores(caps, "tools", newRV_noinc((SV *)tools));
        (void)hv_stores(info, "name", newSVpvs("apip"));
        if (m->title) (void)hv_stores(info, "title", newSVsv(m->title));
        (void)hv_stores(info, "version", newSVpvs("0.06"));
        (void)hv_stores(r, "protocolVersion", newSVpv(proto, 0));
        (void)hv_stores(r, "capabilities", newRV_noinc((SV *)caps));
        (void)hv_stores(r, "serverInfo", newRV_noinc((SV *)info));
        if (m->instructions)
            (void)hv_stores(r, "instructions", newSVsv(m->instructions));
        return mt_rpc_result(aTHX_ id, newRV_noinc((SV *)r));
    }

    if (mlen == 4 && memEQ(method, "ping", 4))
        return mt_rpc_result(aTHX_ id, NULL);

    if (mlen == 10 && memEQ(method, "tools/list", 10)) {
        /* The frozen bytes are spliced into the envelope rather than decoded
         * and re-encoded: freezing them is the whole point, and a list that
         * was walked per request would not be frozen at all. Canonical order
         * puts id before jsonrpc before result. */
        SV *page = m->list_bytes;

        /* A cursor selects one of those frozen pages. It is this server's
         * own opaque token, so the only cursor that can be valid is one
         * this server issued - anything else is a client inventing state,
         * and saying so beats guessing a page and quietly returning the
         * wrong tools. */
        if (m->pages) {
            SV **cv = p ? hv_fetchs(p, "cursor", 0) : NULL;
            IV idx = 0;
            if (cv && *cv && SvOK(*cv)) {
                STRLEN cl, x;
                const char *cp = SvPV_const(*cv, cl);
                if (!cl)
                    return mt_rpc_error(aTHX_ id, MT_RPC_PARAMS,
                                        "invalid cursor", NULL);
                for (x = 0; x < cl; x++)
                    if (cp[x] < '0' || cp[x] > '9')
                        return mt_rpc_error(aTHX_ id, MT_RPC_PARAMS,
                                            "invalid cursor", NULL);
                idx = SvIV(*cv);
            }
            if (idx < 0 || idx > av_len(m->pages))
                return mt_rpc_error(aTHX_ id, MT_RPC_PARAMS,
                                    "invalid cursor", NULL);
            {
                SV **pv = av_fetch(m->pages, (SSize_t)idx, 0);
                if (pv && *pv) page = *pv;
            }
        }

        if (page) {
            SV *idb = mt_mcp_encode(aTHX_ id ? id : &PL_sv_undef);
            SV *out = newSVpvs("{\"id\":");
            if (idb) { sv_catsv(out, idb); SvREFCNT_dec(idb); }
            else sv_catpvs(out, "null");
            sv_catpvs(out, ",\"jsonrpc\":\"2.0\",\"result\":");
            sv_catsv(out, page);
            sv_catpvs(out, "}");
            *served_frozen = 1;
            return out;                      /* already bytes */
        }
        return mt_rpc_error(aTHX_ id, MT_RPC_INTERNAL, "no tools", NULL);
    }

    if (mlen == 10 && memEQ(method, "tools/call", 10)) {
        SV **nv = p ? hv_fetchs(p, "name", 0) : NULL;
        SV **av_ = p ? hv_fetchs(p, "arguments", 0) : NULL;
        HV *tool;
        HV *args;
        SV *res;

        if (!nv || !*nv || !SvOK(*nv))
            return mt_rpc_error(aTHX_ id, MT_RPC_PARAMS, "a tool name is required", NULL);
        {
            STRLEN nl; const char *nm = SvPV_const(*nv, nl);
            SV **t = m->byname ? hv_fetch(m->byname, nm, (I32)nl, 0) : NULL;
            if (!t || !*t || !(tool = MT_HV(*t)))
                return mt_rpc_error(aTHX_ id, MT_RPC_PARAMS, "unknown tool", NULL);
        }
        args = (av_ && *av_ && SvROK(*av_)) ? MT_HV(*av_) : newHV();
        if (!args) args = newHV();

        /* Validated here, before anything is built from it, so a model gets a
         * protocol error it can act on rather than a 400 from an API whose
         * document it cannot see. */
        {
            const jsf_abi *J = mt_jsf(aTHX);
            SV **cv = hv_fetchs(tool, "validator", 0);
            if (J && cv && *cv && SvOK(*cv)) {
                AV *errs = newAV();
                SV *data = sv_2mortal(newRV_noinc((SV *)errs));
                SV *argref = sv_2mortal(newRV_inc((SV *)args));
                if (!J->validate(aTHX_ *cv, argref, errs)) {
                    HV *d = newHV();
                    (void)hv_stores(d, "errors", SvREFCNT_inc_simple_NN(data));
                    return mt_rpc_error(aTHX_ id, MT_RPC_PARAMS,
                                        "invalid arguments",
                                        newRV_noinc((SV *)d));
                }
            }
        }

        if (!m->gw)
            return mt_rpc_error(aTHX_ id, MT_RPC_INTERNAL,
                                "this tenant has no upstream to call", NULL);

        {
            IV retry = 0;
            if (mt_mcp_over_limit(aTHX_ m, MT_HV(env_rv), &retry))
                return mt_rpc_result(aTHX_ id, mt_mcp_limited(aTHX_ retry));
        }

        res = mt_mcp_call(aTHX_ m, tool, args, env_rv);
        if (!res)
            return mt_rpc_error(aTHX_ id, MT_RPC_INTERNAL,
                                "the call could not be built", NULL);
        {
            SV *out = mt_mcp_result_of(aTHX_ res);
            SvREFCNT_dec(res);
            /* A delivered tool result, counted on the tenant's own
             * counters beside `request` - which mt_serve already moved
             * for the synthetic call, because a tool call IS a request
             * and is billed as one. This is the visibility split: how
             * much of an hour an agent asked for.
             *
             * Only here. tools/list, initialize and ping do not reach
             * this line, and must not: a client lists the tools on every
             * session it opens, and metering that would bill a customer
             * for an agent connecting. */
            {
                mt_gw g;
                if (m->gw && mt_load(aTHX_ m->gw, &g) && g.counters)
                    MT_COUNT(g.counters, "mcp");
            }
            return mt_rpc_result(aTHX_ id, out);
        }
    }

    return mt_rpc_error(aTHX_ id, MT_RPC_METHOD, "method not found", NULL);
}

/* ---- the request --------------------------------------------------------- */

static SV *mt_mcp_serve(pTHX_ SV *self, SV *env_rv) {
    mt_mcp m;
    HV *env = MT_HV(env_rv);
    SV *v;
    const char *pm;
    STRLEN pl;
    IV clen = 0;
    SV *bytes = NULL;
    SV *doc = NULL;
    const frj_abi *J;

    if (!env || !mt_mcp_load(aTHX_ self, &m))
        return mt_mcp_bare(aTHX_ 500, NULL, NULL);

    /* DNS rebinding: a browser sends Origin, an agent does not. Anything
     * cross-origin is refused before a byte is read. */
    v = MT_ENV(env, "HTTP_ORIGIN");
    if (v && SvOK(v) && SvCUR(v)) return mt_mcp_bare(aTHX_ 403, NULL, NULL);

    v = MT_ENV(env, "PATH_INFO");
    if (v && SvOK(v)) {
        const char *p = SvPV_const(v, pl);

        if (pl == sizeof(MT_MCP_METADATA_PATH) - 1
            && memEQ(p, MT_MCP_METADATA_PATH, pl)) {
            /* Public by design, and deliberately not behind the check below:
             * this document is what tells a client how to authenticate, so
             * requiring authentication to read it would be a loop. It is
             * served by a keys-only tenant too, because saying which
             * authorization servers exist - none, for that tenant - is the
             * answer a client needs in order to stop looking. */
            SV *mv = MT_ENV(env, "REQUEST_METHOD");
            const char *mm = (mv && SvOK(mv)) ? SvPV_nolen(mv) : "GET";
            if (!strEQ(mm, "GET") && !strEQ(mm, "HEAD"))
                return mt_mcp_bare(aTHX_ 405, "Allow", "GET");
            if (!m.metadata) return mt_mcp_bare(aTHX_ 404, NULL, NULL);
            return mt_mcp_psgi(aTHX_ 200, "application/json",
                               newSVsv(m.metadata));
        }

        if (pl != 4 || memNE(p, "/mcp", 4))
            return mt_mcp_bare(aTHX_ 404, NULL, NULL);
    }

    v = MT_ENV(env, "REQUEST_METHOD");
    pm = (v && SvOK(v)) ? SvPV_nolen(v) : "GET";
    if (!strEQ(pm, "POST")) {
        /* GET would open a server-initiated stream and DELETE would end a
         * session; this endpoint is stateless and answers in one response, so
         * both are honestly refused rather than half-implemented. */
        return mt_mcp_bare(aTHX_ 405, "Allow", "POST");
    }

    v = MT_ENV(env, "HTTP_ACCEPT");
    if (v && SvOK(v) && SvCUR(v)) {
        const char *a = SvPV_nolen(v);
        if (!strstr(a, "application/json") && !strstr(a, "*/*"))
            return mt_mcp_bare(aTHX_ 406, NULL, NULL);
    }

    v = MT_ENV(env, "HTTP_MCP_PROTOCOL_VERSION");
    if (v && SvOK(v) && SvCUR(v)) {
        const char *s = SvPV_nolen(v);
        if (!strEQ(s, MT_MCP_PROTO_CURRENT) && !strEQ(s, MT_MCP_PROTO_PRIOR))
            return mt_mcp_bare(aTHX_ 400, NULL, NULL);
    }

    /* Who is calling, decided before the envelope is read: an unauthenticated
     * request costs one hash and nothing else, and never reaches the parser.
     *
     * The matched key goes on the REAL environment here, and mt_mcp_call
     * carries it onto the synthetic one, which is what lets a tool call be
     * rate limited and metered per key exactly as the caller's own requests
     * are. Nothing off the wire can forge it: this is the only writer. */
    {
        SV *key = NULL;
        int a = mt_mcp_authenticate(aTHX_ &m, env, &key);

        if (a == MT_AUTH_NONE || a == MT_AUTH_BAD)
            return mt_mcp_bare(aTHX_ 401, "WWW-Authenticate",
                               (m.challenge && SvOK(m.challenge))
                                   ? SvPV_nolen(m.challenge)
                                   : "Bearer realm=\"" MT_MCP_REALM "\"");

        /* Authenticated, but this key was not issued for agents. */
        if (a == MT_AUTH_SCOPE)
            return mt_mcp_bare(aTHX_ 403, NULL, NULL);

        if (key) (void)hv_stores(env, "maat.key", newSVsv(key));
    }

    v = MT_ENV(env, "CONTENT_LENGTH");
    clen = (v && SvOK(v)) ? SvIV(v) : 0;
    if (clen > MT_MCP_BODY_MAX) return mt_mcp_bare(aTHX_ 413, NULL, NULL);

    J = mt_frj(aTHX);
    if (!J) return mt_mcp_bare(aTHX_ 500, NULL, NULL);

    if (clen > 0) {
        SV *args[2];
        args[0] = env_rv;
        args[1] = sv_2mortal(newSViv(clen));
        bytes = mt_call_perl(aTHX_ "Maat::Gateway::_slurp_input", args, 2);
        if (bytes) sv_2mortal(bytes);
    }

    if (bytes && SvOK(bytes) && SvCUR(bytes)) {
        /* A malformed envelope is a -32700, not an exception: the client is
         * owed an answer it can parse. These bytes are attacker-controlled,
         * so the decoder croaking is NORMAL operation here, not an edge.
         *
         * Which is why this goes through the XSUB under G_EVAL and not
         * through the ABI's decode pointer. Trapping a croak out of plain C
         * with JMPENV_PUSH catches the jump but restores none of the state
         * the croak abandoned - the value stack, the mark stack, the scope
         * and save stacks, the tmps floor. The endpoint then answers
         * correctly and the interpreter dies later and elsewhere, in a loop
         * some caller owns ("panic: pp_iter, type=0"), which is how this was
         * found. Only a real G_EVAL call frame unwinds all of that. Same
         * parser underneath; the cost is one XSUB dispatch per MCP request,
         * on a path that already makes one to slurp the body. */
        SV *dargs[1];
        dargs[0] = bytes;
        doc = mt_call_perl(aTHX_ "File::Raw::JSON::file_json_decode", dargs, 1);
    }

    if (!doc) {
        SV *err = mt_rpc_error(aTHX_ NULL, MT_RPC_PARSE, "parse error", NULL);
        SV *out = mt_mcp_encode(aTHX_ err);
        SvREFCNT_dec(err);
        return mt_mcp_psgi(aTHX_ 400, "application/json",
                           out ? out : newSVpvs("{}"));
    }
    sv_2mortal(doc);

    /* One message. A 2025-03-26 batch is an array; this version of the
     * protocol removed them, and a client that still sends one is told so
     * rather than served half. */
    if (SvROK(doc) && SvTYPE(SvRV(doc)) == SVt_PVAV) {
        SV *err = mt_rpc_error(aTHX_ NULL, MT_RPC_REQUEST,
                               "batches are not supported", NULL);
        SV *out = mt_mcp_encode(aTHX_ err);
        SvREFCNT_dec(err);
        return mt_mcp_psgi(aTHX_ 400, "application/json",
                           out ? out : newSVpvs("{}"));
    }

    {
        HV *msg = SvROK(doc) ? MT_HV(doc) : NULL;
        SV **jv = msg ? hv_fetchs(msg, "jsonrpc", 0) : NULL;
        SV **mv = msg ? hv_fetchs(msg, "method", 0) : NULL;
        SV **iv = msg ? hv_fetchs(msg, "id", 0) : NULL;
        SV **pv = msg ? hv_fetchs(msg, "params", 0) : NULL;
        SV *id  = (iv && *iv) ? *iv : NULL;
        int frozen = 0;
        SV *reply, *out;

        if (!msg || !jv || !*jv || !SvOK(*jv) || !strEQ(SvPV_nolen(*jv), "2.0")) {
            SV *err = mt_rpc_error(aTHX_ id, MT_RPC_REQUEST,
                                   "invalid request", NULL);
            out = mt_mcp_encode(aTHX_ err);
            SvREFCNT_dec(err);
            return mt_mcp_psgi(aTHX_ 400, "application/json",
                               out ? out : newSVpvs("{}"));
        }

        /* No method, or no id: a response or a notification. Both are
         * accepted and nothing is owed back. */
        if (!mv || !*mv || !SvOK(*mv) || !iv)
            return mt_mcp_bare(aTHX_ 202, NULL, NULL);

        {
            STRLEN ml;
            const char *mname = SvPV_const(*mv, ml);
            reply = mt_mcp_dispatch(aTHX_ &m, mname, ml, id,
                                    (pv && *pv) ? *pv : NULL, env_rv, &frozen);
        }
        if (!reply) return mt_mcp_bare(aTHX_ 202, NULL, NULL);
        if (frozen) return mt_mcp_psgi(aTHX_ 200, "application/json", reply);

        out = mt_mcp_encode(aTHX_ reply);
        SvREFCNT_dec(reply);
        return mt_mcp_psgi(aTHX_ 200, "application/json",
                           out ? out : newSVpvs("{}"));
    }
}

#endif /* MT_MCP_H */
