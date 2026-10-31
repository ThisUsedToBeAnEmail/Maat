/*
 * Maat.xs - the request path, in one C function.
 *
 * The Perl version of this was not slow because any one line was slow.
 * Measured per request: the counters were 0.09us each, the three eval
 * blocks 0.04us together, the uuid 0.035us - and the whole path was
 * 5.5us. The cost was the shape, not the lines: a dozen Perl ops and
 * four Perl<->XS crossings for work that is a handful of hash fetches
 * and two calls.
 *
 * So this is deliberately one function rather than a set of helpers.
 * mt_serve does the id, the counters, the routing, the validation, the
 * forward and the header stamp without unwinding into Perl except where
 * it must: Open::API's router and validator, Reverse::Proxy's forward,
 * and - only when a request has actually violated its contract - the
 * Perl recorder and problem+json builder. Those are call_sv, and the
 * rare ones are on the rare path.
 *
 * WHAT MAY NOT CHANGE
 *
 * Fail-open. Every call out of here is G_EVAL and every failure lands in
 * the same place: count it and forward. t/05-chaos.t is the contract -
 * six injection points, both modes, ninety assertions - and it is the
 * reason this file is written the way it is rather than the shortest
 * way. The chaos points are implemented HERE, not left in Perl, because
 * a fail-open path that is only exercised through a Perl wrapper is not
 * the path that runs in production.
 */

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "mt_compat.h"
#include "mt_env.h"
#include "mt_chaos.h"
#include "mt_serve.h"
#include "mt_mcp.h"      /* the MCP endpoint; needs mt_serve for a tool call */
#include "mt_mcp_tools.h"/* the tools a document offers, derived at compile   */
#include "mt_mcp_build.h"/* and the endpoint they hang on                     */
#include "mt_fleet.h"
#include "mt_dispatch.h"

/* The table pointer out of a blessed Maat::Fleet::Table. NULL for
 * anything else, including one already DESTROYed - the accessors below
 * all probe rather than croak, because this is a cache and a cache that
 * dies is worse than no cache. */
#define MT_TABLE(sv) \
    (((sv) && SvROK(sv) && SvIOK(SvRV(sv)) && SvIVX(SvRV(sv))) \
        ? INT2PTR(mt_fleet *, SvIVX(SvRV(sv))) : NULL)

MODULE = Maat        PACKAGE = Maat::Gateway

PROTOTYPES: DISABLE

# The PSGI application. $self is the gateway; the closure to_app returns
# calls straight into this with the environment.
SV *
_serve(self, env)
        SV *self
        SV *env
    CODE:
        RETVAL = mt_serve(aTHX_ self, env);
    OUTPUT:
        RETVAL

# Parse a MAAT_CHAOS specification into the hash the request path reads.
# Perl-visible so the tests can drive it directly.
SV *
_chaos_parse(spec)
        SV *spec
    CODE:
        RETVAL = mt_chaos_parse(aTHX_ spec);
    OUTPUT:
        RETVAL

MODULE = Maat        PACKAGE = Maat

PROTOTYPES: DISABLE

# Increment one counter. The counters stay an ordinary Perl hash so
# $gw->counters keeps working; this only avoids the method call and the
# two hash lookups per count.
void
_count(counters, name, n = 1)
        SV *counters
        SV *name
        IV n
    CODE:
        mt_count(aTHX_ counters, name, n);

MODULE = Maat        PACKAGE = Maat::MCP::Tools

# The tools a proxied document offers an agent, derived once from the same
# compiled Open::API the gateway enforces. Ordered by operationId, because a
# decoded JSON object has no order and a frozen list built on hash order would
# differ between workers - names included, since the collision suffixes are
# handed out as the walk goes.
SV *
new(class, ...)
        SV *class
    PREINIT:
        SV *api = NULL;
        HV *cfg = NULL;
        HV *self;
        I32 i;
    CODE:
        for (i = 1; i + 1 < items; i += 2) {
            const char *k = SvPV_nolen(ST(i));
            if (strEQ(k, "api")) api = ST(i + 1);
            else if (strEQ(k, "mcp")) cfg = MT_HV(ST(i + 1));
        }
        if (!api || !SvOK(api))
            croak("Maat::MCP::Tools: an api is required");
        self = mt_tools_build(aTHX_ api, cfg);
        RETVAL = sv_bless(newRV_noinc((SV *)self),
                          gv_stashpv("Maat::MCP::Tools", GV_ADD));
    OUTPUT:
        RETVAL

SV *
tools(self)
        SV *self
    PREINIT:
        HV *h;
        SV **v;
    CODE:
        h = MT_HV(self);
        v = h ? hv_fetchs(h, "tools", 0) : NULL;
        RETVAL = (v && *v) ? newSVsv(*v) : newRV_noinc((SV *)newAV());
    OUTPUT:
        RETVAL

SV *
tool(self, name)
        SV *self
        SV *name
    PREINIT:
        HV *h, *by;
        SV **v;
        STRLEN nl;
        const char *nm;
    CODE:
        h  = MT_HV(self);
        v  = h ? hv_fetchs(h, "byname", 0) : NULL;
        by = (v && *v) ? MT_HV(*v) : NULL;
        nm = SvOK(name) ? SvPV_const(name, nl) : "";
        if (!SvOK(name)) nl = 0;
        v  = by ? hv_fetch(by, nm, (I32)nl, 0) : NULL;
        RETVAL = (v && *v) ? newSVsv(*v) : newSV(0);
    OUTPUT:
        RETVAL

SV *
names(self)
        SV *self
    PREINIT:
        HV *h;
        SV **v;
        AV *out, *tools;
        SSize_t n, i;
    CODE:
        out = newAV();
        h = MT_HV(self);
        v = h ? hv_fetchs(h, "tools", 0) : NULL;
        tools = (v && *v) ? MT_AV(*v) : NULL;
        n = tools ? av_len(tools) + 1 : 0;
        for (i = 0; i < n; i++) {
            SV **e = av_fetch(tools, i, 0);
            HV *th = (e && *e) ? MT_HV(*e) : NULL;
            SV **nv = th ? hv_fetchs(th, "name", 0) : NULL;
            if (nv && *nv) av_push(out, newSVsv(*nv));
        }
        RETVAL = newRV_noinc((SV *)out);
    OUTPUT:
        RETVAL

IV
count(self)
        SV *self
    PREINIT:
        HV *h;
        SV **v;
        AV *tools;
    CODE:
        h = MT_HV(self);
        v = h ? hv_fetchs(h, "tools", 0) : NULL;
        tools = (v && *v) ? MT_AV(*v) : NULL;
        RETVAL = tools ? (IV)(av_len(tools) + 1) : 0;
    OUTPUT:
        RETVAL

IV
builds(self)
        SV *self
    PREINIT:
        HV *h;
        SV **v;
    CODE:
        h = MT_HV(self);
        v = h ? hv_fetchs(h, "builds", 0) : NULL;
        RETVAL = (v && *v) ? SvIV(*v) : 0;
    OUTPUT:
        RETVAL

# The frozen tools/list result. Built on first ask and cached: reading it
# must never be build work, which is what `builds` staying at 1 asserts.
SV *
list_bytes(self)
        SV *self
    PREINIT:
        HV *h;
    CODE:
        h = MT_HV(self);
        RETVAL = h ? newSVsv(mt_tools_list_bytes(aTHX_ h)) : newSVpvs("");
    OUTPUT:
        RETVAL

MODULE = Maat        PACKAGE = Maat::MCP

# The endpoint a tenant serves at /mcp. Built once, here; served from C.
SV *
new(class, ...)
        SV *class
    PREINIT:
        SV *api = NULL, *gw = NULL, *host = NULL, *version = NULL;
        SV *proxy = NULL;
        HV *cfg = NULL;
        HV *self;
        I32 i;
    CODE:
        for (i = 1; i + 1 < items; i += 2) {
            const char *k = SvPV_nolen(ST(i));
            if      (strEQ(k, "api"))     api     = ST(i + 1);
            else if (strEQ(k, "gw"))      gw      = ST(i + 1);
            else if (strEQ(k, "host"))    host    = ST(i + 1);
            else if (strEQ(k, "version")) version = ST(i + 1);
            else if (strEQ(k, "proxy"))   proxy   = ST(i + 1);
            else if (strEQ(k, "mcp"))     cfg     = MT_HV(ST(i + 1));
        }
        if (!api || !SvOK(api)) croak("Maat::MCP: an api is required");
        self = mt_mcp_new(aTHX_ api, gw, host, version, cfg);
        if (proxy && SvOK(proxy))
            (void)hv_stores(self, "proxy", newSViv(SvIV(proxy)));
        RETVAL = sv_bless(newRV_noinc((SV *)self),
                          gv_stashpv("Maat::MCP", GV_ADD));
    OUTPUT:
        RETVAL

SV *
tools(self)
        SV *self
    PREINIT:
        HV *h;
        SV **v;
    CODE:
        h = MT_HV(self);
        v = h ? hv_fetchs(h, "tools", 0) : NULL;
        RETVAL = (v && *v) ? newSVsv(*v) : newSV(0);
    OUTPUT:
        RETVAL

SV *
tool(self, name)
        SV *self
        SV *name
    PREINIT:
        HV *h, *by;
        SV **v;
        STRLEN nl;
        const char *nm;
    CODE:
        h  = MT_HV(self);
        v  = h ? hv_fetchs(h, "byname", 0) : NULL;
        by = (v && *v) ? MT_HV(*v) : NULL;
        nm = SvOK(name) ? SvPV_const(name, nl) : "";
        if (!SvOK(name)) nl = 0;
        v  = by ? hv_fetch(by, nm, (I32)nl, 0) : NULL;
        RETVAL = (v && *v) ? newSVsv(*v) : newSV(0);
    OUTPUT:
        RETVAL

SV *
list_bytes(self)
        SV *self
    PREINIT:
        HV *h;
        SV **v;
    CODE:
        h = MT_HV(self);
        v = h ? hv_fetchs(h, "list_bytes", 0) : NULL;
        RETVAL = (v && *v) ? newSVsv(*v) : newSVpvs("");
    OUTPUT:
        RETVAL

# The MCP endpoint's request path. Maat::Registry closes over this when it
# builds a tenant, the way it closes over the gateway's own app: the build is
# above, the request is C, and a tool call re-enters mt_serve with no Perl
# frame between the agent and the upstream.
SV *
_serve(self, env)
        SV *self
        SV *env
    CODE:
        RETVAL = mt_mcp_serve(aTHX_ self, env);
    OUTPUT:
        RETVAL

MODULE = Maat        PACKAGE = Maat::MCP::Input

# psgi.input for a tool call's synthetic request: bytes and an offset behind
# the one method mt_serve asks of a body. It exists so a tool call crosses
# into no Perl at all - the gateway reads its body exactly as it would a
# client's, and never learns the difference.
IV
read(self, buf, len, ...)
        SV *self
        SV *buf
        IV len
    PREINIT:
        HV *h;
        SV **bv, **pv;
        STRLEN blen;
        const char *bp;
        IV pos, n;
    CODE:
        h  = MT_HV(self);
        bv = h ? hv_fetchs(h, "bytes", 0) : NULL;
        pv = h ? hv_fetchs(h, "pos", 0) : NULL;
        if (!bv || !*bv || !pv || !*pv) { sv_setpvn(buf, "", 0); XSRETURN_IV(0); }
        bp  = SvPV_const(*bv, blen);
        pos = SvIV(*pv);
        if (pos < 0 || (STRLEN)pos >= blen) { sv_setpvn(buf, "", 0); XSRETURN_IV(0); }
        n = (IV)blen - pos;
        if (len > 0 && n > len) n = len;
        sv_setpvn(buf, bp + pos, (STRLEN)n);
        sv_setiv(*pv, pos + n);
        RETVAL = n;
    OUTPUT:
        RETVAL

void
close(self)
        SV *self
    CODE:
        PERL_UNUSED_VAR(self);

MODULE = Maat        PACKAGE = Maat::Fleet::Table

PROTOTYPES: DISABLE

# The C tenant table (phase 12b). Maat::Registry publishes into it when
# it compiles or drops a tenant; the phase-12c dispatcher reads it per
# request without touching an SV. Everything here is derivable from the
# registry's own state, so a table that is never wired, or a publish
# that fails, costs speed and nothing else - see mt_fleet.h.

SV *
new(class)
        SV *class
    PREINIT:
        mt_fleet *f;
    CODE:
        PERL_UNUSED_VAR(class);
        f = mt_fleet_new(aTHX);
        RETVAL = sv_bless(newRV_noinc(newSViv(PTR2IV(f))),
                          gv_stashpv("Maat::Fleet::Table", GV_ADD));
    OUTPUT:
        RETVAL

# publish($host, \%entry) - the entry hash names what the dispatcher
# needs: app (required), gw, version, keys, proxy, expires, max_body,
# max_header_bytes, concurrency, portal, poison. Returns true when the
# host is now in the table.
IV
publish(self, host, spec)
        SV *self
        SV *host
        SV *spec
    PREINIT:
        mt_fleet *f;
        HV *h;
        SV **s;
        SV *gw = NULL, *app = NULL, *version = NULL, *keys = NULL;
        IV proxy = 0, expires = 0;
        SV *mcp = NULL;
        IV max_body = 0, max_header = 0, conc = 0;
        U32 flags = 0;
        STRLEN hlen;
        const char *hp;
    CODE:
        f = MT_TABLE(self);
        h = MT_HV(spec);
        if (!f || !h || !SvOK(host)) XSRETURN_IV(0);

        if ((s = hv_fetchs(h, "app", 0))     && *s && SvOK(*s)) app     = *s;
        if ((s = hv_fetchs(h, "gw", 0))      && *s && SvOK(*s)) gw      = *s;
        if ((s = hv_fetchs(h, "version", 0)) && *s && SvOK(*s)) version = *s;
        if ((s = hv_fetchs(h, "keys", 0))    && *s && MT_AV(*s)) keys   = *s;
        if ((s = hv_fetchs(h, "mcp", 0))     && *s && SvOK(*s)) mcp     = *s;
        if ((s = hv_fetchs(h, "proxy", 0))   && *s && SvOK(*s)) proxy   = SvIV(*s);
        if ((s = hv_fetchs(h, "expires", 0)) && *s && SvOK(*s)) expires = SvIV(*s);
        if ((s = hv_fetchs(h, "max_body", 0)) && *s && SvOK(*s))
            max_body = SvIV(*s);
        if ((s = hv_fetchs(h, "max_header_bytes", 0)) && *s && SvOK(*s))
            max_header = SvIV(*s);
        if ((s = hv_fetchs(h, "concurrency", 0)) && *s && SvOK(*s))
            conc = SvIV(*s);
        if ((s = hv_fetchs(h, "portal", 0)) && *s && SvTRUE(*s))
            flags |= MT_E_PORTAL;
        if ((s = hv_fetchs(h, "poison", 0)) && *s && SvTRUE(*s))
            flags |= MT_E_POISON;
        if (gw)  flags |= MT_E_DIRECT;
        if (mcp) flags |= MT_E_MCP;

        if (!app) XSRETURN_IV(0);
        hp = SvPV(host, hlen);
        RETVAL = mt_fleet_publish(aTHX_ f, hp, hlen, gw, app, mcp, version, keys,
                                  proxy, expires, max_body, max_header,
                                  conc, flags) ? 1 : 0;
    OUTPUT:
        RETVAL

# refresh($host, \%fields) - the terms of a tenant that changed without
# its spec changing: keys, caps, expiry. In place, so an in-flight
# request keeps the entry it started with. See mt_fleet.h.
IV
refresh(self, host, spec)
        SV *self
        SV *host
        SV *spec
    PREINIT:
        mt_fleet *f;
        HV *h;
        SV **s;
        SV *keys = NULL;
        IV expires = 0, max_body = 0, max_header = 0, conc = 0;
        STRLEN hlen;
        const char *hp;
    CODE:
        f = MT_TABLE(self);
        h = MT_HV(spec);
        if (!f || !h || !SvOK(host)) XSRETURN_IV(0);
        if ((s = hv_fetchs(h, "keys", 0))    && *s && MT_AV(*s)) keys = *s;
        if ((s = hv_fetchs(h, "expires", 0)) && *s && SvOK(*s)) expires = SvIV(*s);
        if ((s = hv_fetchs(h, "max_body", 0)) && *s && SvOK(*s))
            max_body = SvIV(*s);
        if ((s = hv_fetchs(h, "max_header_bytes", 0)) && *s && SvOK(*s))
            max_header = SvIV(*s);
        if ((s = hv_fetchs(h, "concurrency", 0)) && *s && SvOK(*s))
            conc = SvIV(*s);
        hp = SvPV(host, hlen);
        RETVAL = mt_fleet_refresh(aTHX_ f, hp, hlen, keys, expires,
                                  max_body, max_header, conc);
    OUTPUT:
        RETVAL

# count($host, $field) - bump one isolation counter. The Perl dispatch
# calls this instead of keeping its own hash, so there is one store for
# a number two code paths produce.
IV
count(self, host, field, n = 1)
        SV *self
        SV *host
        SV *field
        IV n
    PREINIT:
        mt_fleet *f;
        STRLEN hlen, flen;
        const char *hp, *fp;
    CODE:
        f = MT_TABLE(self);
        if (!f || !SvOK(host) || !SvOK(field)) XSRETURN_IV(0);
        hp = SvPV(host, hlen);
        fp = SvPV(field, flen);
        RETVAL = mt_fleet_count(aTHX_ f, hp, hlen, fp, flen, n);
    OUTPUT:
        RETVAL

# Every tenant's isolation counters, keyed by proxy id - what
# Maat::Router::tenant_metrics reads. An introspection call, walked
# rather than indexed: the request path never asks this.
SV *
by_proxy(self)
        SV *self
    PREINIT:
        mt_fleet *f;
        HV *out;
        char *key;
        I32 klen;
        SV *val;
    CODE:
        f = MT_TABLE(self);
        if (!f) XSRETURN_UNDEF;
        out = newHV();
        hv_iterinit(f->by_host);
        while ((val = hv_iternextsv(f->by_host, &key, &klen))) {
            mt_entry *e;
            HV *one;
            char pbuf[32];
            int plen;
            if (!SvIOK(val)) continue;
            e = INT2PTR(mt_entry *, SvIVX(val));
            if (!e) continue;
            one = newHV();
            (void)hv_stores(one, "requests",  newSVuv(e->requests));
            (void)hv_stores(one, "rejected_body", newSVuv(e->rejected_body));
            (void)hv_stores(one, "rejected_header", newSVuv(e->rejected_header));
            (void)hv_stores(one, "rejected_concurrency",
                            newSVuv(e->rejected_concurrency));
            (void)hv_stores(one, "inflight", newSViv(e->inflight));
            plen = snprintf(pbuf, sizeof pbuf, "%" IVdf, e->proxy);
            (void)hv_store(out, pbuf, plen, newRV_noinc((SV *)one), 0);
        }
        RETVAL = newRV_noinc((SV *)out);
    OUTPUT:
        RETVAL

# challenges(\%map) - the pending http-01 challenges, replaced wholesale.
# The edge answers these for ANY host, since Let's Encrypt probes a
# domain before its certificate exists and therefore before it routes.
void
challenges(self, map)
        SV *self
        SV *map
    PREINIT:
        mt_fleet *f;
        HV *in, *fresh;
        char *key;
        I32 klen;
        SV *val;
    CODE:
        f = MT_TABLE(self);
        if (!f) XSRETURN_EMPTY;
        in = MT_HV(map);
        fresh = newHV();
        if (in) {
            hv_iterinit(in);
            while ((val = hv_iternextsv(in, &key, &klen)))
                if (val && SvOK(val))
                    (void)hv_store(fresh, key, klen, newSVsv(val), 0);
        }
        SvREFCNT_dec((SV *)f->challenges);
        f->challenges = fresh;

# jwks(\@keys) - the authorization server's public keys, replaced wholesale
# by each bundle. Fleet-wide: one authorization server, one set. Pass undef
# or an empty list to clear it, which is what a tenant base with no OAuth
# publishes and what leaves the request path untouched.
void
jwks(self, keys)
        SV *self
        SV *keys
    PREINIT:
        mt_fleet *f;
        AV *in;
    CODE:
        f = MT_TABLE(self);
        if (!f) XSRETURN_EMPTY;
        in = (keys && SvOK(keys) && SvROK(keys)
              && SvTYPE(SvRV(keys)) == SVt_PVAV) ? (AV *)SvRV(keys) : NULL;
        if (f->jwks) SvREFCNT_dec(f->jwks);
        f->jwks = (in && av_count(in)) ? newRV_inc((SV *)in) : NULL;

# aliases(\%map) - custom domain -> tenant host, replaced wholesale by
# each bundle. A lookup follows one indirection; see mt_fleet.h for why
# it is a map and not an entry per domain.
void
aliases(self, map)
        SV *self
        SV *map
    PREINIT:
        mt_fleet *f;
        HV *in, *fresh;
        char *key;
        I32 klen;
        SV *val;
    CODE:
        f = MT_TABLE(self);
        if (!f) XSRETURN_EMPTY;
        in = MT_HV(map);
        fresh = newHV();
        if (in) {
            hv_iterinit(in);
            while ((val = hv_iternextsv(in, &key, &klen)))
                if (val && SvOK(val))
                    (void)hv_store(fresh, key, klen, newSVsv(val), 0);
        }
        SvREFCNT_dec((SV *)f->alias);
        f->alias = fresh;

IV
retire(self, host)
        SV *self
        SV *host
    PREINIT:
        mt_fleet *f;
        STRLEN hlen;
        const char *hp;
    CODE:
        f = MT_TABLE(self);
        if (!f || !SvOK(host)) XSRETURN_IV(0);
        hp = SvPV(host, hlen);
        RETVAL = mt_fleet_retire(aTHX_ f, hp, hlen);
    OUTPUT:
        RETVAL

# What is published for a host, as a plain hash - for the tests and for
# `apip` to introspect a running worker. The request path never calls
# this; it reads the struct.
SV *
lookup(self, host)
        SV *self
        SV *host
    PREINIT:
        mt_fleet *f;
        mt_entry *e;
        HV *out;
        STRLEN hlen;
        const char *hp;
    CODE:
        f = MT_TABLE(self);
        if (!f || !SvOK(host)) XSRETURN_UNDEF;
        hp = SvPV(host, hlen);
        e = mt_fleet_lookup(aTHX_ f, hp, hlen);
        if (!e) XSRETURN_UNDEF;
        out = newHV();
        (void)hv_stores(out, "proxy",       newSViv(e->proxy));
        (void)hv_stores(out, "expires",     newSViv(e->expires));
        (void)hv_stores(out, "max_body",    newSViv(e->max_body));
        (void)hv_stores(out, "max_header_bytes", newSViv(e->max_header_bytes));
        (void)hv_stores(out, "concurrency", newSViv(e->concurrency));
        (void)hv_stores(out, "inflight",    newSViv(e->inflight));
        (void)hv_stores(out, "refcnt",      newSViv(e->refcnt));
        (void)hv_stores(out, "direct",      newSViv((e->flags & MT_E_DIRECT) ? 1 : 0));
        (void)hv_stores(out, "portal",      newSViv((e->flags & MT_E_PORTAL) ? 1 : 0));
        (void)hv_stores(out, "mcp",         newSViv((e->flags & MT_E_MCP) ? 1 : 0));
        (void)hv_stores(out, "poison",      newSViv((e->flags & MT_E_POISON) ? 1 : 0));
        (void)hv_stores(out, "requests",    newSVuv(e->requests));
        (void)hv_stores(out, "app",         e->app ? SvREFCNT_inc_simple_NN(e->app) : &PL_sv_undef);
        (void)hv_stores(out, "version",     e->version ? SvREFCNT_inc_simple_NN(e->version) : &PL_sv_undef);
        RETVAL = newRV_noinc((SV *)out);
    OUTPUT:
        RETVAL

# acquire/done drive the lifetime the dispatcher will drive in C. Exposed
# so t/29 can prove the refcount discipline - that a publish under load
# does not free an entry a request is still finishing against - without
# a live worker.
IV
acquire(self, host)
        SV *self
        SV *host
    PREINIT:
        mt_fleet *f;
        mt_entry *e;
        STRLEN hlen;
        const char *hp;
    CODE:
        f = MT_TABLE(self);
        if (!f || !SvOK(host)) XSRETURN_IV(0);
        hp = SvPV(host, hlen);
        e = mt_fleet_lookup(aTHX_ f, hp, hlen);
        if (!e) XSRETURN_IV(0);
        mt_entry_acquire(e);
        RETVAL = PTR2IV(e);
    OUTPUT:
        RETVAL

void
done(self, token)
        SV *self
        IV token
    PREINIT:
        mt_fleet *f;
    CODE:
        f = MT_TABLE(self);
        if (!f || !token) XSRETURN_EMPTY;
        mt_entry_done(aTHX_ f, INT2PTR(mt_entry *, token));

UV
drain(self)
        SV *self
    PREINIT:
        mt_fleet *f;
    CODE:
        f = MT_TABLE(self);
        RETVAL = f ? mt_fleet_drain(aTHX_ f) : 0;
    OUTPUT:
        RETVAL

SV *
stats(self)
        SV *self
    PREINIT:
        mt_fleet *f;
        mt_entry *e;
        HV *out;
        UV waiting = 0;
    CODE:
        f = MT_TABLE(self);
        if (!f) XSRETURN_UNDEF;
        for (e = f->retired; e; e = e->next_retired) waiting++;
        out = newHV();
        (void)hv_stores(out, "live",      newSVuv(f->n_live));
        (void)hv_stores(out, "published", newSVuv(f->n_published));
        (void)hv_stores(out, "retired",   newSVuv(f->n_retired));
        (void)hv_stores(out, "freed",     newSVuv(f->n_freed));
        (void)hv_stores(out, "waiting",   newSVuv(waiting));
        RETVAL = newRV_noinc((SV *)out);
    OUTPUT:
        RETVAL

void
DESTROY(self)
        SV *self
    PREINIT:
        mt_fleet *f;
    CODE:
        f = MT_TABLE(self);
        if (f) {
            mt_fleet_free(aTHX_ f);
            sv_setiv(SvRV(self), 0);
        }

MODULE = Maat        PACKAGE = Maat::Router

PROTOTYPES: DISABLE

# The fleet edge in C. Answers every request - hot and cold, refusals
# included - calling back into Perl only to compile a host it has never
# served and to wrap an async response. See mt_dispatch.h.
#
# (Note for the next person: a line here starting with "# else" becomes
# a C preprocessor #else, because xsubpp passes hash lines through. It
# cost a build to learn.)
SV *
_c_dispatch(self, env)
        SV *self
        SV *env
    PREINIT:
        HV *rh;
        SV **slot;
        mt_fleet *f = NULL;
        HV *metrics = NULL;
        SV *out = NULL;
    CODE:
        rh = MT_HV(self);
        if (!rh) XSRETURN_UNDEF;
        if ((slot = hv_fetchs(rh, "ctable", 0)) && *slot)
            f = MT_TABLE(*slot);
        if (!f) XSRETURN_UNDEF;
        if ((slot = hv_fetchs(rh, "metrics", 0)) && *slot)
            metrics = MT_HV(*slot);
        out = mt_dispatch(aTHX_ self, f, metrics, env);
        if (!out) XSRETURN_UNDEF;
        RETVAL = out;
    OUTPUT:
        RETVAL
