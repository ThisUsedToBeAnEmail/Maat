#ifndef MT_FLEET_H
#define MT_FLEET_H

/*
 * mt_fleet.h - the C tenant table (phase 12b).
 *
 * What Maat::Router consults per request, in a shape C can read without
 * touching an SV: host -> caps, counters, in-flight count, and the
 * gateway to call. Perl still decides what a tenant IS - the bundle,
 * the compile, the LRU, the poison, all of it stays in Maat::Registry -
 * and publishes the result here when it changes. Publishing happens per
 * compile; reading happens per request. That asymmetry is the whole
 * point of the table.
 *
 * bench/fleet.pl measured what this replaces: 6.3us per request of Perl
 * between Hyperman and mt_serve, 141% on top of the C path it guards.
 *
 * IT IS AN ACCELERATOR, NEVER THE TRUTH
 *
 * Every entry here is derivable from Maat::Registry's own state. If a
 * publish fails, is skipped, or is never wired at all, resolve() still
 * answers exactly as it does today - the dispatcher falls back to the
 * Perl path for any host it cannot find. Nothing in this file may be
 * the only copy of anything, because a cache that is also the record is
 * a cache whose bugs are outages.
 *
 * LIFETIME, WHICH IS THE HARD PART
 *
 * Phase 6's property: a publish under load disturbs nobody, because an
 * in-flight request holds a reference to the object it started with and
 * finishes against that. In Perl that was a closure keeping an SV
 * alive. Here it is a refcount:
 *
 *   refcnt = 1 while the entry is in the table
 *          + 1 per in-flight request holding it
 *
 * Publishing a host that already has an entry does not free the old
 * one; it drops the table's reference and moves it to the retired list.
 * The last request to let go frees it. A request that started against
 * version 4 finishes against version 4 while every new request gets
 * version 5, and neither knows the other happened.
 *
 * ONE WORKER, ONE WRITER
 *
 * Per worker, like the compiled cache it mirrors. Hyperman workers are
 * processes, and a worker's loop is single-threaded, so there are no
 * locks here and there must never be: the moment this needs one, the
 * design is wrong somewhere upstream.
 */

#include "mt_compat.h"

/* Flags on an entry. DIRECT is the one that pays for the table: it says
 * the app is a bare Maat::Gateway whose C entry point can be called
 * without going through the Perl closure. A portal-wrapped app, a
 * poisoned host's 503, and anything a test injected are not direct and
 * keep their closure. */
#define MT_E_DIRECT  0x01
#define MT_E_POISON  0x02
#define MT_E_PORTAL  0x04
/* This tenant serves an MCP endpoint. Deliberately NOT in the mask that
 * clears DIRECT below: the branch that answers /mcp runs before the tenant
 * app is entered at all, so the API path keeps its bare C entry point. A
 * tenant without MCP pays one flag test for it. */
#define MT_E_MCP     0x08

typedef struct mt_entry {
    /* what the dispatcher calls */
    SV *gw;        /* the Maat::Gateway, for mt_serve; NULL unless DIRECT */
    SV *app;       /* the PSGI closure - always present, always callable */
    SV *mcp;       /* the MCP endpoint's own app; NULL unless MT_E_MCP     */

    /* what it stamps and hands on */
    SV *version;   /* spec version, for X-Maat-Version */
    SV *keys;      /* AV ref of the tenant's live API keys, or NULL */
    IV  proxy;     /* the tenant's proxy id - the ONLY metrics dimension */
    IV  expires;   /* epoch; 0 = never. A stale bundle must not outserve it */

    /* caps, resolved once at publish rather than merged per request */
    IV max_body;
    IV max_header_bytes;
    IV concurrency;

    /* live state */
    IV  inflight;
    IV  refcnt;
    U32 flags;

    /* per-tenant counters, keyed by proxy id alone - see Maat::Router on
     * why there is no per-path or per-status dimension here */
    UV requests;
    UV rejected_body;
    UV rejected_header;
    UV rejected_concurrency;

    struct mt_entry *next_retired;
} mt_entry;

typedef struct {
    HV *by_host;            /* host -> IV holding an mt_entry pointer */
    mt_entry *retired;      /* published-over or dropped, still in flight */

    /* host -> the isolation counters of the entry that used to be there.
     * A tenant's entry is retired and rebuilt whenever its spec changes,
     * and a counter that restarted on every deploy would be one nobody
     * could reason about - "requests since when?" has to have the same
     * answer for a tenant that publishes weekly and one that never has.
     * Bounded by hosts this worker has served, which is the same bound
     * the table itself has. */
    HV *carry;

    /* token -> key authorization, for the ACME probe. Replaced wholesale
     * by each bundle, because that is how the control plane sends them:
     * a pending challenge is a fact about right now, not an accumulation. */
    HV *challenges;

    /* custom domain -> the tenant host it serves. A map rather than a
     * second entry per domain: two entries would be two sets of
     * counters and two concurrency ceilings for one tenant, which is
     * not a cache detail but a different product. */
    HV *alias;

    /* The authorization server's public keys, for verifying an OAuth tool
     * call without asking the control plane per request. Fleet-wide rather
     * than per tenant because there is one authorization server: a copy on
     * every entry would be N copies of one fact, and rotating a key would
     * have to touch all of them. Replaced wholesale by each bundle, like the
     * challenges above, so a rotation lands on the next poll and an entry
     * that was compiled before it is unaffected. NULL until a bundle carries
     * one, which is what keeps a fleet with no OAuth byte for byte what it
     * was. */
    SV *jwks;

    /* observability, because a refcount bug is otherwise invisible until
     * it is a leak: these are what t/29 asserts against */
    UV n_published;
    UV n_retired;
    UV n_freed;
    UV n_live;              /* entries currently in the table */
} mt_fleet;

/* ---- host normalisation ----------------------------------------------------
 * Lower-cased, port stripped, exactly as Maat::Registry::resolve does it -
 * a Host header may carry a port and casing is not the client's business.
 * Written into a caller-supplied buffer so the request path allocates
 * nothing; a host longer than the buffer is not a host any certificate
 * covers, and is refused by returning 0. */
static int mt_host_norm(char *buf, size_t cap, const char *host, STRLEN len) {
    size_t i, n = 0;
    if (!host || !len) return 0;
    for (i = 0; i < len && n + 1 < cap; i++) {
        char c = host[i];
        if (c == ':') break;                  /* the port is not the host */
        buf[n++] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    buf[n] = '\0';
    return n ? (int)n : 0;
}

/* ---- entries ---------------------------------------------------------------*/

static void mt_entry_free(pTHX_ mt_entry *e) {
    if (!e) return;
    if (e->gw)      SvREFCNT_dec(e->gw);
    if (e->app)     SvREFCNT_dec(e->app);
    if (e->mcp)     SvREFCNT_dec(e->mcp);
    if (e->version) SvREFCNT_dec(e->version);
    if (e->keys)    SvREFCNT_dec(e->keys);
    Safefree(e);
}

/* Drop one reference. The last one out frees - which for a retired entry
 * is the in-flight request that outlived the publish. */
static void mt_entry_unref(pTHX_ mt_fleet *f, mt_entry *e) {
    if (!e) return;
    if (--e->refcnt > 0) return;

    /* Unlink from the retired list before freeing. Walked rather than
     * doubly linked: the list is empty in the steady state and holds one
     * or two entries during a publish under load, so a pointer per entry
     * would cost more than the walk ever does. */
    if (f) {
        mt_entry **pp = &f->retired;
        while (*pp) {
            if (*pp == e) { *pp = e->next_retired; break; }
            pp = &(*pp)->next_retired;
        }
        f->n_freed++;
    }
    mt_entry_free(aTHX_ e);
}

/* Take a slot: one reference for the request, one in-flight for the
 * ceiling. Paired with mt_entry_done, which must run exactly once
 * however the response is shaped. */
static void mt_entry_acquire(mt_entry *e) {
    e->refcnt++;
    e->inflight++;
}

static void mt_entry_done(pTHX_ mt_fleet *f, mt_entry *e) {
    if (!e) return;
    if (e->inflight > 0) e->inflight--;
    mt_entry_unref(aTHX_ f, e);
}

/* ---- the table -------------------------------------------------------------*/

static mt_fleet *mt_fleet_new(pTHX) {
    mt_fleet *f;
    Newxz(f, 1, mt_fleet);
    f->by_host = newHV();
    f->carry   = newHV();
    f->challenges = newHV();
    f->alias      = newHV();
    return f;
}

static mt_entry *mt_fleet_lookup(pTHX_ mt_fleet *f,
                                 const char *host, STRLEN len) {
    char buf[256];
    SV **slot;
    int n;
    if (!f || !(n = mt_host_norm(buf, sizeof buf, host, len))) return NULL;
    slot = hv_fetch(f->by_host, buf, n, 0);
    if (!slot || !*slot || !SvIOK(*slot)) {
        /* A custom domain: one indirection to the tenant host it serves,
         * exactly as Maat::Registry::resolve follows its alias table. */
        SV **a = hv_fetch(f->alias, buf, n, 0);
        if (!a || !*a || !SvOK(*a)) return NULL;
        {
            STRLEN tl;
            const char *tp = SvPV_const(*a, tl);
            char tbuf[256];
            int tn = mt_host_norm(tbuf, sizeof tbuf, tp, tl);
            if (!tn) return NULL;
            slot = hv_fetch(f->by_host, tbuf, tn, 0);
            if (!slot || !*slot || !SvIOK(*slot)) return NULL;
        }
    }
    return INT2PTR(mt_entry *, SvIVX(*slot));
}

/* Retire whatever is at this host: drop the table's reference, and keep
 * the entry alive on the retired list for as long as requests hold it. */
static int mt_fleet_retire(pTHX_ mt_fleet *f, const char *host, STRLEN len) {
    char buf[256];
    SV *old;
    mt_entry *e;
    int n;
    if (!f || !(n = mt_host_norm(buf, sizeof buf, host, len))) return 0;

    old = hv_delete(f->by_host, buf, n, 0);   /* mortal copy of the IV */
    if (!old || !SvIOK(old)) return 0;
    e = INT2PTR(mt_entry *, SvIVX(old));
    if (!e) return 0;

    /* Keep the counters for whatever takes this host next. */
    {
        AV *c = newAV();
        av_push(c, newSVuv(e->requests));
        av_push(c, newSVuv(e->rejected_body));
        av_push(c, newSVuv(e->rejected_header));
        av_push(c, newSVuv(e->rejected_concurrency));
        (void)hv_store(f->carry, buf, n, newRV_noinc((SV *)c), 0);
    }

    f->n_live--;
    f->n_retired++;
    e->next_retired = f->retired;
    f->retired = e;
    mt_entry_unref(aTHX_ f, e);               /* the table's reference */
    return 1;
}

/* Publish an entry for a host, replacing (and retiring) any current one.
 * The SVs are ours from here: each is incremented on the way in and
 * decremented when the entry is finally freed, so the caller may let its
 * own references go immediately. */
static mt_entry *mt_fleet_publish(pTHX_ mt_fleet *f,
                                  const char *host, STRLEN len,
                                  SV *gw, SV *app, SV *mcp, SV *version, SV *keys,
                                  IV proxy, IV expires,
                                  IV max_body, IV max_header_bytes,
                                  IV concurrency, U32 flags) {
    char buf[256];
    mt_entry *e;
    int n;
    UV carried_requests = 0, carried_body = 0;
    UV carried_header = 0, carried_concurrency = 0;

    if (!f || !app) return NULL;
    if (!(n = mt_host_norm(buf, sizeof buf, host, len))) return NULL;

    /* The entry being replaced, if any - its counters carry over. A
     * tenant that publishes a new spec is the same tenant, and an
     * isolation counter that reset on every deploy would be a counter
     * nobody could reason about. */
    mt_fleet_retire(aTHX_ f, buf, (STRLEN)n);
    {
        SV **slot = hv_fetch(f->carry, buf, n, 0);
        AV *c = (slot && *slot) ? MT_AV(*slot) : NULL;
        if (c && av_len(c) >= 3) {
            SV **v;
            if ((v = av_fetch(c, 0, 0))) carried_requests    = SvUV(*v);
            if ((v = av_fetch(c, 1, 0))) carried_body        = SvUV(*v);
            if ((v = av_fetch(c, 2, 0))) carried_header      = SvUV(*v);
            if ((v = av_fetch(c, 3, 0))) carried_concurrency = SvUV(*v);
        }
    }

    Newxz(e, 1, mt_entry);
    e->app     = SvREFCNT_inc_simple_NN(app);
    e->mcp     = (mcp     && SvOK(mcp))     ? SvREFCNT_inc_simple_NN(mcp)     : NULL;
    e->gw      = (gw      && SvOK(gw))      ? SvREFCNT_inc_simple_NN(gw)      : NULL;
    e->version = (version && SvOK(version)) ? SvREFCNT_inc_simple_NN(version) : NULL;
    e->keys    = (keys    && SvOK(keys))    ? SvREFCNT_inc_simple_NN(keys)    : NULL;
    e->proxy   = proxy;
    e->expires = expires;

    /* A cap that arrives as zero or nonsense is not a licence to have no
     * cap: the defaults are abuse ceilings, and an entry published
     * without them would be a tenant with none. */
    e->max_body         = max_body         > 0 ? max_body         : 16777216;
    e->max_header_bytes = max_header_bytes > 0 ? max_header_bytes : 65536;
    e->concurrency      = concurrency      > 0 ? concurrency      : 128;

    e->requests             = carried_requests;
    e->rejected_body        = carried_body;
    e->rejected_header      = carried_header;
    e->rejected_concurrency = carried_concurrency;

    e->flags  = flags;
    e->refcnt = 1;                            /* the table's own */

    /* The gateway is only callable directly if we were given one AND
     * nothing wraps it. Belt and braces: a portal-wrapped app with the
     * DIRECT flag set would serve /docs as an API path. */
    if (!e->gw || (e->flags & (MT_E_PORTAL | MT_E_POISON)))
        e->flags &= ~MT_E_DIRECT;

    /* A flag with no app behind it would be a branch into nothing. */
    if (!e->mcp) e->flags &= ~MT_E_MCP;

    if (!hv_store(f->by_host, buf, n, newSViv(PTR2IV(e)), 0)) {
        mt_entry_free(aTHX_ e);               /* never in the table, no list */
        return NULL;
    }
    f->n_published++;
    f->n_live++;
    return e;
}

/* Refresh the parts of an entry that change WITHOUT a recompile.
 *
 * The bundle carries two kinds of fact about a tenant: what its spec is
 * (a digest - change it and the entry is retired and rebuilt) and what
 * its terms are (keys, plan caps, expiry - change them and the compiled
 * app is still perfectly good). Conflating them cost two bugs the moment
 * the C path started reading this table instead of the tenant hash:
 *
 *   - a REVOKED KEY is dropped from the bundle without touching the
 *     digest, so an entry holding keys from compile time went on
 *     honouring a key the control plane had already killed;
 *   - a PLAN CHANGE moves the caps the same way, so a downgraded tenant
 *     kept the ceilings it no longer paid for.
 *
 * So the poll refreshes them in place. No retire, no refcount change,
 * nothing for an in-flight request to notice: it is the same entry, and
 * the next request reads the new terms.
 */
static int mt_fleet_refresh(pTHX_ mt_fleet *f, const char *host, STRLEN len,
                            SV *keys, IV expires,
                            IV max_body, IV max_header_bytes, IV concurrency) {
    mt_entry *e = mt_fleet_lookup(aTHX_ f, host, len);
    if (!e) return 0;

    if (e->keys) SvREFCNT_dec(e->keys);
    e->keys = (keys && SvOK(keys)) ? SvREFCNT_inc_simple_NN(keys) : NULL;

    e->expires = expires;
    if (max_body         > 0) e->max_body         = max_body;
    if (max_header_bytes > 0) e->max_header_bytes = max_header_bytes;
    if (concurrency      > 0) e->concurrency      = concurrency;
    return 1;
}

/* Bump one of an entry's isolation counters by name. The Perl dispatch
 * calls this rather than keeping a hash of its own: two stores for one
 * number is not duplication, it is a metric that reports the fraction of
 * traffic that happened to take one path - which is worse than no metric,
 * because it looks like one. */
static int mt_fleet_count(pTHX_ mt_fleet *f, const char *host, STRLEN len,
                          const char *field, STRLEN flen, IV n) {
    mt_entry *e = mt_fleet_lookup(aTHX_ f, host, len);
    if (!e) return 0;
    if      (flen == 8  && strnEQ(field, "requests", 8))    e->requests += n;
    else if (flen == 13 && strnEQ(field, "rejected_body", 13))
        e->rejected_body += n;
    else if (flen == 15 && strnEQ(field, "rejected_header", 15))
        e->rejected_header += n;
    else if (flen == 20 && strnEQ(field, "rejected_concurrency", 20))
        e->rejected_concurrency += n;
    else return 0;
    return 1;
}

/* Free the retired entries nothing holds any more. Nothing calls this to
 * make correctness happen - mt_entry_done already frees the last one out
 * - it exists so a caller can prove the list drains, and so a long-lived
 * worker can sweep after a bundle that retired a thousand tenants at
 * once. */
static UV mt_fleet_drain(pTHX_ mt_fleet *f) {
    mt_entry **pp;
    UV freed = 0;
    if (!f) return 0;
    pp = &f->retired;
    while (*pp) {
        mt_entry *e = *pp;
        if (e->refcnt <= 0) {
            *pp = e->next_retired;
            mt_entry_free(aTHX_ e);
            f->n_freed++;
            freed++;
            continue;
        }
        pp = &e->next_retired;
    }
    return freed;
}

static void mt_fleet_free(pTHX_ mt_fleet *f) {
    if (!f) return;
    if (f->carry) SvREFCNT_dec((SV *)f->carry);
    if (f->challenges) SvREFCNT_dec((SV *)f->challenges);
    if (f->alias) SvREFCNT_dec((SV *)f->alias);
    if (f->jwks) SvREFCNT_dec(f->jwks);
    if (f->by_host) {
        char *key;
        I32 klen;
        SV *val;
        hv_iterinit(f->by_host);
        while ((val = hv_iternextsv(f->by_host, &key, &klen))) {
            if (SvIOK(val)) {
                mt_entry *e = INT2PTR(mt_entry *, SvIVX(val));
                /* At teardown the worker is going away and no request is
                 * in flight; free regardless of what the counts say. */
                if (e) mt_entry_free(aTHX_ e);
            }
        }
        SvREFCNT_dec((SV *)f->by_host);
    }
    while (f->retired) {
        mt_entry *e = f->retired;
        f->retired = e->next_retired;
        mt_entry_free(aTHX_ e);
    }
    Safefree(f);
}

#endif /* MT_FLEET_H */
