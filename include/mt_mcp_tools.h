#ifndef MT_MCP_TOOLS_H
#define MT_MCP_TOOLS_H

/*
 * mt_mcp_tools.h - the tools a proxied document offers an agent.
 *
 * Derived once, when the tenant is compiled, and then only read. The request
 * path (mt_mcp.h) serves tools/list from bytes frozen here and finds a tool
 * by a hash lookup, so nothing below is on it.
 *
 * ORDERED BY operationId, and that is load bearing. A JSON object has no
 * order, and Perl perturbs hash iteration per hash, so two documents decoded
 * from identical bytes can be walked in different orders. The frozen list
 * would then differ between workers - and worse, the collision suffixes below
 * are handed out as the walk goes, so even the tool NAMES would depend on the
 * order a process happened to get.
 *
 * Open::API's operations / operation_doc / operation_schema are Perl methods
 * and are called as such. That is a build-time cost paid once per tenant, not
 * a request-time one, which is the whole reason the result is frozen.
 *
 * Needs mt_compat.h, jsf_abi.h and frj_abi.h (both resolved by mt_mcp.h).
 */

#include "mt_compat.h"

#define MT_TOOL_NAME_MAX  64
#define MT_TOOL_DESC_MAX  1024
#define MT_TOOL_PAGE_MAX  65536
#define MT_TOOL_PAGE_N    50

/* Call a method on a Perl object. Build path only. */
static SV *mt_mcp_method(pTHX_ SV *obj, const char *name, SV **args, int nargs) {
    dSP;
    int i, count;
    SV *out = NULL;
    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, nargs + 1);
    PUSHs(obj);
    for (i = 0; i < nargs; i++) PUSHs(args[i] ? args[i] : &PL_sv_undef);
    PUTBACK;
    count = call_method(name, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) { SV *r = POPs; if (!SvTRUE(ERRSV)) out = newSVsv(r); }
    PUTBACK; FREETMPS; LEAVE;
    return out;
}

/* An operationId punched down to what a tool name may hold, made unique
 * against `used`. Models match on these and clients show them. */
static SV *mt_tool_name(pTHX_ SV *raw, HV *used) {
    SV *base = newSVpvs("");
    SV *name;
    STRLEN l, i;
    const char *p;
    int n = 1;

    p = (raw && SvOK(raw)) ? SvPV_const(raw, l) : "";
    if (!raw || !SvOK(raw)) l = 0;
    for (i = 0; i < l && SvCUR(base) < MT_TOOL_NAME_MAX; i++) {
        char c = p[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
              || c == '_' || c == '-'))
            c = '_';
        sv_catpvn(base, &c, 1);
    }
    if (!SvCUR(base)) sv_catpvs(base, "op");

    name = newSVsv(base);
    while (hv_exists_ent(used, name, 0)) {
        char suffix[16];
        int sl = snprintf(suffix, sizeof suffix, "_%d", ++n);
        STRLEN keep = (STRLEN)(MT_TOOL_NAME_MAX - sl);
        SvREFCNT_dec(name);
        name = newSVsv(base);
        if (SvCUR(name) > keep) SvCUR_set(name, keep);
        sv_catpvn(name, suffix, sl);
    }
    (void)hv_store_ent(used, name, newSViv(1), 0);
    SvREFCNT_dec(base);
    return name;
}

/* From the METHOD alone. A client is told to treat annotations as untrusted,
 * so deriving them from a customer's prose would add risk without truth. */
static HV *mt_tool_annotations(pTHX_ SV *method) {
    HV *a = newHV();
    const char *m = (method && SvOK(method)) ? SvPV_nolen(method) : "";
    int read = (strEQ(m, "GET") || strEQ(m, "HEAD")) ? 1 : 0;
    (void)hv_stores(a, "readOnlyHint",    newSViv(read));
    (void)hv_stores(a, "destructiveHint", newSViv(strEQ(m, "DELETE") ? 1 : 0));
    (void)hv_stores(a, "idempotentHint",
        newSViv((read || strEQ(m, "PUT") || strEQ(m, "DELETE")) ? 1 : 0));
    (void)hv_stores(a, "openWorldHint",   newSViv(1));   /* it is a network call */
    return a;
}

static SV *mt_tool_clip(pTHX_ SV *t) {
    if (!t || !SvOK(t)) return NULL;
    if (SvCUR(t) <= MT_TOOL_DESC_MAX) return newSVsv(t);
    {
        SV *c = newSVpvn(SvPVX(t), MT_TOOL_DESC_MAX - 4);
        sv_catpvs(c, " ...");
        return c;
    }
}

/* summary, then description: a client shows every one of these to a model on
 * every turn, so both matter and neither may run away. */
static SV *mt_tool_description(pTHX_ HV *x, HV *doc) {
    SV **xd = x ? hv_fetchs(x, "description", 0) : NULL;
    SV **s, **d;
    SV *joined;

    if (xd && *xd && SvOK(*xd) && SvCUR(*xd)) return mt_tool_clip(aTHX_ *xd);

    s = hv_fetchs(doc, "summary", 0);
    d = hv_fetchs(doc, "description", 0);
    joined = newSVpvs("");
    if (s && *s && SvOK(*s)) sv_catsv(joined, *s);
    if (d && *d && SvOK(*d) && SvCUR(*d)) {
        if (SvCUR(joined)) sv_catpvs(joined, "\n\n");
        sv_catsv(joined, *d);
    }
    if (!SvCUR(joined)) { SvREFCNT_dec(joined); return NULL; }
    {
        SV *c = mt_tool_clip(aTHX_ joined);
        SvREFCNT_dec(joined);
        return c;
    }
}

/* argument name -> where it goes on the wire. Resolved here so a tool call
 * never asks the document again. */
static HV *mt_tool_where(pTHX_ SV *api, SV *op_id) {
    static const char *const locs[] = { "path", "query", "header", "cookie", NULL };
    HV *w = newHV();
    SV *args[1];
    SV *info;
    HV *ih, *params;
    int li;

    args[0] = op_id;
    info = mt_mcp_method(aTHX_ api, "operation", args, 1);
    if (!info) return w;
    sv_2mortal(info);
    ih = MT_HV(info);
    if (!ih) return w;
    {
        SV **p = hv_fetchs(ih, "params", 0);
        params = (p && *p) ? MT_HV(*p) : NULL;
    }
    if (!params) return w;

    for (li = 0; locs[li]; li++) {
        SV **lv = hv_fetch(params, locs[li], (I32)strlen(locs[li]), 0);
        AV *list = (lv && *lv) ? MT_AV(*lv) : NULL;
        SSize_t n, i;
        if (!list) continue;
        n = av_len(list) + 1;
        for (i = 0; i < n; i++) {
            SV **e = av_fetch(list, i, 0);
            HV *ph = (e && *e) ? MT_HV(*e) : NULL;
            SV **nv = ph ? hv_fetchs(ph, "name", 0) : NULL;
            HV *slot;
            STRLEN nl;
            const char *nm;
            if (!nv || !*nv || !SvOK(*nv)) continue;
            nm = SvPV_const(*nv, nl);
            slot = newHV();
            (void)hv_stores(slot, "in", newSVpv(locs[li], 0));
            (void)hv_stores(slot, "name", newSVsv(*nv));
            /* A parameter literally named `body` collides with the request
             * body, and operation_schema carried it as param_body. */
            if (nl == 4 && memEQ(nm, "body", 4))
                (void)hv_stores(w, "param_body", newRV_noinc((SV *)slot));
            else
                (void)hv_store(w, nm, (I32)nl, newRV_noinc((SV *)slot), 0);
        }
    }
    return w;
}

/* The wire form of one tool: what tools/list carries, and nothing else. */
static SV *mt_tool_wire(pTHX_ HV *t) {
    HV *w = newHV();
    SV **v;
    if ((v = hv_fetchs(t, "name", 0)))        (void)hv_stores(w, "name", newSVsv(*v));
    if ((v = hv_fetchs(t, "inputSchema", 0))) (void)hv_stores(w, "inputSchema", newSVsv(*v));
    if ((v = hv_fetchs(t, "annotations", 0))) (void)hv_stores(w, "annotations", newSVsv(*v));
    if ((v = hv_fetchs(t, "title", 0)) && SvOK(*v))
        (void)hv_stores(w, "title", newSVsv(*v));
    if ((v = hv_fetchs(t, "description", 0)) && SvOK(*v))
        (void)hv_stores(w, "description", newSVsv(*v));
    return newRV_noinc((SV *)w);
}

/* Insertion sort by operationId. A document has tens of operations, not
 * thousands, and a sort written here is one fewer perl API to depend on. */
static void mt_tool_sort(pTHX_ AV *ids) {
    SSize_t n = av_len(ids) + 1, i, j;
    for (i = 1; i < n; i++) {
        SV **a = av_fetch(ids, i, 0);
        SV *key = (a && *a) ? newSVsv(*a) : newSV(0);
        for (j = i - 1; j >= 0; j--) {
            SV **b = av_fetch(ids, j, 0);
            if (!b || !*b || sv_cmp(*b, key) <= 0) break;
            (void)av_store(ids, j + 1, newSVsv(*b));
        }
        (void)av_store(ids, j + 1, key);
    }
}

/* Build the whole table. Returns a blessed-ready HV the caller blesses. */
static HV *mt_tools_build(pTHX_ SV *api, HV *cfg) {
    HV *self = newHV();
    AV *tools = newAV();
    HV *byname = newHV();
    HV *used = newHV();
    HV *allow = NULL;
    AV *ids = newAV();
    SV *ops;
    SSize_t n, i;

    /* The allow list, when the tenant named one. */
    if (cfg) {
        SV **o = hv_fetchs(cfg, "ops", 0);
        AV *oa = (o && *o) ? MT_AV(*o) : NULL;
        if (oa && av_len(oa) >= 0) {
            SSize_t k, m = av_len(oa) + 1;
            allow = newHV();
            for (k = 0; k < m; k++) {
                SV **e = av_fetch(oa, k, 0);
                if (e && *e && SvOK(*e)) {
                    STRLEN l; const char *p = SvPV_const(*e, l);
                    (void)hv_store(allow, p, (I32)l, newSViv(1), 0);
                }
            }
        }
    }

    ops = mt_mcp_method(aTHX_ api, "operations", NULL, 0);
    if (ops) {
        AV *oav = MT_AV(ops);
        sv_2mortal(ops);
        n = oav ? av_len(oav) + 1 : 0;
        for (i = 0; i < n; i++) {
            SV **e = av_fetch(oav, i, 0);
            HV *oh = (e && *e) ? MT_HV(*e) : NULL;
            SV **idv = oh ? hv_fetchs(oh, "operationId", 0) : NULL;
            if (!idv || !*idv || !SvOK(*idv) || !SvCUR(*idv)) continue;
            if (allow) {
                STRLEN l; const char *p = SvPV_const(*idv, l);
                if (!hv_exists(allow, p, (I32)l)) continue;
            }
            av_push(ids, newSVsv(*idv));
        }
    }
    mt_tool_sort(aTHX_ ids);

    n = av_len(ids) + 1;
    for (i = 0; i < n; i++) {
        SV **idp = av_fetch(ids, i, 0);
        SV *id = (idp && *idp) ? *idp : NULL;
        SV *doc, *schema;
        HV *dh, *x = NULL;
        HV *tool;
        SV *args[1];
        SV **v;

        if (!id) continue;
        args[0] = id;
        doc = mt_mcp_method(aTHX_ api, "operation_doc", args, 1);
        if (!doc) continue;
        sv_2mortal(doc);
        dh = MT_HV(doc);
        if (!dh) continue;

        if ((v = hv_fetchs(dh, "x-mcp", 0)) && *v) x = MT_HV(*v);
        /* A document can keep an operation out of the tool list entirely. */
        if (x) {
            SV **ex = hv_fetchs(x, "exclude", 0);
            if (ex && *ex && SvTRUE(*ex)) continue;
        }

        args[0] = id;
        schema = mt_mcp_method(aTHX_ api, "operation_schema", args, 1);
        if (schema) sv_2mortal(schema);

        tool = newHV();
        {
            SV **xn = x ? hv_fetchs(x, "name", 0) : NULL;
            SV *nm = mt_tool_name(aTHX_ (xn && *xn && SvOK(*xn)) ? *xn : id, used);
            (void)hv_stores(tool, "name", nm);
            (void)hv_store_ent(byname, nm, newRV_inc((SV *)tool), 0);
        }
        (void)hv_stores(tool, "operationId", newSVsv(id));
        if ((v = hv_fetchs(dh, "method", 0))) (void)hv_stores(tool, "method", newSVsv(*v));
        if ((v = hv_fetchs(dh, "path", 0)))   (void)hv_stores(tool, "path", newSVsv(*v));
        (void)hv_stores(tool, "inputSchema",
            (schema && SvOK(schema)) ? newSVsv(schema) : newRV_noinc((SV *)newHV()));
        {
            SV **mv = hv_fetchs(dh, "method", 0);
            (void)hv_stores(tool, "annotations",
                newRV_noinc((SV *)mt_tool_annotations(aTHX_ (mv ? *mv : NULL))));
        }
        (void)hv_stores(tool, "where", newRV_noinc((SV *)mt_tool_where(aTHX_ api, id)));

        {
            SV **xt = x ? hv_fetchs(x, "title", 0) : NULL;
            SV **su = hv_fetchs(dh, "summary", 0);
            SV *title = (xt && *xt && SvOK(*xt) && SvCUR(*xt)) ? *xt
                      : ((su && *su && SvOK(*su) && SvCUR(*su)) ? *su : NULL);
            if (title) (void)hv_stores(tool, "title", newSVsv(title));
        }
        {
            SV *d = mt_tool_description(aTHX_ x, dh);
            if (d) (void)hv_stores(tool, "description", d);
        }

        /* Compiled once, so a tools/call validates its arguments in C before
         * anything is built from them. */
        {
            const jsf_abi *J = mt_jsf(aTHX);
            SV **sc = hv_fetchs(tool, "inputSchema", 0);
            if (J && sc && *sc && SvROK(*sc)) {
                dJMPENV;
                int ret;
                SV *compiled = NULL;
                JMPENV_PUSH(ret);
                if (ret == 0) compiled = J->compile(aTHX_ *sc, NULL, 0, 0);
                JMPENV_POP;
                if (ret == 0 && compiled)
                    (void)hv_stores(tool, "validator", compiled);
            }
        }

        av_push(tools, newRV_inc((SV *)tool));
        SvREFCNT_dec((SV *)tool);        /* the two refs above own it now */
    }

    SvREFCNT_dec((SV *)ids);
    SvREFCNT_dec((SV *)used);
    if (allow) SvREFCNT_dec((SV *)allow);

    (void)hv_stores(self, "tools",  newRV_noinc((SV *)tools));
    (void)hv_stores(self, "byname", newRV_noinc((SV *)byname));
    (void)hv_stores(self, "builds", newSViv(1));
    return self;
}

/* The frozen tools/list result. Cached on the object: freezing it is the
 * whole point, and a list rebuilt per request would not be frozen at all. */
/* How many tools one tools/list page carries.
 *
 * A document with four hundred operations is a real customer, and four
 * hundred schemas in one response is megabytes a client must take before
 * it can do anything at all. The pages are frozen at compile time exactly
 * as the single list was, so paging costs a client one more round trip
 * and costs this gateway nothing per request. A tenant with fewer tools
 * than this has one page carrying no cursor, which is byte for byte what
 * it answered before there was paging. */
#define MT_MCP_TOOLS_PAGE 50

static AV *mt_tools_list_pages(pTHX_ HV *self) {
    SV **c = hv_fetchs(self, "list_pages", 0);
    AV *tools, *pages;
    SSize_t n, i = 0;
    IV pageno = 0;

    if (c && *c && SvROK(*c)) return MT_AV(*c);

    {
        SV **t = hv_fetchs(self, "tools", 0);
        tools = (t && *t) ? MT_AV(*t) : NULL;
    }
    n = tools ? av_len(tools) + 1 : 0;
    pages = newAV();

    /* do/while, so a tenant offering no tools still has a page zero to
     * answer with rather than an error. */
    do {
        AV *wire = newAV();
        HV *res = newHV();
        SSize_t stop = i + MT_MCP_TOOLS_PAGE;
        SV *bytes;

        if (stop > n) stop = n;
        for (; i < stop; i++) {
            SV **e = av_fetch(tools, i, 0);
            HV *th = (e && *e) ? MT_HV(*e) : NULL;
            if (th) av_push(wire, mt_tool_wire(aTHX_ th));
        }
        (void)hv_stores(res, "tools", newRV_noinc((SV *)wire));
        /* The cursor is this server's own opaque token, and the next
         * page's number is all it has to carry. The LAST page carries
         * none: that absence is how a client knows it has them all. */
        if (i < n)
            (void)hv_stores(res, "nextCursor",
                            newSVpvf("%" IVdf, (IV)(pageno + 1)));
        {
            SV *rv = sv_2mortal(newRV_noinc((SV *)res));
            bytes = mt_mcp_encode(aTHX_ rv);
        }
        if (!bytes) bytes = newSVpvs("{\"tools\":[]}");
        av_push(pages, bytes);
        pageno++;
    } while (i < n);

    (void)hv_stores(self, "list_pages", newRV_noinc((SV *)pages));
    return pages;
}

static SV *mt_tools_list_bytes(pTHX_ HV *self) {
    SV **c = hv_fetchs(self, "list_bytes", 0);
    AV *pages;
    SV **p0;
    SV *bytes;

    if (c && *c && SvOK(*c)) return *c;

    pages = mt_tools_list_pages(aTHX_ self);
    p0 = av_fetch(pages, 0, 0);
    bytes = (p0 && *p0) ? newSVsv(*p0) : newSVpvs("{\"tools\":[]}");
    (void)hv_stores(self, "list_bytes", bytes);
    return bytes;
}

#endif /* MT_MCP_TOOLS_H */
