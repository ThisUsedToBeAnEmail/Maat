#ifndef MT_MCP_BUILD_H
#define MT_MCP_BUILD_H

/*
 * mt_mcp_build.h - what an MCP endpoint is made of, made once.
 *
 * The tenant's tools, the frozen tools/list bytes and this server's identity,
 * assembled when the tenant compiles and only read afterwards. Nothing here
 * runs on a request; mt_mcp.h is that half.
 *
 * The PSGI adapter is deliberately NOT here. Maat::Registry already builds a
 * tenant's app - `$gw->to_app`, then the portal's wrap around it - and the
 * one line that turns this object into a PSGI coderef belongs beside them
 * rather than in a closure factory this distribution would otherwise have no
 * use for.
 *
 * Needs mt_mcp_tools.h (and so mt_mcp.h, for the two ABI tables).
 */

#include "mt_mcp_tools.h"

static HV *mt_mcp_new(pTHX_ SV *api, SV *gw, SV *host, SV *version, HV *cfg) {
    HV *self = newHV();
    HV *tools = mt_tools_build(aTHX_ api, cfg);
    SV *spec;
    HV *sh = NULL, *info = NULL, *xmcp = NULL;
    SV **v;

    /* The tools object is a Maat::MCP::Tools in its own right: the console
     * previews the same list the gateway will serve, from the same code. */
    (void)hv_stores(self, "tools",
        sv_bless(newRV_inc((SV *)tools),
                 gv_stashpv("Maat::MCP::Tools", GV_ADD)));

    /* Lifted onto the endpoint so a request reads one hash, not two. */
    if ((v = hv_fetchs(tools, "byname", 0)))
        (void)hv_stores(self, "byname", newSVsv(*v));
    (void)hv_stores(self, "list_bytes",
                    newSVsv(mt_tools_list_bytes(aTHX_ tools)));
    /* Every page, frozen with it. Taken by reference BEFORE the tools
     * hash is released below, which is what keeps the array alive. */
    {
        AV *pg = mt_tools_list_pages(aTHX_ tools);
        (void)hv_stores(self, "list_pages", newRV_inc((SV *)pg));
    }
    SvREFCNT_dec((SV *)tools);

    if (api && SvOK(api))     (void)hv_stores(self, "api", newSVsv(api));
    if (gw && SvOK(gw))       (void)hv_stores(self, "gw", newSVsv(gw));
    if (host && SvOK(host))   (void)hv_stores(self, "host", newSVsv(host));
    if (version && SvOK(version))
        (void)hv_stores(self, "version", newSVsv(version));

    /* The challenge and the RFC 9728 document, built once from this tenant's
     * own host. Both are constant for the life of the compiled tenant, so a
     * 401 costs a header copy rather than a sprintf, and discovery is served
     * from frozen bytes like tools/list. */
    if (host && SvOK(host) && SvCUR(host)) {
        HV *doc = newHV();
        AV *methods = newAV(), *scopes = newAV();
        SV *res = newSVpvs("https://");
        SV *ch  = newSVpvs("Bearer realm=\"" MT_MCP_REALM "\", "
                           "resource_metadata=\"https://");
        SV *bytes;

        sv_catsv(res, host);
        sv_catpvs(res, "/mcp");
        sv_catsv(ch, host);
        sv_catpvs(ch, MT_MCP_METADATA_PATH "\"");
        (void)hv_stores(self, "challenge", ch);

        /* The canonical resource identifier: this endpoint, not the host.
         * One site fronts many MCP servers, and RFC 8707 wants the most
         * specific identifier a token can be bound to - which is what stops
         * a token minted for one tenant being spent at another. */
        (void)hv_stores(doc, "resource", SvREFCNT_inc_simple_NN(res));
        /* Kept in its own slot as well as in the frozen document: a token's
         * `aud` is checked against this on every OAuth call, and digging it
         * back out of encoded JSON per request would be absurd. */
        (void)hv_stores(self, "resource", res);
        av_push(methods, newSVpvs("header"));
        (void)hv_stores(doc, "bearer_methods_supported",
                        newRV_noinc((SV *)methods));
        av_push(scopes, newSVpvs(MT_MCP_SCOPE));
        (void)hv_stores(doc, "scopes_supported", newRV_noinc((SV *)scopes));
        {
            SV *docs = newSVpvs("https://");
            sv_catsv(docs, host);
            sv_catpvs(docs, "/docs");
            (void)hv_stores(doc, "resource_documentation", docs);
        }

        /* Named only when this tenant may actually use OAuth. A keys-only
         * tenant advertising an authorization server would send every client
         * through a flow that ends in a token this endpoint refuses. */
        if (cfg && (v = hv_fetchs(cfg, "oauth", 0)) && *v && SvTRUE(*v)) {
            AV *as = newAV();
            SV **iss = hv_fetchs(cfg, "issuer", 0);
            SV *issuer = (iss && *iss && SvOK(*iss))
                             ? newSVsv(*iss)
                             : newSVpvs("https://openapi-proxy.com/oauth");
            /* The issuer a token must claim, kept for the same reason as the
             * resource above. Only set when this tenant may use OAuth at
             * all, so a keys-only tenant has nothing to check against and
             * refuses a token outright. */
            (void)hv_stores(self, "issuer", newSVsv(issuer));
            av_push(as, issuer);
            (void)hv_stores(doc, "authorization_servers",
                            newRV_noinc((SV *)as));
        }

        bytes = mt_mcp_encode(aTHX_ sv_2mortal(newRV_noinc((SV *)doc)));
        if (bytes) (void)hv_stores(self, "metadata", bytes);
    }

    spec = mt_mcp_method(aTHX_ api, "spec", NULL, 0);
    if (spec) {
        sv_2mortal(spec);
        sh = MT_HV(spec);
    }
    if (sh) {
        if ((v = hv_fetchs(sh, "info", 0)))  info = MT_HV(*v);
        if ((v = hv_fetchs(sh, "x-mcp", 0))) xmcp = MT_HV(*v);
    }

    /* The title a client shows beside the server. The document's own, because
     * the alternative is this gateway naming somebody else's API. */
    if (info && (v = hv_fetchs(info, "title", 0)) && *v && SvOK(*v))
        (void)hv_stores(self, "title", newSVsv(*v));
    else
        (void)hv_stores(self, "title", newSVpvs("apip"));

    /* Instructions handed to the client at initialize: the tenant's setting
     * first, else whatever the document said on its root. */
    if (cfg && (v = hv_fetchs(cfg, "instructions", 0)) && *v && SvOK(*v))
        (void)hv_stores(self, "instructions", newSVsv(*v));
    else if (xmcp && (v = hv_fetchs(xmcp, "instructions", 0)) && *v && SvOK(*v))
        (void)hv_stores(self, "instructions", newSVsv(*v));

    return self;
}

#endif /* MT_MCP_BUILD_H */
