#ifndef MT_MCP_AUTH_H
#define MT_MCP_AUTH_H

/*
 * mt_mcp_auth.h - who is calling, decided before anything is framed.
 *
 * The tenant's own API keys are the credential: `Authorization: Bearer
 * apip_...` is hashed and compared against the key hashes already on the
 * environment as `maat.keys`, which the dispatcher put there before this
 * endpoint was entered. So there is no second lookup, no per-request trip to
 * the control plane, and a revoked key stops working the moment the next
 * bundle drops it - the same revocation path the API side has today.
 *
 * The hash and the compare are the ONE implementation, Crypt::JWS's, reached
 * through its C ABI. Writing a second sha256 here would be a second thing to
 * get wrong, and the two would drift the first time either was touched.
 *
 * Two rules carried over from Maat::Gateway::_key_checker deliberately, so
 * that the API path and this path cannot disagree about what a key permits:
 *
 *   - The compare never returns early. Which key matched, and whether any
 *     did, must not be a timing signal.
 *   - A key with no scopes at all is a key with every scope. That is the
 *     existing rule; inventing a stricter one here would silently break
 *     every key already issued.
 *
 * Needs mt_mcp.h (for mt_jws and MT_ENV).
 */

#define MT_MCP_REALM "apip"
#define MT_MCP_SCOPE "mcp"

/* What the caller turned out to be. */
#define MT_AUTH_OK     0   /* matched, and permitted            */
#define MT_AUTH_OPEN   1   /* tenant publishes no keys at all   */
#define MT_AUTH_NONE   2   /* nothing presented          -> 401 */
#define MT_AUTH_BAD    3   /* presented, no match        -> 401 */
#define MT_AUTH_SCOPE  4   /* matched, lacks `mcp`       -> 403 */

static void mt_hex(pTHX_ SV *out, const unsigned char *b, STRLEN n) {
    static const char H[] = "0123456789abcdef";
    STRLEN i;
    for (i = 0; i < n; i++) {
        char t[2];
        t[0] = H[(b[i] >> 4) & 0xF];
        t[1] = H[b[i] & 0xF];
        sv_catpvn(out, t, 2);
    }
}

/* The credential out of an Authorization header, or NULL. The scheme is
 * matched case-insensitively because RFC 9110 says it is case-insensitive,
 * and a client that sends `bearer` is not wrong. */
static const char *mt_mcp_bearer(pTHX_ HV *env, STRLEN *lenp) {
    static const char B[] = "bearer";
    SV *v = MT_ENV(env, "HTTP_AUTHORIZATION");
    const char *h;
    STRLEN hl, i;

    if (!v || !SvOK(v)) return NULL;
    h = SvPV_const(v, hl);
    if (hl < sizeof(B)) return NULL;
    for (i = 0; i < sizeof(B) - 1; i++) {
        char c = h[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != B[i]) return NULL;
    }
    i = sizeof(B) - 1;
    if (h[i] != ' ' && h[i] != '\t') return NULL;
    while (i < hl && (h[i] == ' ' || h[i] == '\t')) i++;
    if (i >= hl) return NULL;
    *lenp = hl - i;
    return h + i;
}

/* Does this key carry the scope an MCP call needs? */
static int mt_mcp_scoped(pTHX_ HV *key) {
    SV **sv = hv_fetchs(key, "scopes", 0);
    AV *scopes;
    SSize_t n, i;

    if (!sv || !*sv || !SvOK(*sv) || !SvROK(*sv)) return 1;  /* none = all */
    scopes = MT_AV(*sv);
    if (!scopes) return 1;
    n = av_len(scopes) + 1;
    if (n <= 0) return 1;                                    /* none = all */

    for (i = 0; i < n; i++) {
        SV **e = av_fetch(scopes, i, 0);
        if (e && *e && SvOK(*e)) {
            STRLEN l;
            const char *s = SvPV_const(*e, l);
            if (l == sizeof(MT_MCP_SCOPE) - 1
                && memEQ(s, MT_MCP_SCOPE, sizeof(MT_MCP_SCOPE) - 1))
                return 1;
        }
    }
    return 0;
}

/* ---- OAuth: a token naming a key, instead of the key ---------------------- */

/* Three dot-separated segments is a JWS compact serialisation. Anything else
 * is tried as an API key, so the two kinds of credential never collide. */
static int mt_mcp_is_jwt(const char *c, STRLEN l) {
    STRLEN i, dots = 0;
    for (i = 0; i < l; i++) if (c[i] == '.') dots++;
    return dots == 2;
}

/* $invocant->$name(@args) under G_EVAL, for the one class method this needs. */
static SV *mt_auth_method(pTHX_ SV *invocant, const char *name,
                          SV **args, int n) {
    dSP;
    int i, count;
    SV *out = NULL;
    ENTER; SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, n + 1);
    PUSHs(invocant);
    for (i = 0; i < n; i++) PUSHs(args[i] ? args[i] : &PL_sv_undef);
    PUTBACK;
    count = call_method(name, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (count > 0) { SV *r = POPs; if (!SvTRUE(ERRSV)) out = newSVsv(r); }
    PUTBACK; FREETMPS; LEAVE;
    return out;
}

/* Does a space-separated claim contain this token? */
static int mt_claim_has(pTHX_ SV *v, const char *want, STRLEN wl) {
    STRLEN l, a = 0, b;
    const char *s;
    if (!v || !SvOK(v)) return 0;
    s = SvPV_const(v, l);
    for (b = 0; b <= l; b++)
        if (b == l || s[b] == ' ') {
            if (b > a && (b - a) == wl && memEQ(s + a, want, wl)) return 1;
            a = b + 1;
        }
    return 0;
}

/* Is `want` the aud, or one of them? RFC 7519 allows either shape. */
static int mt_aud_has(pTHX_ SV *aud, SV *want) {
    STRLEN wl, al;
    const char *wp, *ap;
    if (!aud || !SvOK(aud) || !want || !SvOK(want)) return 0;
    wp = SvPV_const(want, wl);
    if (SvROK(aud) && SvTYPE(SvRV(aud)) == SVt_PVAV) {
        AV *av = (AV *)SvRV(aud);
        SSize_t i, n = av_len(av) + 1;
        for (i = 0; i < n; i++) {
            SV **e = av_fetch(av, i, 0);
            if (!e || !*e || !SvOK(*e)) continue;
            ap = SvPV_const(*e, al);
            if (al == wl && memEQ(ap, wp, wl)) return 1;
        }
        return 0;
    }
    ap = SvPV_const(aud, al);
    return (al == wl && memEQ(ap, wp, wl)) ? 1 : 0;
}

/* Verify an OAuth access token and resolve the key it names.
 *
 * Statelessly, against the JWKS the bundle carried: the data plane must not
 * call the control plane per request. What the token is checked for is the
 * whole point of RFC 8707 being in the authorization server - `aud` must be
 * THIS endpoint's canonical resource, so a token minted for one tenant is
 * refused here even though the same authorization server issued it.
 *
 * The client's token never goes upstream. It names a key with `apip_key`,
 * that key is resolved against the tenant's published set, and the resolved
 * key is what the synthetic request carries - which is also why a revoked key
 * kills a live token on the next bundle. */
static int mt_mcp_jwt(pTHX_ const mt_mcp *m, HV *env,
                      const char *cred, STRLEN credlen, SV **out) {
    SV *token, *hdr = NULL, *jwk = NULL, *key = NULL;
    SV *payload = NULL, *claims = NULL;
    SV *v = MT_ENV(env, "maat.jwks");
    AV *jwks = (v && SvOK(v) && SvROK(v)) ? MT_AV(v) : NULL;
    HV *ch;
    SV **c;
    IV now = (IV)time(NULL);
    SSize_t i, n;

    /* A tenant that may not use OAuth has no issuer to check against, so a
     * token is refused rather than half-validated. */
    if (!m->issuer || !m->resource) return MT_AUTH_BAD;
    if (!jwks || av_len(jwks) < 0) return MT_AUTH_BAD;

    token = sv_2mortal(newSVpvn(cred, credlen));

    /* The header names which key signed it. Routing only: nothing in here is
     * trusted until the signature verifies below. */
    hdr = mt_call_perl(aTHX_ "Crypt::JWS::peek", &token, 1);
    if (hdr) sv_2mortal(hdr);
    n = av_len(jwks) + 1;
    {
        SV *kid = NULL;
        HV *hh = (hdr && SvROK(hdr)) ? MT_HV(hdr) : NULL;
        if (hh && (c = hv_fetchs(hh, "kid", 0)) && *c && SvOK(*c)) kid = *c;
        for (i = 0; i < n; i++) {
            SV **e = av_fetch(jwks, i, 0);
            HV *k = (e && *e && SvROK(*e)) ? MT_HV(*e) : NULL;
            SV **ek = k ? hv_fetchs(k, "kid", 0) : NULL;
            if (!k) continue;
            if (!kid) { jwk = *e; break; }          /* no kid: the only key */
            if (ek && *ek && SvOK(*ek) && sv_eq(*ek, kid)) { jwk = *e; break; }
        }
    }
    if (!jwk) return MT_AUTH_BAD;

    {
        SV *cls = sv_2mortal(newSVpvs("Crypt::JWS::Key"));
        key = mt_auth_method(aTHX_ cls, "from_jwk", &jwk, 1);
    }
    if (!key) return MT_AUTH_BAD;
    sv_2mortal(key);

    {
        AV *algs = newAV();
        SV *args[4];
        av_push(algs, newSVpvs("ES256"));
        args[0] = token;
        args[1] = key;
        args[2] = sv_2mortal(newSVpvs("algs"));
        args[3] = sv_2mortal(newRV_noinc((SV *)algs));
        payload = mt_call_perl(aTHX_ "Crypt::JWS::verify", args, 4);
    }
    if (!payload || !SvOK(payload)) { SvREFCNT_dec(payload); return MT_AUTH_BAD; }
    sv_2mortal(payload);

    claims = mt_call_perl(aTHX_ "File::Raw::JSON::file_json_decode", &payload, 1);
    if (!claims) return MT_AUTH_BAD;
    sv_2mortal(claims);
    if (!SvROK(claims) || !(ch = MT_HV(claims))) return MT_AUTH_BAD;

    if (!(c = hv_fetchs(ch, "iss", 0)) || !*c || !sv_eq(*c, m->issuer))
        return MT_AUTH_BAD;

    /* The audience check, which is what makes a token tenant-specific. */
    if (!(c = hv_fetchs(ch, "aud", 0)) || !*c
        || !mt_aud_has(aTHX_ *c, m->resource))
        return MT_AUTH_BAD;

    /* 60 seconds of leeway, for the clock skew between two hosts. */
    if ((c = hv_fetchs(ch, "exp", 0)) && *c && SvOK(*c)
        && SvIV(*c) + 60 < now) return MT_AUTH_BAD;
    if ((c = hv_fetchs(ch, "nbf", 0)) && *c && SvOK(*c)
        && SvIV(*c) - 60 > now) return MT_AUTH_BAD;

    if (m->proxy) {
        c = hv_fetchs(ch, "apip_proxy", 0);
        if (!c || !*c || !SvOK(*c) || SvIV(*c) != m->proxy) return MT_AUTH_BAD;
    }

    c = hv_fetchs(ch, "scope", 0);
    if (!c || !*c || !mt_claim_has(aTHX_ *c, MT_MCP_SCOPE,
                                   sizeof(MT_MCP_SCOPE) - 1))
        return MT_AUTH_SCOPE;

    /* The key the token acts as. The gateway holds only hashes, so the token
     * cannot carry a credential to replay; it names one, and the name is
     * resolved here against what the tenant currently publishes. */
    {
        SV *kv = MT_ENV(env, "maat.keys");
        AV *keys = (kv && SvOK(kv) && SvROK(kv)) ? MT_AV(kv) : NULL;
        SV *want = NULL;
        c = hv_fetchs(ch, "apip_key", 0);
        if (c && *c && SvOK(*c)) want = *c;
        if (!want || !keys) return MT_AUTH_BAD;
        n = av_len(keys) + 1;
        for (i = 0; i < n; i++) {
            SV **e = av_fetch(keys, i, 0);
            HV *k = (e && *e) ? MT_HV(*e) : NULL;
            SV **id = k ? hv_fetchs(k, "id", 0) : NULL;
            if (id && *id && SvOK(*id) && sv_eq(*id, want)) {
                if (out) *out = *e;
                return MT_AUTH_OK;
            }
        }
    }
    return MT_AUTH_BAD;       /* named a key this tenant no longer publishes */
}

/* Authenticate the caller against the tenant's published keys. On
 * MT_AUTH_OK, *out is the matched key (a borrowed reference into the env). */
static int mt_mcp_authenticate(pTHX_ const mt_mcp *m, HV *env, SV **out) {
    const jws_abi *J;
    SV *kv = MT_ENV(env, "maat.keys");
    AV *keys = NULL;          /* assigned conditionally below: must start NULL */
    const char *cred;
    STRLEN credlen;
    SV *digest, *hex;
    SSize_t n, i;
    SV *matched = NULL;

    if (out) *out = NULL;

    if (kv && SvOK(kv) && SvROK(kv)) keys = MT_AV(kv);

    /* No keys published means two different things, and conflating them was a
     * hole the OAuth tests found.
     *
     * For a KEYS-ONLY tenant it means authentication was never configured, and
     * the endpoint is open - the same stance the API path takes, where a
     * keyless tenant is forwarded untouched, so a republish that happens to
     * drop the last key is not an outage.
     *
     * For a tenant configured for OAUTH it means every credential it could
     * possibly resolve has just been revoked. Opening the endpoint there would
     * turn a revocation into an anonymous, agent-callable relay, which is the
     * exact opposite of what configuring an issuer asked for. So it falls
     * through: a request with no credential is refused below, and one with a
     * token is refused when the token's `apip_key` resolves against nothing. */
    if ((!keys || av_len(keys) < 0) && !(m && m->issuer))
        return MT_AUTH_OPEN;

    cred = mt_mcp_bearer(aTHX_ env, &credlen);
    if (!cred || !credlen) return MT_AUTH_NONE;

    /* Two kinds of credential reach this header, and they are told apart by
     * shape rather than by configuration: a JWS has three segments, an API
     * key does not. A token is verified against the authorization server's
     * keys and resolves to one of these keys anyway, so both arms end in the
     * same place - a key on the request. */
    if (mt_mcp_is_jwt(cred, credlen))
        return mt_mcp_jwt(aTHX_ m, env, cred, credlen, out);

    J = mt_jws(aTHX);
    if (!J) return MT_AUTH_BAD;   /* cannot hash means cannot admit */

    digest = J->sha256(aTHX_ (const unsigned char *)cred, credlen);
    if (!digest) return MT_AUTH_BAD;
    sv_2mortal(digest);
    hex = sv_2mortal(newSVpvs(""));
    {
        STRLEN dl;
        const char *dp = SvPV_const(digest, dl);
        mt_hex(aTHX_ hex, (const unsigned char *)dp, dl);
    }

    /* Every key, every time: no break on a match. The list may now be empty
     * or absent (an OAuth tenant whose keys were all revoked), in which case
     * nothing matches and the caller is refused. */
    n = keys ? av_len(keys) + 1 : 0;
    for (i = 0; i < n; i++) {
        SV **e = av_fetch(keys, i, 0);
        HV *k = (e && *e) ? MT_HV(*e) : NULL;
        SV **h = k ? hv_fetchs(k, "hash", 0) : NULL;
        if (h && *h && SvOK(*h)) {
            STRLEN hl, xl;
            const char *hp = SvPV_const(*h, hl);
            const char *xp = SvPV_const(hex, xl);
            if (J->ct_eq(aTHX_ (const unsigned char *)hp, hl,
                               (const unsigned char *)xp, xl))
                matched = *e;
        }
    }
    if (!matched) return MT_AUTH_BAD;

    {
        HV *mk = MT_HV(matched);
        if (mk && !mt_mcp_scoped(aTHX_ mk)) return MT_AUTH_SCOPE;
    }

    if (out) *out = matched;
    return MT_AUTH_OK;
}

#endif /* MT_MCP_AUTH_H */
