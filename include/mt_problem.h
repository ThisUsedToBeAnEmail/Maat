#ifndef MT_PROBLEM_H
#define MT_PROBLEM_H

/*
 * mt_problem.h - the edge's refusals, built in C.
 *
 * The five answers Maat::Router used to build in Perl - 404 for a host
 * nobody serves, 413 and 431 and 429 for a tenant over its caps, 502 for
 * an app that died - plus the ACME probe's two. They are here so that
 * the C dispatcher can own the cold path as well as the hot one, which
 * is the only way the Perl it replaced can actually be deleted rather
 * than merely bypassed.
 *
 * BYTE FOR BYTE
 *
 * These bodies are a public interface: a customer's client parses them,
 * and t/30 compares them against what Perl produced before this file
 * existed. The key order is `detail, status, title, type` because
 * Maat::Router::_problem encodes with sort_keys and that is what sorted
 * looks like - not because anything here chose it. Change a word and the
 * parity test fails, which is the point.
 */

#include "mt_compat.h"

#define MT_PROBLEM_TYPE "https://openapi-proxy.com/problem/edge"

/* JSON string escaping for the detail. The details below are ours and
 * contain nothing exotic, but they interpolate integers from a tenant's
 * caps, and "the input is ours" is exactly the assumption that stops
 * being true the day somebody puts a hostname in one. */
static void mt_json_str(pTHX_ SV *out, const char *s, STRLEN len) {
    STRLEN i;
    sv_catpvn(out, "\"", 1);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  sv_catpvn(out, "\\\"", 2); break;
            case '\\': sv_catpvn(out, "\\\\", 2); break;
            case '\n': sv_catpvn(out, "\\n", 2);  break;
            case '\r': sv_catpvn(out, "\\r", 2);  break;
            case '\t': sv_catpvn(out, "\\t", 2);  break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    int n = snprintf(buf, sizeof buf, "\\u%04x", c);
                    sv_catpvn(out, buf, n);
                }
                else sv_catpvn(out, (const char *)&c, 1);
        }
    }
    sv_catpvn(out, "\"", 1);
}

/* A PSGI triplet carrying problem+json. `extra_k`/`extra_v` add one
 * header (Retry-After, for the 429) or are NULL. */
static SV *mt_problem(pTHX_ int status, const char *title,
                      const char *detail, STRLEN dlen,
                      const char *extra_k, const char *extra_v) {
    SV *body = newSVpvs("");
    AV *trip = newAV();
    AV *hdrs = newAV();
    char nbuf[24];
    int nlen;

    sv_catpvs(body, "{\"detail\":");
    mt_json_str(aTHX_ body, detail, dlen);
    nlen = snprintf(nbuf, sizeof nbuf, "%d", status);
    sv_catpvs(body, ",\"status\":");
    sv_catpvn(body, nbuf, nlen);
    sv_catpvs(body, ",\"title\":");
    mt_json_str(aTHX_ body, title, strlen(title));
    sv_catpvs(body, ",\"type\":\"" MT_PROBLEM_TYPE "\"}");

    av_push(hdrs, newSVpvs("Content-Type"));
    av_push(hdrs, newSVpvs("application/problem+json"));
    av_push(hdrs, newSVpvs("Content-Length"));
    av_push(hdrs, newSViv((IV)SvCUR(body)));
    if (extra_k && extra_v) {
        av_push(hdrs, newSVpv(extra_k, 0));
        av_push(hdrs, newSVpv(extra_v, 0));
    }

    av_push(trip, newSViv(status));
    av_push(trip, newRV_noinc((SV *)hdrs));
    {
        AV *b = newAV();
        av_push(b, body);
        av_push(trip, newRV_noinc((SV *)b));
    }
    return newRV_noinc((SV *)trip);
}

/* text/plain, for the ACME probe - which is not problem+json because an
 * ACME client is not looking for one. */
static SV *mt_text(pTHX_ int status, SV *payload) {
    AV *trip = newAV();
    AV *hdrs = newAV();
    AV *body = newAV();
    SV *b = payload ? payload : newSVpvs("");

    av_push(hdrs, newSVpvs("Content-Type"));
    av_push(hdrs, newSVpvs("text/plain"));
    av_push(hdrs, newSVpvs("Content-Length"));
    av_push(hdrs, newSViv((IV)SvCUR(b)));

    av_push(body, b);
    av_push(trip, newSViv(status));
    av_push(trip, newRV_noinc((SV *)hdrs));
    av_push(trip, newRV_noinc((SV *)body));
    return newRV_noinc((SV *)trip);
}

/* ---- the five, with the wording they have always had --------------- */

static SV *mt_problem_unknown_host(pTHX) {
    static const char d[] = "no proxy is configured for this host";
    return mt_problem(aTHX_ 404, "Not Found", d, sizeof(d) - 1, NULL, NULL);
}

static SV *mt_problem_too_large(pTHX_ IV cap) {
    char d[128];
    int n = snprintf(d, sizeof d,
        "the request body exceeds this proxy's limit of %" IVdf " bytes", cap);
    return mt_problem(aTHX_ 413, "Payload Too Large", d, (STRLEN)n, NULL, NULL);
}

static SV *mt_problem_headers(pTHX) {
    static const char d[] = "the request headers exceed this proxy's limit";
    return mt_problem(aTHX_ 431, "Request Header Fields Too Large",
                      d, sizeof(d) - 1, NULL, NULL);
}

static SV *mt_problem_busy(pTHX_ IV ceiling) {
    char d[128];
    int n = snprintf(d, sizeof d,
        "this proxy is at its concurrency ceiling of %" IVdf "; retry shortly",
        ceiling);
    return mt_problem(aTHX_ 429, "Too Many Requests", d, (STRLEN)n,
                      "Retry-After", "1");
}

static SV *mt_problem_bad_gateway(pTHX) {
    static const char d[] = "the proxy for this host failed to produce a response";
    return mt_problem(aTHX_ 502, "Bad Gateway", d, sizeof(d) - 1, NULL, NULL);
}

#endif /* MT_PROBLEM_H */
