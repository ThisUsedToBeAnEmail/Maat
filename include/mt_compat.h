#ifndef MT_COMPAT_H
#define MT_COMPAT_H

/* Perl-version shims, so Maat builds on every perl it claims (5.10+).
 * Each is the standard definition of the thing it stands in for; on a
 * perl new enough to have the real one none of this is compiled. */

#ifndef mPUSHs
#  define mPUSHs(s) PUSHs(sv_2mortal(s))
#endif
#ifndef newSVpvs
#  define newSVpvs(s) newSVpvn(s "", sizeof(s) - 1)
#endif
#ifndef hv_fetchs
#  define hv_fetchs(hv, k, lval) hv_fetch(hv, k "", sizeof(k) - 1, lval)
#endif
#ifndef hv_stores
#  define hv_stores(hv, k, v) hv_store(hv, k "", sizeof(k) - 1, v, 0)
#endif
#ifndef SvREFCNT_inc_simple_void
#  define SvREFCNT_inc_simple_void(sv) SvREFCNT_inc(sv)
#endif
#ifndef SvREFCNT_inc_simple_NN
#  define SvREFCNT_inc_simple_NN(sv) SvREFCNT_inc(sv)
#endif
/* G_LIST is the 5.36+ name for the flag every earlier perl calls G_ARRAY. */
#ifndef G_LIST
#  define G_LIST G_ARRAY
#endif

/* An HV from an SV that should be a hashref; NULL for anything else.
 * Never croaks - the request path has to be able to probe. */
#define MT_HV(sv) \
    (((sv) && SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PVHV) ? (HV *)SvRV(sv) : NULL)
#define MT_AV(sv) \
    (((sv) && SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PVAV) ? (AV *)SvRV(sv) : NULL)

#endif /* MT_COMPAT_H */
