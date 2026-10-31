package Maat::Router;

use 5.010;
use strict;
use warnings;
use Carp ();
use Scalar::Util ();
use File::Raw::JSON ();

our $VERSION = '0.05';

# The edge in front of the fleet: one PSGI app that takes the Host header
# and routes to the right tenant, isolates tenants from each other, and
# answers the two things that are the edge's own - an unknown host and an
# ACME http-01 probe - without ever touching a tenant's code path.
#
# The dispatch itself is a Maat::Registry lookup; what this adds is the
# policy the registry deliberately does not hold, because it is
# per-request rather than per-tenant:
#
#   UNKNOWN HOST IS A 404 HERE. A Host we do not serve - a scan, a stale
#   edge map, a domain removed a poll ago - is answered 404 at the edge.
#   No tenant is resolved, no spec compiled, no neighbour's path entered.
#
#   THE ACME PROBE IS ANSWERED HERE. GET /.well-known/acme-challenge/
#   <token> is served from the registry's challenge table for ANY host,
#   because Let's Encrypt probes the domain being validated over plain
#   HTTP before its certificate exists. The control plane runs the ACME
#   protocol; the edge only answers this one probe.
#
#   ISOLATION IS ENFORCED HERE. A tenant's body cap, header cap and
#   concurrency ceiling are the shared-hosting risk, so they are checked
#   before the tenant app is entered and the ceiling is held until the
#   response completes - a tenant whose upstream hangs consumes at most
#   its own ceiling of slots and cannot starve a neighbour.
#
#   VERSION IS STAMPED HERE. Every response leaves with X-Maat-Proxy and
#   X-Maat-Version, so under a publish each response is attributable to
#   exactly one version whatever the tenant app did - which is the whole
#   of gate 2's evidence.
#
# Per-tenant metrics are keyed by the tenant's proxy id ALONE. There is
# no per-host, per-path or per-status counter here - that is how you turn
# a metrics system into an outage on a fleet with a hundred thousand
# tenants.

my $ACME_PREFIX = '/.well-known/acme-challenge/';

# Defaults are abuse ceilings, not validation limits: generous enough
# that a real client never meets them, low enough that one tenant cannot
# exhaust a worker. A plan may raise them; the bundle may one day carry
# them per tenant (limits.concurrency), and that wins when present.
my %DEFAULT_CAPS = (
    max_body         => 16 * 1024 * 1024,   # bytes; a hard 413 above this
    max_header_bytes => 64 * 1024,          # total request header bytes
    concurrency      => 128,                # in-flight requests per tenant
);

sub new {
    my ($class, %o) = @_;
    my $reg = $o{registry}
        or Carp::croak('Maat::Router: registry is required');

    my $self = bless {
        registry => $reg,

        # Per-plan cap overrides: { free => { concurrency => 16, ... }, ... }.
        # A tenant's caps are the plan's over the defaults, then anything
        # the bundle carried per tenant over that.
        caps     => $o{caps} || {},
        defaults => { %DEFAULT_CAPS, %{ $o{default_caps} || {} } },

        # Every key the C dispatcher counts is seeded here, including
        # `mcp`: the first increment of a key that is not present reads
        # an undef, and the warning it raises is reported against the
        # caller of the XSUB rather than against the counter.
        metrics  => { acme_hit => 0, acme_miss => 0, routed => 0,
                      unknown => 0, rejected => 0, mcp => 0 },
    }, $class;

    return $self;
}

sub registry { $_[0]{registry} }

sub to_app {
    my ($self) = @_;

    # The caps the C path enforces have to be the caps this router would
    # have computed, so the registry is handed the resolver and calls it
    # once per compile - which is also where the per-request merge went.
    my $reg = $self->{registry};
    my $ctable = eval { $reg->table }
        or Carp::croak('Maat::Router: no C tenant table - this build of '
                     . 'Maat has no dispatcher, and the Perl one it used '
                     . 'to fall back to was deleted when the C path took '
                     . 'over the cold cases too');
    $reg->{caps} = sub { $self->_caps_for($_[0]) };
    $self->{ctable} = $ctable;
    $reg->_table_refresh;

    # Challenges are answered for any host, so they live on the table
    # rather than behind a routing decision. Republished on every bundle.
    $reg->{on_challenges} = sub { $ctable->challenges($_[0]) };
    $reg->{on_aliases}    = sub { $ctable->aliases($_[0]) };
    $reg->_table_challenges;
    $reg->_table_aliases;

    return sub { Maat::Router::_c_dispatch($self, $_[0]) };
}

sub _caps_for {
    my ($self, $meta) = @_;
    my $plan   = defined $meta->{plan} ? $meta->{plan} : '';
    my $limits = $meta->{limits} || {};
    my %caps   = %{ $self->{defaults} };
    %caps = (%caps, %{ $self->{caps}{$plan} }) if $self->{caps}{$plan};
    # A per-tenant ceiling in the bundle (a future limits.concurrency)
    # wins over the plan default: the control plane knows more than the
    # worker does.
    $caps{concurrency} = $limits->{concurrency}
        if defined $limits->{concurrency};
    $caps{max_body} = $limits->{max_body}
        if defined $limits->{max_body};
    return \%caps;
}

# Per-tenant, keyed by proxy id only. The one place a caller reads the
# isolation counters; there is deliberately nothing finer-grained.
sub tenant_metrics {
    my ($self, $proxy) = @_;
    my $t  = $self->{ctable} or return defined $proxy ? undef : {};
    my $by = $t->by_proxy || {};
    return defined $proxy ? $by->{$proxy} : $by;
}

# In flight for one tenant, from the C table - the same store the
# ceiling is enforced against. It used to read a Perl hash that the Perl
# dispatch maintained; when that dispatch was deleted the hash stopped
# being written and this quietly answered 0 forever, which is the exact
# shape of the tenant_metrics bug and was hiding in the same file.
sub inflight {
    my ($self, $proxy) = @_;
    my $tm = $self->tenant_metrics($proxy) or return 0;
    return $tm->{inflight} || 0;
}

# ---- problem+json ----------------------------------------------------------

# ---- what the C dispatcher calls back for -----------------------------------
#
# Two functions, and neither is a second implementation of anything in
# mt_dispatch.h. That is the whole test for what may live here: if C
# could do it, C does it, and the Perl is deleted rather than kept as a
# fallback nobody exercises.

# A host this worker has never served. Compiling is Maat::Registry's job
# entire - fetch by digest, verify it, hold it to the budget, cache it
# under the LRU, poison it if it will not compile - and none of that
# belongs on a request path in C. Called once per host per version; every
# request after it is answered in C.
#
# Returns a scalar ref when the host is now published (C looks it up
# again and carries on), a response when this side answered it outright,
# or undef when nobody serves the host.
sub _c_miss {
    my ($self, $env) = @_;
    my $host = $env->{HTTP_HOST};
    return undef unless defined $host && length $host;

    my ($app, $meta) = $self->{registry}->resolve($host);
    return undef unless defined $app;

    # Published? Then C takes it from here.
    return \1 if $self->{ctable} && $self->{ctable}->lookup($host);

    # Not published, but resolvable: a portal tenant (whose /docs must be
    # rebuilt when its guides move, which is resolve's business) or a
    # poisoned host serving its 503. Answer it here, once, without
    # pretending the table knows about it.
    $self->{metrics}{routed}++;
    my $res = eval { $app->($env) };
    return _c_edge_502($self) unless $res;
    _c_mark($res, $meta->{proxy}, $meta->{version}) if ref $res eq 'ARRAY';
    return $res;
}

# A streamed responder or a future. The slot this request took is
# released when the response COMPLETES rather than when it is returned,
# and `$token` names the exact entry to release - not the host, which may
# have been republished under it in the meantime.
sub _c_async {
    my ($self, $res, $proxy, $version, $token) = @_;
    my $table = $self->{ctable};
    my $released = 0;
    my $release = sub {
        return if $released++;
        $table->done($token) if $table;
    };

    if (ref $res eq 'CODE') {
        return sub {
            my ($responder) = @_;
            my $ret = eval {
                $res->(sub {
                    my ($r) = @_;
                    _c_mark($r, $proxy, $version) if ref $r eq 'ARRAY';
                    return $responder->($r);
                });
            };
            $release->();
            die $@ if $@ && !$ret;
            return $ret;
        };
    }
    if (Scalar::Util::blessed($res) && $res->can('then')) {
        return $res->then(sub {
            my ($r) = @_;
            _c_mark($r, $proxy, $version) if ref $r eq 'ARRAY';
            $release->();
            return $r;
        }, sub {
            my ($e) = @_;
            $release->();
            die $e;
        });
    }

    # A shape neither C nor this recognises: give the slot back rather
    # than leak it, and hand it on untouched.
    $release->();
    return $res;
}

# The version markers, only when the tenant did not set its own - the
# same rule mt_stamp_tenant follows for the responses C completes.
sub _c_mark {
    my ($res, $proxy, $version) = @_;
    return unless ref $res eq 'ARRAY' && ref $res->[1] eq 'ARRAY';
    my $h = $res->[1];
    my ($have_v, $have_p);
    for (my $i = 0; $i < @$h; $i += 2) {
        my $k = lc($h->[$i] // '');
        $have_v = 1 if $k eq 'x-maat-version';
        $have_p = 1 if $k eq 'x-maat-proxy';
    }
    push @$h, 'X-Maat-Version', $version if !$have_v && defined $version;
    push @$h, 'X-Maat-Proxy',   $proxy   if !$have_p && $proxy;
    return;
}

sub _c_edge_502 {
    my ($self) = @_;
    $self->{metrics}{rejected}++;
    my $body = File::Raw::JSON::file_json_encode({
        type   => 'https://openapi-proxy.com/problem/edge',
        title  => 'Bad Gateway',
        status => 502,
        detail => 'the proxy for this host failed to produce a response',
    }, sort_keys => 1);
    return [ 502, [ 'Content-Type'   => 'application/problem+json',
                    'Content-Length' => length $body ], [ $body ] ];
}

1;

__END__

=head1 NAME

Maat::Router - the multi-tenant edge: host dispatch and isolation

=head1 SYNOPSIS

    my $router = Maat::Router->new(
        registry => $registry,
        caps     => { free => { concurrency => 16, max_body => '4M' } },
    );
    my $app = $router->to_app;      # a PSGI coderef for Hyperman->run

=head1 DESCRIPTION

One PSGI application in front of the whole fleet. It routes each request
to a tenant by its C<Host> header through L<Maat::Registry>, isolates
tenants from one another, and answers the edge's own two cases - an
unknown host and an ACME http-01 probe - without entering any tenant's
code path.

=head2 Routing

The C<Host> header (port stripped, lower-cased) is looked up in the
registry: a C<< <slug>.openapi-proxy.com >> tenant or a phase-7 custom
domain both resolve to their proxy's compiled app, compiled lazily on the
first request for that host. A host the registry does not serve is
answered C<404> C<application/problem+json> at the edge - no tenant is
resolved and no spec is compiled, so a scan or a stale edge map has zero
blast radius.

=head2 The ACME probe

C<GET /.well-known/acme-challenge/E<lt>tokenE<gt>> is answered from the
registry's challenge table for B<any> host, since Let's Encrypt probes a
domain over plain HTTP before its certificate exists. A known token
returns its key authorization as C<text/plain>; an unknown one is a bare
C<404>. This is the entire edge half of phase 7; the ACME protocol itself
runs in the control plane.

=head2 Isolation

Before a tenant app is entered, three caps drawn from its plan are
checked: a request body over C<max_body> is C<413>, request headers over
C<max_header_bytes> are C<431>, and a request past the tenant's
C<concurrency> ceiling is C<429>. The ceiling is the confinement that
matters: a tenant whose upstream hangs holds at most its own ceiling of
in-flight slots - given back exactly once when each response completes,
whether a triplet, a streamed responder or a future - so a hung upstream
cannot reduce a neighbour's throughput beyond its own ceiling. The caps
default to abuse ceilings a real client never meets; a plan may raise
them, and a per-tenant C<limits.concurrency> or C<limits.max_body> in the
bundle wins over the plan default.

=head2 Version attribution

Every response leaves with C<X-Maat-Version> and C<X-Maat-Proxy> (added
only when the tenant app did not set them), so under a live publish each
response is attributable to exactly one tenant and one spec version.

=head2 Metrics

Router-level aggregates (C<routed>, C<unknown>, C<rejected>,
C<acme_hit>/C<acme_miss>) plus the registry's, and per-tenant counters
keyed by B<proxy id alone> - requests and each rejection reason - so the
cardinality is the tenant count and nothing multiplies it.

=head1 METHODS

=head2 new(registry => $reg, caps => \%per_plan, default_caps => \%caps)

=head2 to_app

=head2 metrics / tenant_metrics($proxy?) / inflight($proxy)

=cut
