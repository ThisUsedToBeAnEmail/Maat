package Maat::Poller;

use 5.010;
use strict;
use warnings;
use Carp ();
use Digest::SHA ();
use Maat::Log ();
use File::Raw::JSON ();
use Scalar::Util ();

our $VERSION = '0.05';

# Config distribution, the data-plane end: pull the signed tenant bundle
# from the control plane and publish it into a Maat::Registry. POLL, not
# push, and the reason is the whole of this module's design - a poll
# cannot break in a way that silently stops updating. A push we stopped
# receiving looks exactly like a push with nothing to send; a poll that
# fails MOVES A COUNTER and keeps serving the last good bundle, so "we
# have not heard from the control plane in five minutes" is a number an
# operator can alert on rather than a silence nobody notices.
#
# Three properties, each a line below:
#
#   NEVER GO BLANK. A failed poll - a 5xx, a timeout, a torn body, a bad
#   signature - keeps the last good bundle. apply_bundle is called only
#   on a fresh, verified 200. The registry cannot be emptied by the
#   control plane having a bad minute.
#
#   VERIFY BEFORE APPLY. The bundle is signed with HMAC-SHA256 of its
#   body under the shared registry token (X-Maat-Bundle-Signature). A
#   body whose signature does not match is dropped and counted
#   bad_signature; a middlebox that mangled it, or anything that is not
#   the control plane, cannot install tenants.
#
#   304 IS CHEAP. The ETag is sent back as If-None-Match, so an unchanged
#   bundle is a 304 with no body to parse, verify or apply - counted
#   not_modified and nothing else.

sub new {
    my ($class, %o) = @_;
    my $reg = $o{registry}
        or Carp::croak('Maat::Poller: registry is required');
    my $url = $o{url}
        or Carp::croak('Maat::Poller: url is required (the /registry/bundle endpoint)');
    my $token = $o{token};
    Carp::croak('Maat::Poller: token is required (APIP_REGISTRY_TOKEN)')
        unless defined $token && length $token;

    my $self = bless {
        registry => $reg,
        url      => $url,
        token    => $token,
        interval => $o{interval} || 15,
        timeout  => $o{timeout}  || 10,

        # How one HTTP GET is made. Injectable so a test drives the whole
        # verify/apply path against an in-process stub without a socket;
        # production builds a Fetch-backed one lazily. Signature:
        #   ->($url, $etag) -> { status, headers => \%lc, body }
        fetch    => $o{fetch},

        etag     => undef,
        armed    => 0,
        last_ok  => undef,   # epoch of the last applied-or-304 poll
    }, $class;

    return $self;
}

sub registry { $_[0]{registry} }
sub etag     { $_[0]{etag} }
sub last_ok  { $_[0]{last_ok} }

# `apip revoke <key-id>` makes a revoked key stop working AT ONCE rather
# than at the next scheduled poll. Revocation itself happens at the
# control plane (the key vanishes from the bundle); the data plane's job
# is to notice immediately. So the running gateway installs a signal
# handler that forces one poll now, and `apip revoke` sends that signal
# to the gateway's pid. A poll picks up the bundle the control plane has
# already updated, so within one round trip the revoked key's hash is gone
# from the in-memory table and its next request is a 401.
#
# Safe (deferred) signals mean the handler runs at a Perl sequence point,
# not mid-op, so calling poll_once from it is safe; a failed poll can
# never take the process down, as poll_once already swallows its own
# errors. The default is SIGUSR1, a signal a gateway has no other use for.
sub install_revoke_signal {
    my ($self, $sig) = @_;
    $sig ||= 'USR1';
    $SIG{$sig} = sub { $self->poll_once };
    $self->{revoke_signal} = $sig;
    return $sig;
}

# The name for the immediate poll, so a caller (or a test) reads intent:
# `apip revoke` forces this, the loop timer runs the same poll_once on its
# interval.
sub poll_now { $_[0]->poll_once }

# One poll. Returns a short status string naming what happened, so a
# caller (or a test) can assert on it: 'applied', 'not_modified',
# 'bad_signature', 'bad_body', or 'error'. Every path that is not a
# clean apply keeps the last good bundle untouched.
sub poll_once {
    my ($self) = @_;
    my $res = eval { $self->_fetch->($self->{url}, $self->{etag}) };
    return $self->_apply($res);
}

# One poll WITHOUT blocking, for a worker that is on an event loop.
#
# This exists because the blocking one cannot be used there, and using it
# there took a production fleet down: `Fetch::Future->get` pumps the loop
# re-entrantly, so a poll made from inside a timer callback stops that
# worker serving until the fetch resolves - and if it never resolves, the
# worker never serves again. Every worker arms its own timer on its first
# request, so a fleet does not degrade, it stops: 200s for one interval,
# then nothing, with nothing in the log because nothing died.
#
# The synchronous path stays exactly as it was. It is the right shape for
# `apip-fleet check`, for the boot poll before any listener is bound, and
# for every test - none of which is on a loop.
sub poll_async {
    my ($self) = @_;

    # An injected fetcher is synchronous by contract (the tests', the
    # stub's), so honour it rather than pretending. Only the real
    # Fetch-backed path can be asynchronous.
    return $self->poll_once if $self->{fetch};

    my $ua = eval { $self->_ua } or return $self->poll_once;
    my %h = ('Authorization' => "Bearer $self->{token}");
    $h{'If-None-Match'} = qq{"$self->{etag}"} if defined $self->{etag};

    my $f = eval { $ua->get($self->{url}, headers => \%h) };
    if (!$f || !eval { $f->can('on_done') }) {
        $self->{registry}->metric('poll_fail');
        return undef;
    }

    $f->on_done(sub {
        my ($r) = @_;
        $self->_apply({ status  => eval { $r->status },
                        headers => _lc_headers(eval { $r->headers }),
                        body    => eval { $r->content } });
    });
    # A failed request is a failed poll and nothing more: the registry
    # keeps its last good bundle, which is the whole reason this is a
    # poll and not a push.
    $f->on_fail(sub { $self->{registry}->metric('poll_fail') });
    return undef;
}

# Everything after the fetch: verify, decode, publish, advance the tag.
# Shared by both paths so there is one implementation of what a bundle
# means, and only one implementation of what an unverified one means.
sub _apply {
    my ($self, $res) = @_;
    my $r = $self->_apply_inner($res);

    # Everything except not_modified, which is what a healthy fleet says
    # every interval on every worker - four workers on a fifteen-second
    # timer is a line every four seconds saying nothing happened. Proof
    # of life belongs in the counters, where `poll_ok` and `last_ok` say
    # it on demand; the log is for things that happened.
    Maat::Log->event(ev => 'poll', result => $r,
                     tenants => scalar keys %{ $self->{registry}{tenants} || {} })
        unless $r eq 'not_modified';
    return $r;
}

sub _apply_inner {
    my ($self, $res) = @_;
    my $reg = $self->{registry};

    if (!$res || ref $res ne 'HASH') {
        $reg->metric('poll_fail');
        return 'error';
    }

    my $status  = $res->{status} || 0;
    my $headers = $res->{headers} || {};

    if ($status == 304) {
        $reg->metric('poll_ok');
        $reg->metric('not_modified');
        $self->{last_ok} = time;
        return 'not_modified';
    }

    if ($status != 200) {
        # 401, 503, a network stumble the fetcher turned into a status:
        # keep the last good bundle, count it, and let the next tick try.
        $reg->metric('poll_fail');
        return 'error';
    }

    my $body = defined $res->{body} ? $res->{body} : '';

    # Verify before parse. A body we will not trust is not worth decoding.
    my $sig = $headers->{'x-maat-bundle-signature'};
    my $want = Digest::SHA::hmac_sha256_hex($body, $self->{token});
    if (!defined $sig || !_ct_eq($sig, $want)) {
        $reg->metric('bad_signature');
        $reg->metric('poll_fail');
        return 'bad_signature';
    }

    my $bundle = eval { File::Raw::JSON::file_json_decode($body) };
    if (!$bundle || ref $bundle ne 'HASH') {
        $reg->metric('poll_fail');
        return 'bad_body';
    }

    $reg->apply_bundle($bundle);
    # Only now is the ETag advanced: a bundle that failed to verify or
    # parse must not move the tag, or the next If-None-Match would 304 on
    # a bundle we never actually applied.
    my $etag = $headers->{etag};
    if (defined $etag) { $etag =~ s/\A"|"\z//g; $self->{etag} = $etag }
    $reg->metric('poll_ok');
    $self->{last_ok} = time;
    return 'applied';
}

# Constant-time string compare for the signature, matching the control
# plane's own compare on the token: a timing side channel on a signature
# check is cheap to close and embarrassing to leave open.
sub _ct_eq {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b;
    return 0 unless length $a == length $b;
    my $diff = 0;
    $diff |= ord(substr $a, $_, 1) ^ ord(substr $b, $_, 1)
        for 0 .. length($a) - 1;
    return $diff == 0 ? 1 : 0;
}

# Response headers, lower-cased, whatever shape they arrive in.
#
# Every shape matters and one of them cost a production afternoon:
# Fetch->get returns a Fetch::Headers, which IS a flat [k, v, ...] list
# but is BLESSED, so `ref $h eq 'ARRAY'` is false and a plain arrayref
# test silently produces no headers at all. The bundle then has no
# X-Maat-Bundle-Signature to check, poll_once reports `bad_signature`
# for a header it never read, and it does it with a perfectly correct
# token - which is the least debuggable failure this file can produce,
# since the operator is then staring at a shared secret that is right.
#
# reftype sees through the blessing; `pairs` is preferred when the
# object offers it, since that is the documented accessor and cannot be
# wrong about its own layout. A hashref is accepted too, because the
# injected fetchers the tests use return one - which is exactly why this
# path went unexercised until a real socket was on the other end.
sub _lc_headers {
    my ($h) = @_;
    my %lc;
    return \%lc unless defined $h && ref $h;

    if (Scalar::Util::blessed($h) && $h->can('pairs')) {
        my @pairs = $h->pairs;
        $lc{ lc $pairs[$_ * 2] } = $pairs[$_ * 2 + 1]
            for 0 .. int(@pairs / 2) - 1;
        return \%lc;
    }

    my $type = Scalar::Util::reftype($h) || '';
    if ($type eq 'ARRAY') {
        for (my $i = 0; $i < @$h; $i += 2) {
            $lc{ lc $h->[$i] } = $h->[$i + 1];
        }
    }
    elsif ($type eq 'HASH') {
        $lc{ lc $_ } = $h->{$_} for keys %$h;
    }
    return \%lc;
}

# The agent, shared by both paths and OWNED BY ONE PROCESS. Fetch keeps
# its connection pool on it, so a fresh agent per poll would mean a fresh
# TLS handshake to the control plane every interval - and a SHARED one
# across a fork is worse than either. See forget_agent.
sub _ua {
    my ($self) = @_;
    return $self->{ua} if $self->{ua};
    require Fetch;

    # On a Hyperman worker the agent MUST share the worker's loop. A
    # loop-less Fetch runs on its own standalone loop, which is pumped
    # only inside a blocking ->get - so a fire-and-forget future there
    # never completes, and its request is never even sent; and a
    # blocking ->get inside a worker pumps HYPERMAN's loop while the
    # request's fd sits on the standalone one, which is a wedge, not a
    # wait. Hyperman->loop answers only inside a worker, so everywhere
    # else (the boot poll in the parent, apip-fleet check, the tests)
    # this stays a plain standalone agent whose blocking get works.
    my $loop = eval { Hyperman->loop };
    $self->{pid} = $$;
    return $self->{ua} = Fetch->new(timeout => $self->{timeout},
                                    ($loop ? (loop => $loop) : ()));
}

# Drop the agent, and anything built over it, so the next poll opens its
# own connection.
#
# This is a fork-safety rule, and the fleet is exactly the shape that
# needs it: the boot poll runs in the parent - deliberately, so that
# every worker starts with a full tenant table - and leaves a live
# keep-alive TLS connection on the agent. Hyperman then forks, and every
# worker inherits that same socket. Left alone, all of them poll down one
# connection, interleaving writes into a single TLS session, and nothing
# on it ever completes again.
#
# An INJECTED fetcher is never dropped: it belongs to whoever injected it
# (a test, a stub) and has no socket of its own to be confused about.
sub forget_agent {
    my ($self) = @_;
    delete $self->{ua};
    if ($self->{fetch_built}) {
        delete $self->{fetch};
        delete $self->{fetch_built};
    }
    delete $self->{pid};
    return;
}

# The production fetcher, built once on first use. A GET with the bearer
# token and, when we hold one, If-None-Match.
sub _fetch {
    my ($self) = @_;
    return $self->{fetch} if $self->{fetch};

    my $ua = $self->_ua;
    $self->{fetch_built} = 1;
    $self->{fetch} = sub {
        my ($url, $etag) = @_;
        my %h = ('Authorization' => "Bearer $self->{token}");
        $h{'If-None-Match'} = qq{"$etag"} if defined $etag;
        my $r = $ua->get($url, headers => \%h)->get;
        return {
            status  => $r->status,
            headers => _lc_headers($r->headers),
            body    => $r->content,
        };
    };
    return $self->{fetch};
}

# Drive the poll on the worker's own event loop, once, if there is one -
# the same shape Maat::Gateway->arm uses, and for the same reason: off a
# loop Hyperman->timer would block, and on one it must not. A caller with
# no loop just calls poll_once on whatever schedule it likes.
sub arm {
    my ($self, $env) = @_;
    return 0 if $self->{armed};
    return 0 unless $env && $env->{'psgix.loop'};

    # First thing, and the reason is the fork. arm() runs inside a worker,
    # after Hyperman has forked from a parent that already polled once -
    # so whatever agent this object is holding belongs to that parent and
    # its socket is shared with every sibling. This worker gets its own.
    $self->forget_agent if !defined $self->{pid} || $self->{pid} != $$;

    my $tick;
    $tick = sub {
        # Asynchronous, always: this runs ON the worker's loop, and a
        # blocking await here stops the worker serving for as long as the
        # fetch takes - forever, if it never resolves. The timer is
        # re-armed immediately rather than after the response, so a slow
        # control plane delays a bundle, never the next tick.
        # `last_attempt` is stamped here too, so the traffic-driven
        # fallback (poll_if_stale) sees a working timer as recent and never
        # double-polls behind it.
        $self->{last_attempt} = time;
        eval { $self->poll_async };           # a poll can never take the loop down
        my $f = eval { Hyperman->timer($self->{interval}) } or return;
        $f->on_done($tick);
        return;
    };
    my $ok = eval {
        require Hyperman;
        my $f = Hyperman->timer($self->{interval});
        $f->on_done($tick);
        1;
    };
    $self->{armed} = $ok ? 1 : 0;
    return $self->{armed};
}

# A poll driven by traffic, as a fallback for a worker whose timer never
# fires. arm() sets up a Hyperman->timer, but a worker loop that did not
# survive the fork leaves that timer silent - and then only a restart's
# boot poll ever updates the bundle, so a freshly published tenant (a
# pasted mock, a new proxy) 404s until the process is replaced. This keeps
# a worker that is TAKING requests from going stale: at most one poll per
# interval, only on a real loop, and off the same `last_attempt` clock the
# timer stamps, so the two never poll on top of each other. When the timer
# works this never fires; when it does not, traffic carries the fleet.
sub poll_if_stale {
    my ($self, $env) = @_;
    return unless $env && $env->{'psgix.loop'};
    my $now = time;
    return if $now < ($self->{last_attempt} || 0) + $self->{interval};
    $self->{last_attempt} = $now;
    eval { $self->poll_async };
    return;
}

1;

__END__

=head1 NAME

Maat::Poller - pull the signed tenant bundle and publish it

=head1 SYNOPSIS

    my $poller = Maat::Poller->new(
        registry => $registry,
        url      => 'https://openapi-proxy.com/registry/bundle',
        token    => $ENV{APIP_REGISTRY_TOKEN},
        interval => 15,
    );

    $poller->poll_once;     # verify + apply one bundle (returns a status word)
    $poller->arm($env);     # or drive it on the worker's event loop

=head1 DESCRIPTION

The config-distribution client. It GETs C<< /registry/bundle >> with the
bundle's ETag as C<If-None-Match>, verifies the C<X-Maat-Bundle-Signature>
HMAC against the shared registry token, and publishes the result into a
L<Maat::Registry> with C<apply_bundle>.

Poll, not push. A push that stopped arriving is indistinguishable from
one with nothing to send; a poll that fails moves C<poll_fail> and keeps
the last good bundle, so a control plane having a bad minute cannot blank
a worker's tenant table, and "no successful poll in N seconds" is a
number to alert on.

=head2 What each poll can do

=over 4

=item * B<200, signature good> - the bundle is decoded and published;
the ETag advances; C<poll_ok> moves. Returns C<'applied'>.

=item * B<304> - nothing changed; nothing is parsed or applied.
C<poll_ok> and C<not_modified> move. Returns C<'not_modified'>.

=item * B<200, signature bad> - dropped, last good bundle kept.
C<bad_signature> and C<poll_fail> move. Returns C<'bad_signature'>.

=item * B<200, body will not decode> - dropped, last good bundle kept.
C<poll_fail> moves. Returns C<'bad_body'>.

=item * B<401 / 503 / a network error> - dropped, last good bundle kept.
C<poll_fail> moves. Returns C<'error'>.

=back

The ETag is advanced B<only> on a clean apply, so a bundle that failed to
verify or parse can never cause the next C<If-None-Match> to 304 over a
bundle that was never installed.

=head1 METHODS

=head2 new(registry => $reg, url => $url, token => $token, interval => 15, timeout => 10, fetch => \&code)

C<fetch> overrides the HTTP client for testing: a coderef
C<< ($url, $etag) -> { status, headers => \%lowercased, body } >>. Without
it, a L<Fetch> agent is built on first use.

=head2 poll_once

Make one poll; verify and publish on a fresh 200. Returns the status
word above.

=head2 arm($env) / registry / etag / last_ok

C<arm> schedules C<poll_once> on the worker's C<psgix.loop> every
C<interval> seconds, once; it is a no-op off a loop. C<last_ok> is the
epoch of the last 200-or-304, the freshness an alert watches.

=head2 install_revoke_signal($sig?) / poll_now

C<install_revoke_signal> installs a handler (C<SIGUSR1> by default) that
forces one C<poll_once> when the signal arrives, and returns the signal
name. This is how C<apip revoke> makes a revoked key stop working at once:
revocation happens at the control plane (the key vanishes from the
bundle), and the signal forces the running gateway to pull the updated
bundle now rather than at the next scheduled poll. C<poll_now> is a name
for that immediate poll, the same C<poll_once> the interval timer runs.

=cut
