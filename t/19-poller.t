use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;
use Digest::SHA ();

use Maat::Registry;
use Maat::Poller;

# The config-distribution client: verify-before-apply, 304 on an
# unchanged bundle, and - the property the whole poll-not-push choice
# exists for - never going blank on a failed poll.

sub build {
    my (%o) = @_;
    my $stub = RegistryStub->new(token => 'secret-token');
    $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    my $poller = Maat::Poller->new(
        registry => $reg,
        url      => 'http://control/registry/bundle',
        token    => 'secret-token',
        fetch    => $o{fetch} || $stub->fetcher,
    );
    return ($stub, $reg, $poller);
}

# ---- a clean apply, then a 304 --------------------------------------------

{
    my ($stub, $reg, $poller) = build();
    is $poller->poll_once, 'applied', 'first poll applies the bundle';
    is scalar @{ $reg->hosts }, 1, 'the tenant is now in the registry';
    ok defined $poller->etag, 'the ETag was recorded';

    is $poller->poll_once, 'not_modified',
        'an unchanged bundle is a 304 (If-None-Match earns its keep)';
    is $reg->metrics->{not_modified}, 1, 'the 304 is counted';
    is $reg->metrics->{poll_ok}, 2, 'both polls counted as ok';
}

# ---- a change is picked up -------------------------------------------------

{
    my ($stub, $reg, $poller) = build();
    $poller->poll_once;
    $stub->add_tenant(host => 'b.openapi-proxy.com', proxy => 2,
        spec => RegistryStub->tenant_spec(2));
    is $poller->poll_once, 'applied', 'a changed bundle applies again';
    is scalar @{ $reg->hosts }, 2, 'the new tenant is now served';
}

# ---- a bad signature keeps the last good bundle ---------------------------

{
    my ($stub, $reg, $poller) = build();
    $poller->poll_once;                       # good bundle in place
    my $good_hosts = scalar @{ $reg->hosts };

    # A fetcher that returns a 200 whose signature is wrong (a different
    # token signed it, or a middlebox mangled the body).
    my $forged = sub {
        my $r = $stub->bundle_response(undef);
        $r->{headers}{'x-maat-bundle-signature'} = 'deadbeef' x 8;
        return $r;
    };
    $poller->{fetch} = $forged;
    # force a fresh 200 rather than a 304
    $poller->{etag} = undef;

    is $poller->poll_once, 'bad_signature', 'a forged bundle is rejected';
    is $reg->metrics->{bad_signature}, 1, 'a bad signature is counted';
    is scalar @{ $reg->hosts }, $good_hosts,
        'the last good bundle is kept - the registry never goes blank';
}

# ---- a torn body keeps the last good bundle -------------------------------

{
    my ($stub, $reg, $poller) = build();
    $poller->poll_once;
    my $good_hosts = scalar @{ $reg->hosts };

    my $torn = sub {
        my $body = '{ this is not json';
        return {
            status  => 200,
            headers => {
                etag => '"whatever"',
                'x-maat-bundle-signature' =>
                    Digest::SHA::hmac_sha256_hex($body, 'secret-token'),
            },
            body => $body,
        };
    };
    $poller->{fetch} = $torn;
    $poller->{etag}  = undef;
    is $poller->poll_once, 'bad_body', 'a body that will not decode is rejected';
    is scalar @{ $reg->hosts }, $good_hosts, 'the last good bundle is kept';
}

# ---- a 5xx / 401 keeps the last good bundle -------------------------------

{
    my ($stub, $reg, $poller) = build();
    $poller->poll_once;
    my $good_hosts = scalar @{ $reg->hosts };

    $poller->{fetch} = sub { { status => 503, headers => {}, body => '' } };
    is $poller->poll_once, 'error', 'a 503 from the control plane is an error';
    is $reg->metrics->{poll_fail}, 1, 'the failed poll is counted';
    is scalar @{ $reg->hosts }, $good_hosts, 'the registry still serves the last good bundle';

    $poller->{fetch} = sub { die "connection refused\n" };
    is $poller->poll_once, 'error', 'a thrown network error is an error, not a crash';
    is scalar @{ $reg->hosts }, $good_hosts, 'still not blank after a network error';
}

# ---- the ETag only advances on a clean apply ------------------------------

{
    my ($stub, $reg, $poller) = build();
    $poller->poll_once;
    my $etag = $poller->etag;

    # A forged 200 must not move the ETag, or the next If-None-Match would
    # 304 over a bundle that was never applied.
    $poller->{fetch} = sub {
        my $r = $stub->bundle_response(undef);
        $r->{headers}{'x-maat-bundle-signature'} = 'bad' x 20;
        $r->{headers}{etag} = '"a-new-etag"';
        return $r;
    };
    $poller->{etag} = undef;
    $poller->poll_once;
    isnt $poller->etag, 'a-new-etag', 'a rejected bundle does not advance the ETag';
}

# ---- the header shapes a real Fetch actually returns -----------------------
#
# The regression this file was missing, and it cost a production
# afternoon: every test above injects a `fetch` that returns headers as a
# plain hashref, so _fetch - the only code path a real socket takes - was
# never exercised. Fetch->get returns a Fetch::Headers, which is a flat
# [k, v, ...] list but BLESSED, and the old `ref $h eq 'ARRAY'` test is
# false for a blessed arrayref. Result: no headers at all, no signature
# to check, and `bad_signature` reported on every poll with a completely
# correct token - a shared secret the operator can prove is right.

subtest 'response headers are normalised whatever shape they arrive in' => sub {
    my $want = { 'x-maat-bundle-signature' => 'abc', etag => '"v1"' };

    is_deeply Maat::Poller::_lc_headers(
        [ 'X-Maat-Bundle-Signature' => 'abc', 'ETag' => '"v1"' ]),
        $want, 'a plain arrayref of pairs';

    is_deeply Maat::Poller::_lc_headers(
        { 'X-Maat-Bundle-Signature' => 'abc', 'ETag' => '"v1"' }),
        $want, 'a hashref - what the injected fetchers in this file return';

    is_deeply Maat::Poller::_lc_headers(
        bless([ 'X-Maat-Bundle-Signature' => 'abc', 'ETag' => '"v1"' ],
              'Some::Headers')),
        $want, 'a BLESSED arrayref - Fetch::Headers, and the one that broke';

    # And the documented accessor, when the object offers it.
    {
        package Test::Headers::WithPairs;
        sub new   { bless { p => $_[1] }, $_[0] }
        sub pairs { @{ $_[0]{p} } }
    }
    is_deeply Maat::Poller::_lc_headers(
        Test::Headers::WithPairs->new(
            [ 'X-Maat-Bundle-Signature' => 'abc', 'ETag' => '"v1"' ])),
        $want, 'an object with pairs()';

    is_deeply Maat::Poller::_lc_headers(undef), {}, 'nothing at all is empty';

    # The consequence, stated where somebody will read it: an empty
    # header set is indistinguishable from a forged bundle, so getting
    # this wrong cannot be diagnosed from the status word.
    my ($stub, $reg, $poller) = build();
    $poller->{fetch} = sub {
        my $r = $stub->bundle_response(undef);
        return { %$r, headers => {} };
    };
    is $poller->poll_once, 'bad_signature',
        'headers that never arrived look exactly like a bad signature';
};

# Fetch::Headers itself, when it is installed - the real shape, not a
# stand-in for it. Skipped rather than required: Fetch is a prerequisite
# of this distribution, but the class arrived in 0.09.
subtest 'the real Fetch::Headers' => sub {
    plan skip_all => 'Fetch::Headers 0.09+ is not installed'
        unless eval { require Fetch::Headers; Fetch::Headers->can('new') };

    my $h = Fetch::Headers->new('X-Maat-Bundle-Signature' => 'abc',
                                'ETag' => '"v1"');
    is_deeply Maat::Poller::_lc_headers($h),
        { 'x-maat-bundle-signature' => 'abc', etag => '"v1"' },
        'a Fetch::Headers normalises to the same lower-cased hash';
};

# ---- the poll must never block the worker it runs on -----------------------
#
# The bug this pins took a live fleet down completely, and quietly.
# Maat::Poller->arm runs on the worker's event loop, and poll_once awaits
# with Fetch::Future->get, which pumps that loop re-entrantly - so a poll
# from inside the timer callback stops the worker serving until the fetch
# resolves, and forever if it does not. Every worker arms its own timer
# on its first request, so the fleet served 200s for one interval and
# then nothing, with an empty log, because nothing had died.

subtest 'the timer path is asynchronous' => sub {
    my ($stub, $reg, $poller) = build();

    # With no injected fetcher, the async path builds a real request and
    # hands back futures rather than awaiting. A fake agent stands in for
    # Fetch so the shape is asserted without a socket.
    delete $poller->{fetch};
    my $done;
    $poller->{ua} = FakeUA->new(sub {
        my ($url, %args) = @_;
        like $url, qr{/registry/bundle\z}, 'it asks for the bundle';
        like $args{headers}{Authorization}, qr/\ABearer secret-token\z/,
            '...with the token';
        return FakeFuture->new;
    });

    my $ret = $poller->poll_async;
    is $ret, undef,
        'poll_async returns nothing to wait on - the caller is a timer '
      . 'callback on the worker loop, and anything it waited for would be '
      . 'the worker not serving';

    # The response is handled when it arrives, off the request path.
    my $stub_res = $stub->bundle_response(undef);
    $poller->{ua}{last}->resolve(FakeRes->new($stub_res));
    is scalar @{ $reg->hosts }, 1, 'and the bundle applies when it does';
};

subtest 'the agent is never shared across a fork' => sub {
    # The boot poll runs in the parent, on purpose, so every worker starts
    # with a full tenant table - and it leaves a live keep-alive TLS
    # connection on the agent. Hyperman forks. Without this, every worker
    # polls down that one inherited socket, interleaving writes into a
    # single TLS session, and nothing on it completes again: the fleet
    # serves for one interval and then stops, with an empty log.
    my ($stub, $reg, $poller) = build();
    delete $poller->{fetch};

    $poller->{ua}  = 'the parent\'s agent';
    $poller->{pid} = $$ - 1;                 # as an inherited one looks
    $poller->{fetch} = sub { }; $poller->{fetch_built} = 1;

    $poller->forget_agent if $poller->{pid} != $$;
    ok !exists $poller->{ua}, 'a worker drops the agent it inherited';
    ok !exists $poller->{fetch},
        '...and the fetcher built over it, so the next poll dials its own';

    # An injected fetcher belongs to whoever injected it and has no
    # socket to be confused about.
    my ($s2, $r2, $p2) = build();
    my $injected = $p2->{fetch};
    $p2->{ua} = 'x';
    $p2->forget_agent;
    is $p2->{fetch}, $injected, 'an injected fetcher survives';
    ok !exists $p2->{ua}, '...while the agent still goes';
};

subtest 'an injected fetcher stays synchronous' => sub {
    # The tests, `apip-fleet check` and the boot poll are all off-loop and
    # want the answer before continuing. Only the loop needs the other
    # shape, so an injected fetcher keeps the simple one.
    my ($stub, $reg, $poller) = build();
    is $poller->poll_async, 'applied',
        'with a fetcher injected, poll_async is poll_once';
};

subtest 'traffic keeps a worker fresh when its timer never fires' => sub {
    # The failure this guards: a worker whose arm() timer is silent (a loop
    # that did not survive the fork) never re-polls, so a newly published
    # tenant 404s until a restart's boot poll. poll_if_stale lets traffic
    # carry the fleet - one poll per interval, only on a loop.
    my ($stub, $reg, $poller) = build();
    my $loop = { 'psgix.loop' => 1 };

    # off a loop, it never polls (the boot poll and tests are off-loop)
    $poller->poll_if_stale({});
    is scalar @{ $reg->hosts }, 0, 'no loop, no traffic-driven poll';

    # a worker taking requests applies the current bundle
    $poller->poll_if_stale($loop);
    is scalar @{ $reg->hosts }, 1, 'a request on a loop applies the bundle';

    # a new tenant is published to the control plane...
    $stub->add_tenant(host => 'b.openapi-proxy.com', proxy => 2,
        spec => RegistryStub->tenant_spec(2));

    # ...but a second request within the interval does NOT re-poll
    $poller->poll_if_stale($loop);
    is scalar @{ $reg->hosts }, 1, 'bounded to one poll per interval';

    # once the interval has passed, traffic picks it up - no restart needed
    $poller->{last_attempt} -= $poller->{interval} + 1;
    $poller->poll_if_stale($loop);
    is scalar @{ $reg->hosts }, 2,
        'the next interval of traffic picks up the new tenant';
};

done_testing;

# ---- doubles ---------------------------------------------------------------

{
    package FakeUA;
    sub new { my ($c, $cb) = @_; bless { cb => $cb }, $c }
    sub get {
        my ($self, $url, %args) = @_;
        return $self->{last} = $self->{cb}->($url, %args);
    }

    # Enough of a future for the poller: on_done/on_fail, and a resolve
    # that fires what was registered.
    package FakeFuture;
    sub new     { bless { done => [], fail => [] }, shift }
    sub can     { my ($s, $m) = @_;
                  return $m =~ /\Aon_(?:done|fail)\z/ ? sub { 1 } : undef }
    sub on_done { push @{ $_[0]{done} }, $_[1]; $_[0] }
    sub on_fail { push @{ $_[0]{fail} }, $_[1]; $_[0] }
    sub resolve { my ($s, $v) = @_; $_->($v) for @{ $s->{done} }; return }

    package FakeRes;
    sub new     { my ($c, $r) = @_; bless { r => $r }, $c }
    sub status  { $_[0]{r}{status} }
    sub content { $_[0]{r}{body} }
    # A blessed arrayref, exactly as Fetch::Headers is - the shape that
    # broke the header parse.
    sub headers { my $h = $_[0]{r}{headers};
                  bless [ map { ($_ => $h->{$_}) } sort keys %$h ],
                        'Fake::Headers' }
}
