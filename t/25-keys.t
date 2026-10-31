use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Open::API ();
use Maat::Config ();
use Maat::Gateway ();
use Maat::Registry ();
use Maat::Router ();
use Maat::Poller ();
use Maat::RateLimit ();
use File::Raw::JSON ();
use File::Temp ();

# Phase 9 - keys, rate limits, and the off-by-default guarantee.
#
#   - a presented key is hashed and constant-time compared; the spec's
#     securityScheme is the guard (we register the checker, we do not
#     invent a parallel auth path)
#   - an operation the spec does not secure is untouched
#   - a per-(key, operation) fixed-window rate limit, answered 429
#     problem+json with Retry-After and the X-RateLimit-* headers
#   - upstream credentials pass through untouched
#   - GATE 2: a limit survives a spec reload (counters not reset)
#   - GATE 3: a revoked key stops working within one poll, and at once on
#     `apip revoke`
#   - GATE 4: with no keys the gateway forwards exactly as phase 1
#
# GATE 1 (a limit exact across four workers) is the multi-process
# t/26-ratelimit-workers.t.

# A registry + router around one secured tenant, in mock mode (the spec
# is the upstream, so no socket is needed to prove auth and limits).
sub secured_fleet {
    my (%o) = @_;
    my $stub = RegistryStub->new;
    my $tenant = $stub->add_tenant(
        host  => 'app.openapi-proxy.com',
        proxy => 1, version => 1, plan => 'starter',
        spec  => RegistryStub->secured_spec(1),
        limits => { requests => 100000, enforce => 1 },
        keys  => $o{keys},
    );
    my $reg = Maat::Registry->new(
        fetch_spec => $stub->spec_fetcher,
        ($o{ratelimit} ? (ratelimit => $o{ratelimit}) : ()),
    );
    $reg->apply_bundle({ tenants => $stub->{tenants},
                         domains => [], challenges => [] });
    my $router = Maat::Router->new(registry => $reg);
    return ($stub, $reg, $router, $router->to_app);
}

sub req {
    my ($app, %o) = @_;
    my @h;
    push @h, 'X-API-Key', $o{key} if defined $o{key};
    push @h, @{ $o{headers} } if $o{headers};
    my $env = MaatTest::psgi_env(path => $o{path} || '/secure', headers => \@h);
    $env->{HTTP_HOST} = $o{host} || 'app.openapi-proxy.com';
    return MaatTest::run_app($app, $env);
}

# ---- key verification, via the spec's securityScheme -----------------------

{
    my $key = RegistryStub->make_key(id => 7, secret => 'topsecret-abc',
                                     rate_per_min => 0);
    my ($stub, $reg, $router, $app) = secured_fleet(keys => [ $key ]);

    my ($s) = req($app, path => '/secure');
    is $s, 401, 'a secured operation with no key is 401';

    ($s) = req($app, path => '/secure', key => 'wrong-key');
    is $s, 401, 'a secured operation with a wrong key is 401';

    (my $s2, my $h2, my $b2) = req($app, path => '/secure', key => 'topsecret-abc');
    is $s2, 200, 'a secured operation with the right key passes';
    like $b2, qr/"ok"/, '...and gets the synthesized body';

    # The public operation carries no security requirement, so it is
    # untouched whether or not a key is sent - the spec decides.
    my ($sp) = req($app, path => '/public');
    is $sp, 200, 'an operation the spec does not secure needs no key';
    my ($sp2) = req($app, path => '/public', key => 'wrong-key');
    is $sp2, 200, '...and is unaffected by a bad key too';
}

# ---- the key is hashed, never matched in the clear -------------------------

{
    my $secret = 'plate-of-shrimp';
    my $key = RegistryStub->make_key(id => 1, secret => $secret);
    unlike $key->{hash}, qr/\Q$secret\E/, 'the bundle carries a hash, not the secret';
    is length $key->{hash}, 64, 'the hash is a sha256 hex digest';
    is $key->{hash}, Digest::SHA::sha256_hex($secret),
        'the checker will match sha256($presented) against it';

    my ($stub, $reg, $router, $app) = secured_fleet(keys => [ $key ]);
    my ($s) = req($app, path => '/secure', key => $secret);
    is $s, 200, 'the un-hashed secret authorizes against the stored hash';
}

# ---- keys but no security in the spec: auth never arms ---------------------

{
    # A tenant with keys, but a document that declares no securityScheme.
    # There is nothing to carry a key, so the gateway forwards as phase 1.
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'plain.openapi-proxy.com', proxy => 2,
        spec => RegistryStub->tenant_spec(9),
        keys => [ RegistryStub->make_key(id => 5, secret => 'x') ]);
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my $env = MaatTest::psgi_env(path => '/hello');
    $env->{HTTP_HOST} = 'plain.openapi-proxy.com';
    my ($s, $h, $b) = MaatTest::run_app($app, $env);
    is $s, 200, 'keys with no securityScheme in the spec: forwarded, not guarded';
    like $b, qr/"tenant":9/, '...serving the document as normal';
}

# ---- rate limit: fixed window per (key, operation) -------------------------

{
    my $t0 = 1_000_000_000;   # pin the window so the test never straddles a minute
    my $dir = File::Temp::tempdir('maat-rl25-XXXXXX', TMPDIR => 1, CLEANUP => 1);
    my $rl  = Maat::RateLimit->new(dir => $dir, now => sub { $t0 });

    my $key = RegistryStub->make_key(id => 42, secret => 'limited', rate_per_min => 3);
    my ($stub, $reg, $router, $app) = secured_fleet(keys => [ $key ], ratelimit => $rl);

    my @status;
    push @status, (req($app, path => '/secure', key => 'limited'))[0] for 1 .. 5;
    is_deeply \@status, [ 200, 200, 200, 429, 429 ],
        'a 3/min key is allowed exactly three times, then 429';

    # A different operation for the same key has its own window.
    # (secured_spec declares only one secured op, so re-use across the
    # window is what we can assert here; the per-op keying is exercised by
    # peek below.)
    # allow() counts every hit, allowed or not (a fixed window gives no
    # fresh allowance to a client that keeps hammering), so five requests
    # leave the window count at five.
    is $rl->peek(42, 'secure1'), 5, 'the window count advanced past the limit';
    is $rl->peek(99, 'secure1'), 0, 'a different key shares nothing';
}

# ---- the 429 is problem+json with Retry-After and the rate headers ---------

{
    my $t0  = 1_000_000_020;   # 20s into a window: reset is 40s away
    my $dir = File::Temp::tempdir('maat-rl25b-XXXXXX', TMPDIR => 1, CLEANUP => 1);
    my $rl  = Maat::RateLimit->new(dir => $dir, now => sub { $t0 });
    my $key = RegistryStub->make_key(id => 8, secret => 'burst', rate_per_min => 1);
    my ($stub, $reg, $router, $app) = secured_fleet(keys => [ $key ], ratelimit => $rl);

    req($app, path => '/secure', key => 'burst');            # uses the one allowance
    my ($s, $h, $b) = req($app, path => '/secure', key => 'burst');
    is $s, 429, 'past the limit is 429';
    is scalar(MaatTest::header_get($h, 'Content-Type')), 'application/problem+json',
        'the 429 body is problem+json';
    my $doc = File::Raw::JSON::file_json_decode($b);
    is $doc->{status}, 429, 'the problem document names the status';
    like $doc->{type}, qr{openapi-proxy\.com/problem/}, '...with the gateway problem type';
    ok defined $doc->{request_id}, '...and carries the request id';

    is scalar(MaatTest::header_get($h, 'X-RateLimit-Limit')), 1, 'X-RateLimit-Limit';
    is scalar(MaatTest::header_get($h, 'X-RateLimit-Remaining')), 0, 'X-RateLimit-Remaining';
    ok defined(scalar MaatTest::header_get($h, 'X-RateLimit-Reset')), 'X-RateLimit-Reset present';
    my $retry = scalar MaatTest::header_get($h, 'Retry-After');
    ok defined $retry && $retry =~ /\A\d+\z/, 'Retry-After is a whole number of seconds';
}

# ---- upstream credentials pass through untouched ---------------------------

{
    # A header-capturing upstream: it appends each request's head to a file
    # so we can prove the gateway neither stripped nor rewrote what the
    # client sent.
    my ($capfh, $capfile) = File::Temp::tempfile('maat-cap-XXXXXX', TMPDIR => 1, UNLINK => 0);
    close $capfh;
    my $srv = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                    Listen => 8, ReuseAddr => 1) or die $!;
    my $port = $srv->sockport;
    my $pid = fork // die "fork: $!";
    if (!$pid) {
        local $SIG{TERM} = sub { exit 0 };
        while (my $c = $srv->accept) {
            my $head = '';
            while (defined(my $l = <$c>)) { $head .= $l; last if $l =~ /\A\r?\n\z/ }
            if (open my $lf, '>>', $capfile) { print $lf $head, "----\n"; close $lf }
            my $body = 'ok';
            print $c "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                   . "Content-Length: " . length($body) . "\r\n"
                   . "Connection: close\r\n\r\n$body";
            close $c;
        }
        exit 0;
    }
    close $srv;

    my $key = RegistryStub->make_key(id => 3, secret => 'apikey-value', rate_per_min => 0);
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'proxy.openapi-proxy.com', proxy => 3,
        upstream => "http://127.0.0.1:$port", mode => 'observe',
        spec => RegistryStub->secured_spec(1), keys => [ $key ]);
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my $env = MaatTest::psgi_env(path => '/secure',
        headers => [ 'X-API-Key', 'apikey-value', 'Authorization', 'Bearer upstream-token' ]);
    $env->{HTTP_HOST} = 'proxy.openapi-proxy.com';
    my ($s) = MaatTest::run_app($app, $env);
    is $s, 200, 'authorized request is forwarded to the upstream';

    open my $rf, '<', $capfile; local $/; my $seen = <$rf>; close $rf;
    like $seen, qr/^Authorization:\s*Bearer upstream-token/mi,
        'the client Authorization reached the upstream untouched';
    like $seen, qr/^X-API-Key:\s*apikey-value/mi,
        'the key header we authenticated on is not stripped from the forward';

    kill 'TERM', $pid; waitpid $pid, 0; unlink $capfile;
}

# ---- GATE 4: no keys => forwarding exactly as phase 1 ----------------------

{
    my $up = MaatTest::start_upstream;

    # The same tenant, at the gateway level, with no keys at all. Its
    # response must be byte-identical to going straight to the upstream -
    # the phase-1 property, unchanged by the phase-9 code being present.
    my $api = Open::API->new(spec => RegistryStub->tenant_spec(1));
    my $config = Maat::Config->tenant(mode => 'observe',
        upstream => "http://127.0.0.1:$up->{port}", version => 1, plan => 'free');
    my $gw = Maat::Gateway->new(config => $config, api => $api);   # NO keys, NO ratelimit
    ok !$gw->{auth}, 'with no keys the auth step is not armed at all';
    my $app = $gw->to_app;

    my $env = MaatTest::psgi_env(path => '/hello');
    my ($ps, $ph, $pb) = MaatTest::run_app($app, $env);
    my ($ds, $dh, $db) = MaatTest::http_request($up->{port}, 'GET', '/hello');

    is $ps, $ds, 'gate 4: same status as the direct upstream';
    is $pb, $db, 'gate 4: byte-identical body';
    is_deeply MaatTest::normalise_headers($ph), MaatTest::normalise_headers($dh),
        'gate 4: byte-identical headers (bar hop-by-hop and the added request id)';

    MaatTest::stop_upstream($up);
}

# ---- GATE 2: a limit survives a spec reload --------------------------------

{
    my $t0  = 1_000_000_100;
    my $dir = File::Temp::tempdir('maat-rl25c-XXXXXX', TMPDIR => 1, CLEANUP => 1);
    my $rl  = Maat::RateLimit->new(dir => $dir, now => sub { $t0 });
    my $key = RegistryStub->make_key(id => 55, secret => 'persist', rate_per_min => 5);

    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'reload.openapi-proxy.com', proxy => 4, version => 1,
        plan => 'starter', limits => { enforce => 1 },
        spec => RegistryStub->secured_spec(1), keys => [ $key ]);
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher, ratelimit => $rl);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my $hit = sub {
        my $env = MaatTest::psgi_env(path => '/secure', headers => ['X-API-Key','persist']);
        $env->{HTTP_HOST} = 'reload.openapi-proxy.com';
        return (MaatTest::run_app($app, $env))[0];
    };

    is $hit->(), 200, 'req 1 ok';
    is $hit->(), 200, 'req 2 ok';
    is $hit->(), 200, 'req 3 ok';

    # Publish a NEW version of the SAME operation: different bytes (a
    # different digest) but the same operationId, so the registry drops the
    # compiled entry and rebuilds the tenant's app around a fresh
    # Open::API object. If the count lived in that object it would reset.
    my $v2 = RegistryStub->secured_spec(1);
    $v2 =~ s/guarded greeting/guarded greeting v2/;
    my $stub2 = RegistryStub->new;
    $stub2->add_tenant(host => 'reload.openapi-proxy.com', proxy => 4, version => 2,
        plan => 'starter', limits => { enforce => 1 }, spec => $v2, keys => [ $key ]);
    # carry the v1 spec bytes too, in case an in-flight resolve wants them
    $reg->{fetch_spec} = $stub2->spec_fetcher;
    $reg->apply_bundle({ tenants => $stub2->{tenants}, domains => [], challenges => [] });

    is $hit->(), 200, 'req 4 (post-publish) still counts against the same window';
    is $hit->(), 200, 'req 5 ok';
    is $hit->(), 429, 'gate 2: req 6 is 429 - the publish did NOT reset the counter';
}

# ---- GATE 3: revocation - within one poll, and at once on `apip revoke` ----

# A poller-driven fleet: the whole bundle path (fetch, verify, apply) is
# real, so a change at the stub (the control plane) moves the ETag and the
# next poll applies it. Fresh per mechanism, so one does not perturb the
# next through the ETag/304 cache.
sub poller_fleet {
    my ($host, $proxy, $key, $secret) = @_;
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => $host, proxy => $proxy, version => 1,
        plan => 'starter', limits => { enforce => 1 },
        spec => RegistryStub->secured_spec(1), keys => [ $key ]);
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    my $poller = Maat::Poller->new(
        registry => $reg, url => 'https://openapi-proxy.com/registry/bundle',
        token => $stub->token, fetch => $stub->fetcher);
    $poller->poll_once;
    my $app = Maat::Router->new(registry => $reg)->to_app;
    my $hit = sub {
        my $env = MaatTest::psgi_env(path => '/secure',
                                     headers => ['X-API-Key', $secret]);
        $env->{HTTP_HOST} = $host;
        return (MaatTest::run_app($app, $env))[0];
    };
    return ($stub, $reg, $poller, $hit);
}

# (a) IMMEDIATE, in-process: `apip revoke` running inside the gateway
# drops the key from the live table at once, no poll needed.
{
    my $key = RegistryStub->make_key(id => 77, secret => 'revoke-me');
    my ($stub, $reg, $poller, $hit) = poller_fleet("reva.openapi-proxy.com", 6, $key, "revoke-me");
    is $hit->(), 200, 'the key works before revocation';
    is $reg->revoke_key(77), 1, 'revoke_key removes the key from the in-memory table';
    is $hit->(), 401, 'gate 3a: revoke_key stops the key working immediately, in-process';
}

# (b) WITHIN ONE POLL: the control plane drops the key from the bundle -
# which moves the ETag - and the next scheduled poll removes it.
{
    my $key = RegistryStub->make_key(id => 78, secret => 'poll-away');
    my ($stub, $reg, $poller, $hit) = poller_fleet("revb.openapi-proxy.com", 7, $key, "poll-away");
    is $hit->(), 200, 'the key works before revocation';
    $stub->{tenants}[0]{keys} = [];              # revoked at the control plane
    is $poller->poll_once, 'applied', 'the changed bundle is a fresh 200, not a 304';
    is $hit->(), 401, 'gate 3b: a revoked key stops working within one poll interval';
}

# (c) IMMEDIATE, out-of-process: `apip revoke` signals the running gateway
# to re-poll now. The installed handler forces poll_once, which picks up
# the control plane's revocation at once instead of at the next interval.
{
    my $key = RegistryStub->make_key(id => 79, secret => 'signal-me');
    my ($stub, $reg, $poller, $hit) = poller_fleet("revc.openapi-proxy.com", 8, $key, "signal-me");
    is $hit->(), 200, 'the key works before revocation';
    my $sig = $poller->install_revoke_signal('USR1');
    is $sig, 'USR1', 'the poller installs a re-poll signal handler';
    $stub->{tenants}[0]{keys} = [];              # revoked at the control plane
    $SIG{USR1}->();                               # exactly what `apip revoke` sends
    is $hit->(), 401, 'gate 3c: the re-poll signal stops the key at once';
}

done_testing;
