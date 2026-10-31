use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;

use Maat::Config;
use Maat::Gateway;

my $up = start_upstream();

sub gateway {
    my (%o) = @_;
    my $config = Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('petstore.json'),
        mode     => delete $o{mode} || 'observe',
    });
    return Maat::Gateway->new(config => $config, %o);
}

# ---- construction -----------------------------------------------------------

{
    my $g = gateway();
    isa_ok($g, 'Maat::Gateway');
    isa_ok($g->api, 'Open::API');
    isa_ok($g->config, 'Maat::Config');
    isa_ok($g->violation, 'Maat::Violation');
    is(ref $g->to_app, 'CODE', 'to_app returns a coderef');
}

# A spec that does not compile refuses to start.
{
    local $@;
    eval { Maat::Gateway->new(config => Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('broken.json'),
    })) };
    like($@, qr/did not compile/, 'a non-compiling spec refuses to start');

    eval { Maat::Gateway->new() };
    like($@, qr/config is required/, 'config is required');
}

# ---- a conforming request is forwarded --------------------------------------

{
    my $g   = gateway();
    my $app = $g->to_app;

    my ($status, $headers, $body) =
        run_app($app, psgi_env(method => 'GET', path => '/pets/42'));
    is($status, 200, 'conforming GET forwarded');
    is($body, "method=GET\ntarget=/pets/42\nbody=", 'upstream body untouched');
    is(header_get($headers, 'X-Upstream'), 'maat-test', 'upstream header kept');

    my $rid = header_get($headers, 'X-Request-Id');
    like($rid, qr/\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\z/,
         'a v7 uuid was minted for X-Request-Id');

    my @log = upstream_log($up);
    is($log[-1]{rid}, $rid, 'the minted id was forwarded to the upstream');

    is($g->counters->{request}, 1, 'request counted');
    is($g->counters->{conforming}, 1, 'conforming counted');
    is($g->counters->{violation}, 0, 'no violation');
}

# ---- a client-supplied request id is kept -----------------------------------

{
    my $app = gateway()->to_app;
    my ($status, $headers) = run_app($app, psgi_env(
        method => 'GET', path => '/pets/42',
        headers => [ 'X-Request-Id' => 'client-id-001' ],
    ));
    is($status, 200, 'forwarded');
    is(header_get($headers, 'X-Request-Id'), 'client-id-001',
       'the client id is echoed, not replaced');
    my @log = upstream_log($up);
    is($log[-1]{rid}, 'client-id-001', 'and forwarded to the upstream');
}

# ---- an undeclared path is forwarded, not rejected --------------------------

{
    my $g   = gateway();
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/not/in/the/spec',
        body => 'anything at all', content_type => 'text/plain',
    ));
    is($status, 200, 'undeclared path forwarded');
    is($body, "method=POST\ntarget=/not/in/the/spec\nbody=anything at all",
       'body reached the upstream byte for byte');
    is($g->counters->{undeclared}, 1, 'counted as undeclared');
    is($g->counters->{conforming}, 0, 'not counted as conforming');
}

# ---- a valid body is buffered, validated and forwarded intact ---------------

{
    my $g   = gateway();
    my $app = $g->to_app;
    my $json = '{"name":"rex","tag":"dog"}';
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => $json,
    ));
    is($status, 200, 'valid POST forwarded');
    is($body, "method=POST\ntarget=/pets\nbody=$json",
       'the exact body bytes were forwarded after validation read them');
    is($g->counters->{conforming}, 1, 'conforming');
}

# ---- query strings are carried and validated --------------------------------

{
    my $g   = gateway();
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=10',
    ));
    is($status, 200, 'query forwarded');
    is($body, "method=GET\ntarget=/pets?limit=10\nbody=",
       'query string reached the upstream');
    is($g->counters->{conforming}, 1, 'conforming with a query');
}

# ---- a body over max_body streams through unvalidated -----------------------

{
    my $config = Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('petstore.json'),
        max_body => 10,
        mode     => 'enforce',
    });
    my $g   = Maat::Gateway->new(config => $config);
    my $app = $g->to_app;
    my $big = '{"name":"' . ('x' x 50) . '"}';
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => $big,
    ));
    is($status, 200, 'oversized body forwarded even in enforce');
    is($body, "method=POST\ntarget=/pets\nbody=$big", 'bytes untouched');
    is($g->counters->{skipped}, 1, 'counted as skipped');
    is($g->counters->{rejected}, 0, 'never rejected on a skipped check');
}

stop_upstream($up);
done_testing;
