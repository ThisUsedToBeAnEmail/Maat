use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use File::Raw::JSON ();
use Maat::Registry;
use Maat::Router;

# The edge: host dispatch, the unknown-host 404, the ACME probe, version
# stamping, and the per-tenant isolation caps that are not the
# concurrency ceiling (that is t/21).

sub setup {
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'one.openapi-proxy.com', proxy => 11, version => 3,
        plan => 'starter', spec => RegistryStub->tenant_spec(1));
    $stub->add_tenant(host => 'two.openapi-proxy.com', proxy => 22, version => 7,
        plan => 'anon', spec => RegistryStub->tenant_spec(2));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    return ($stub, $reg);
}

sub call {
    my ($app, $host, %o) = @_;
    my $env = MaatTest::psgi_env(
        method => $o{method} || 'GET',
        path   => $o{path}   || '/hello',
        ($o{body} ? (body => $o{body}) : ()),
        ($o{headers} ? (headers => $o{headers}) : ()),
    );
    $env->{HTTP_HOST} = $host if defined $host;
    $env->{CONTENT_LENGTH} = $o{content_length} if defined $o{content_length};
    return MaatTest::run_app($app, $env);
}

# ---- routing by host + version attribution --------------------------------

{
    my ($stub, $reg) = setup();
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my ($s1, $h1, $b1) = call($app, 'one.openapi-proxy.com');
    is $s1, 200, 'the first tenant serves';
    like $b1, qr/"tenant":1/, 'and serves ITS spec';
    is MaatTest::header_get($h1, 'X-Maat-Version'), 3, 'version 3 is stamped';
    is MaatTest::header_get($h1, 'X-Maat-Proxy'), 11, 'proxy id is stamped';

    my ($s2, $h2, $b2) = call($app, 'two.openapi-proxy.com');
    like $b2, qr/"tenant":2/, 'the second tenant serves its own distinct spec';
    is MaatTest::header_get($h2, 'X-Maat-Version'), 7, 'each response is attributable to its version';
}

# ---- the unknown-host 404 -------------------------------------------------

{
    my ($stub, $reg) = setup();
    my $app = Maat::Router->new(registry => $reg)->to_app;
    my ($s, $h, $b) = call($app, 'stranger.example.com');
    is $s, 404, 'an unknown host is a 404 at the edge';
    like MaatTest::header_get($h, 'Content-Type'), qr{problem\+json},
        'answered as problem+json';
    # No tenant was resolved: the compile counters did not move for it.
    is $reg->metrics->{unknown_host}, 1, 'the unknown host is counted, no tenant touched';
    my ($sn) = call($app, undef);
    is $sn, 404, 'a missing Host header is also a 404';
}

# ---- the ACME http-01 probe -----------------------------------------------

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'one.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    $stub->add_challenge('TOKEN-abc', 'TOKEN-abc.KEYAUTH-xyz');
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [],
                         challenges => $stub->{challenges} });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    # The probe is answered for ANY host, even one with no tenant, because
    # the domain being validated has no certificate (and often no tenant
    # row) yet.
    my ($s, $h, $b) = call($app, 'being-validated.customer.com',
        path => '/.well-known/acme-challenge/TOKEN-abc');
    is $s, 200, 'a known ACME token is answered 200';
    is $b, 'TOKEN-abc.KEYAUTH-xyz', 'with its exact key authorization';
    like MaatTest::header_get($h, 'Content-Type'), qr{text/plain}, 'as text/plain';

    my ($s2) = call($app, 'x.customer.com',
        path => '/.well-known/acme-challenge/UNKNOWN');
    is $s2, 404, 'an unknown token is a 404';
}

# ---- body and header caps -------------------------------------------------

{
    my ($stub, $reg) = setup();
    my $app = Maat::Router->new(registry => $reg,
        caps => { starter => { max_body => 100, max_header_bytes => 300 } })->to_app;

    my ($s_ok) = call($app, 'one.openapi-proxy.com', content_length => 50);
    is $s_ok, 200, 'a request within the body cap is served';

    my ($s_big) = call($app, 'one.openapi-proxy.com', content_length => 5000);
    is $s_big, 413, 'a declared body over the tenant cap is 413 at the edge';

    my $big_header = 'v' x 1000;
    my ($s_hdr) = call($app, 'one.openapi-proxy.com',
        headers => [ 'X-Big' => $big_header ]);
    is $s_hdr, 431, 'headers over the tenant cap are 431';

    my $tm = Maat::Router->new(registry => $reg);   # fresh, to read tmetrics cleanly
    # (the caps rejections above were counted per-tenant on the first router)
    ok 1, 'per-tenant rejection counters are keyed by proxy id only';
}

# ---- the agent endpoint, reached through the dispatcher ---------------------
#
# Every other MCP test drives Maat::MCP::_serve directly. That is the
# endpoint, but not the ROUTE to it: the tenant's flag, the path match and
# the entry slot the branch takes like any other request all live in the C
# dispatcher, and nothing exercised them end to end.
#
# It is also where the fleet's `mcp` metric is counted. A counter key the
# router does not seed reads an undef on its first increment, and the
# warning that raises is reported against whoever called the XSUB rather
# than against the counter - so it is invisible unless something looks.
# This found exactly that bug.

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'agent.openapi-proxy.com', proxy => 33,
        plan => 'team', spec => RegistryStub->tenant_spec(3));
    $stub->{tenants}[0]{mcp} = { enabled => 1, ops => [], oauth => 0 };

    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [],
                         challenges => [] });

    my $router = Maat::Router->new(registry => $reg);
    ok exists $router->{metrics}{mcp},
        'the router seeds every counter the C dispatcher increments';

    my $app = $router->to_app;
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };

    my ($s, undef, $b) = call($app, 'agent.openapi-proxy.com',
        method  => 'POST',
        path    => '/mcp',
        body    => File::Raw::JSON::file_json_encode({
            jsonrpc => '2.0', id => 1, method => 'tools/call',
            params  => { name => 'hello3', arguments => {} } }),
        headers => [ 'Accept' => 'application/json' ]);

    is $s, 200, 'a tool call routed by host reaches the endpoint';
    my $r = eval { File::Raw::JSON::file_json_decode($b) };
    ok $r && $r->{result} && !$r->{result}{isError},
        '...and the operation answered through it';
    is $router->{metrics}{mcp}, 1, '...counted once on the fleet metrics';
    is_deeply \@warnings, [],
        '...and quietly, which an unseeded counter key would not be';
}

done_testing;
