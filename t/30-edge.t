use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Maat;
use Maat::Registry;
use Maat::Poller;
use Maat::Router;

# The edge's answers, written down.
#
# This began life as a parity test: every case run through the C
# dispatcher and the Perl one, compared field by field. That was the
# right test while both existed, and it earned its keep - it caught three
# bugs in the C path in an afternoon.
#
# Then the Perl was deleted rather than left as a fallback nobody
# exercised, which took the reference implementation with it. So the
# expectations moved here: the exact status, body and headers the edge
# produced BEFORE the port, transcribed as literals.
#
# Literals rather than anything derived, on purpose. A refusal body is a
# public interface - a customer's client parses it, and a fingerprint of
# it may sit in somebody's cache key - so the only way to notice a word
# changing is to have written the word down.

sub fleet {
    my (%o) = @_;
    my $stub = RegistryStub->new(token => 'tok');
    $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 5, version => 4,
        plan => 'team', spec => RegistryStub->tenant_spec(5));
    $stub->add_tenant(host => 'b.openapi-proxy.com', proxy => 6, version => 1,
        plan => 'free', spec => RegistryStub->tenant_spec(6));
    $stub->add_challenge('probe-token', 'probe-token.key-auth');

    my $caps = delete $o{caps};
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher, %o);
    my $poller = Maat::Poller->new(registry => $reg, fetch => $stub->fetcher,
        url => 'http://control/registry/bundle', token => 'tok');
    $poller->poll_once;
    # Caps are the router's: it resolves them per plan and hands the
    # resolver to the registry, which calls it once per compile.
    my $router = Maat::Router->new(registry => $reg,
                                   ($caps ? (caps => $caps) : ()));
    return ($stub, $reg, $router, $router->to_app);
}

sub call {
    my ($app, %a) = @_;
    my $env = MaatTest::psgi_env(
        method => $a{method} || 'GET',
        path   => defined $a{path} ? $a{path} : '/hello',
    );
    $env->{HTTP_HOST} = $a{host} if defined $a{host};
    $env->{CONTENT_LENGTH} = $a{content_length} if defined $a{content_length};
    $env->{"HTTP_X_PAD_$_"} = ('x' x 900) for 1 .. ($a{pad} || 0);
    my ($s, $h, $b) = MaatTest::run_app($app, $env);
    # scalar(), because header_get returns the EMPTY LIST for a header
    # that is not there - which in a hash constructor eats the next key
    # and shifts every pair after it, so an absent X-Maat-Version made
    # `proxy` the version and `type` the proxy. Perl warns about the odd
    # element; it does not warn about the answers being wrong.
    return {
        status  => $s,
        body    => $b,
        version => scalar MaatTest::header_get($h, 'X-Maat-Version'),
        proxy   => scalar MaatTest::header_get($h, 'X-Maat-Proxy'),
        type    => scalar MaatTest::header_get($h, 'Content-Type'),
        retry   => scalar MaatTest::header_get($h, 'Retry-After'),
    };
}

my $TYPE = 'https://openapi-proxy.com/problem/edge';

subtest 'a tenant is served, and stamped' => sub {
    my ($stub, $reg, $router, $app) = fleet();
    for my $pass (1 .. 2) {          # the first compiles; the second is pure C
        my $r = call($app, host => 'a.openapi-proxy.com');
        is $r->{status}, 200, "served (pass $pass)";
        is $r->{version}, 4, '...stamped with its spec version';
        is $r->{proxy}, 5, '...and its proxy id';
        like $r->{body}, qr/"tenant":5/, '...out of its own document';
    }
    is call($app, host => 'A.OpenAPI-Proxy.COM:8443')->{status}, 200,
        'capitals and a port find the same tenant';
    is call($app, host => 'b.openapi-proxy.com')->{status}, 200,
        'and the neighbour is served independently';
};

subtest 'the refusals, word for word' => sub {
    my ($stub, $reg, $router, $app) = fleet();

    my $unknown = call($app, host => 'nowhere.example');
    is $unknown->{status}, 404, 'a host nobody serves: 404';
    is $unknown->{body},
        qq[{"detail":"no proxy is configured for this host","status":404,]
      . qq["title":"Not Found","type":"$TYPE"}],
        '...with the body the Perl edge produced';
    is $unknown->{type}, 'application/problem+json', '...as problem+json';

    is call($app)->{status}, 404, 'no Host header at all is the same 404';

    call($app, host => 'a.openapi-proxy.com');           # publish it
    my $big = call($app, host => 'a.openapi-proxy.com',
                   content_length => 99_999_999);
    is $big->{status}, 413, 'over the body cap: 413';
    is $big->{body},
        qq[{"detail":"the request body exceeds this proxy's limit of ]
      . qq[16777216 bytes","status":413,"title":"Payload Too Large",]
      . qq["type":"$TYPE"}],
        '...naming the limit, in bytes';

    my $heavy = call($app, host => 'a.openapi-proxy.com', pad => 80);
    is $heavy->{status}, 431, 'over the header cap: 431';
    is $heavy->{body},
        qq[{"detail":"the request headers exceed this proxy's limit",]
      . qq["status":431,"title":"Request Header Fields Too Large",]
      . qq["type":"$TYPE"}],
        '...with its exact body';
};

subtest 'the concurrency ceiling, and its Retry-After' => sub {
    my ($stub, $reg, $router, $app) = fleet(
        caps => { team => { concurrency => 1 } });
    call($app, host => 'a.openapi-proxy.com');           # publish, slot free

    # Hold the only slot by acquiring it the way a request would, then
    # ask for another.
    my $held = $reg->table->acquire('a.openapi-proxy.com');
    my $busy = call($app, host => 'a.openapi-proxy.com');
    is $busy->{status}, 429, 'at the ceiling: 429';
    is $busy->{body},
        qq[{"detail":"this proxy is at its concurrency ceiling of 1; ]
      . qq[retry shortly","status":429,"title":"Too Many Requests",]
      . qq["type":"$TYPE"}],
        '...naming the ceiling it hit';
    is $busy->{retry}, 1, '...with Retry-After, so a client knows to come back';

    $reg->table->done($held);
    is call($app, host => 'a.openapi-proxy.com')->{status}, 200,
        'and the slot is servable again the moment it is released';
};

subtest 'the ACME probe is answered for any host, before routing' => sub {
    my ($stub, $reg, $router, $app) = fleet();

    my $hit = call($app, host => 'being-validated.example',
                   path => '/.well-known/acme-challenge/probe-token');
    is $hit->{status}, 200,
        'a pending challenge is answered even for a host nothing routes - '
      . 'which is the point: the domain is validated before it serves';
    is $hit->{body}, 'probe-token.key-auth', '...with the key authorization';
    is $hit->{type}, 'text/plain', '...as text, not problem+json';

    my $miss = call($app, host => 'being-validated.example',
                    path => '/.well-known/acme-challenge/not-a-token');
    is $miss->{status}, 404, 'a token we hold no challenge for is a 404';
    is $miss->{body}, '', '...with an empty body';
};

subtest 'a path the document does not declare' => sub {
    my ($stub, $reg, $router, $app) = fleet();
    call($app, host => 'a.openapi-proxy.com');
    my $r = call($app, host => 'a.openapi-proxy.com', path => '/not-declared');
    is $r->{status}, 404, 'the tenant answers it, not the edge';
    like $r->{body}, qr{problem/request-validation},
        '...so it carries the gateway problem type, not the edge one';
    is $r->{version}, 4, '...and is still stamped as that tenant';
};

subtest 'the C path really is answering' => sub {
    # Without this the file passes gloriously while every request takes
    # some other route - which is exactly what happened the first time the
    # dispatcher was wired, with the whole suite green throughout.
    my ($stub, $reg, $router, $app) = fleet();
    ok $router->{ctable}, 'the router holds the table';

    call($app, host => 'a.openapi-proxy.com');           # compiles, publishes
    my $before = $reg->table->lookup('a.openapi-proxy.com')->{requests};
    call($app, host => 'a.openapi-proxy.com') for 1 .. 5;
    my $after = $reg->table->lookup('a.openapi-proxy.com')->{requests};
    is $after - $before, 5,
        'five requests, five counted in the C entry';
};

subtest 'no exit leaks a concurrency slot' => sub {
    # A leak here is invisible until a tenant is wrongly 429ed hours
    # later, which is the worst way to find one.
    my ($stub, $reg, $router, $app) = fleet();
    call($app, host => 'a.openapi-proxy.com');
    is $reg->table->lookup('a.openapi-proxy.com')->{inflight}, 0,
        'nothing in flight after a served request';

    call($app, host => 'a.openapi-proxy.com', path => '/not-declared');
    call($app, host => 'a.openapi-proxy.com', content_length => 99_999_999);
    call($app, host => 'a.openapi-proxy.com', pad => 80);
    my $e = $reg->table->lookup('a.openapi-proxy.com');
    is $e->{inflight}, 0, 'nor after the refusals';
    is $e->{refcnt}, 1, 'and the table alone holds the entry';
};

subtest 'a tenant that leaves the bundle stops being served' => sub {
    my ($stub, $reg, $router, $app) = fleet();
    call($app, host => 'a.openapi-proxy.com');
    ok $reg->table->lookup('a.openapi-proxy.com'), 'published';

    $stub->clear_tenants;
    $stub->add_tenant(host => 'b.openapi-proxy.com', proxy => 6, version => 1,
        plan => 'free', spec => RegistryStub->tenant_spec(6));
    Maat::Poller->new(registry => $reg, fetch => $stub->fetcher,
        url => 'http://control/registry/bundle', token => 'tok')->poll_once;

    ok !$reg->table->lookup('a.openapi-proxy.com'), 'out of the table';
    is call($app, host => 'a.openapi-proxy.com')->{status}, 404,
        'and its next request is a 404, not a stale 200';
};

subtest 'the isolation counters have one store' => sub {
    # The regression this pins is not a crash, it is a lie: while the
    # Perl dispatch kept a hash of its own, tenant_metrics reported only
    # the requests that happened to take that path.
    my ($stub, $reg, $router, $app) = fleet();

    call($app, host => 'a.openapi-proxy.com') for 1 .. 5;
    call($app, host => 'a.openapi-proxy.com', content_length => 99_999_999);

    my $tm = $router->tenant_metrics(5);
    ok $tm, 'the tenant has counters';
    is $tm->{requests}, 6,
        'all six counted - a refused request is still a routed one, and is '
      . 'the denominator its rejection rate is measured against';
    is $tm->{rejected_body}, 1, 'and the refusal is counted as one';
    is $router->tenant_metrics->{5}{requests}, 6,
        'the by-proxy view is the same store, not a second tally';
};

subtest 'a republish does not reset a tenant history' => sub {
    my ($stub, $reg, $router, $app) = fleet();
    call($app, host => 'a.openapi-proxy.com') for 1 .. 3;
    is $router->tenant_metrics(5)->{requests}, 3, 'three requests';

    $stub->clear_tenants;
    $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 5, version => 9,
        plan => 'team', spec => RegistryStub->tenant_spec(99));
    Maat::Poller->new(registry => $reg, fetch => $stub->fetcher,
        url => 'http://control/registry/bundle', token => 'tok')->poll_once;
    call($app, host => 'a.openapi-proxy.com') for 1 .. 2;

    is $router->tenant_metrics(5)->{requests}, 5,
        'the count carries across the republish - a deploy is not a reason '
      . 'for a tenant history to start again';
    is call($app, host => 'a.openapi-proxy.com')->{version}, 9,
        'and the new version is what serves';
};

subtest 'the agent endpoint refusals, word for word' => sub {
    # Same rule as the block above: a refusal is a public interface, an
    # agent's client parses it, and the only way to notice a word changing
    # is to have written the word down. These were transcribed from what
    # the C produced, not derived from what it ought to produce.
    my $stub = RegistryStub->new(token => 'tok');
    $stub->add_tenant(host => 'm.openapi-proxy.com', proxy => 7, version => 2,
        plan => 'team', spec => RegistryStub->tenant_spec(7));
    $stub->{tenants}[0]{mcp} = { enabled => 1, ops => [], oauth => 0 };

    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [],
                         challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my $mcp = sub {
        my (%a) = @_;
        my $env = MaatTest::psgi_env(
            method => $a{method} || 'POST', path => '/mcp',
            (defined $a{body}
                ? (body => $a{body}, content_type => 'application/json') : ()));
        $env->{HTTP_HOST}   = 'm.openapi-proxy.com';
        $env->{HTTP_ACCEPT} = defined $a{accept} ? $a{accept}
                                                 : 'application/json';
        $env->{HTTP_ORIGIN} = $a{origin} if defined $a{origin};
        my ($s, $h, $b) = MaatTest::run_app($app, $env);
        return { status => $s, body => $b,
                 allow  => scalar MaatTest::header_get($h, 'Allow'),
                 type   => scalar MaatTest::header_get($h, 'Content-Type') };
    };

    my $ping = '{"jsonrpc":"2.0","id":1,"method":"ping"}';

    my $get = $mcp->(method => 'GET');
    is $get->{status}, 405, 'GET on the endpoint: 405, it opens no stream';
    is $get->{allow}, 'POST', '...naming the one method it takes';
    is $get->{body}, '', '...and no body, because Allow has already said it';

    my $origin = $mcp->(origin => 'https://evil.example', body => $ping);
    is $origin->{status}, 403,
        'a browser client on another origin: 403, before the message is read';
    is $origin->{body}, '', '...with nothing echoed back to it';

    my $accept = $mcp->(accept => 'text/html', body => $ping);
    is $accept->{status}, 406, 'a client that will not take JSON: 406';
    is $accept->{body}, '', '...and no body it could not have read anyway';

    my $parse = $mcp->(body => 'not json');
    is $parse->{status}, 400, 'a body that is not JSON: 400';
    is $parse->{body},
        q[{"error":{"code":-32700,"message":"parse error"},"id":null,]
      . q["jsonrpc":"2.0"}],
        '...a JSON-RPC parse error carrying a null id, there being none to echo';
    is $parse->{type}, 'application/json',
        '...as JSON: this refusal is a protocol answer, not problem+json';
};

done_testing;
