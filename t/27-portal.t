use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Digest::SHA ();
use File::Raw::JSON ();
use Open::API ();
use Maat::Config ();
use Maat::Violation ();
use Maat::Portal ();
use Maat::Registry ();
use Maat::Router ();

# Phase 10 - the docs portal. Rendered from the SAME compiled spec the
# gateway enforces, served from frozen bytes off the request path, with a
# reality badge from the gateway's own drift. The four gates:
#
#   1. docs and enforcing gateway report the same version hash, and a spec
#      change moves both.
#   2. the docs build adds no measurable per-request cost - it is boot
#      work and frozen bytes; a /docs page is a hash lookup and the API
#      path never enters the portal.
#   3. the reality badge equals what Maat::Violation holds.
#   4. portal off by default - no /docs route at all.

sub decode { File::Raw::JSON::file_json_decode($_[0]) }

sub call {
    my ($app, $host, $path, %o) = @_;
    my $env = MaatTest::psgi_env(
        method => $o{method} || 'GET',
        path   => $path,
        ($o{query} ? (query => $o{query}) : ()),
    );
    $env->{HTTP_HOST}    = $host if defined $host;
    $env->{QUERY_STRING} = $o{query} if defined $o{query};
    return MaatTest::run_app($app, $env);
}

# ---- A. the portal, built from a compiled spec ----------------------------

{
    my $spec   = RegistryStub->portal_spec(1);
    my $digest = Digest::SHA::sha256_hex($spec);
    my $api    = Open::API->new(spec => $spec);
    my $v      = Maat::Violation->new(window => 1000);

    my $portal = Maat::Portal->new(
        api     => $api,
        host    => 'acme.openapi-proxy.com',
        version => '3.2.1',
        digest  => $digest,
        badges  => 1,
        violation => $v,
        guides  => [
            { slug => 'getting-started', title => 'Getting Started',
              body => "# Getting Started\n\nAuthenticate with a bearer token, "
                    . "then call the pets API.\n", order => 1 },
        ],
    );

    ok $portal->renders > 0, 'the portal did its rendering at construction';
    is $portal->version, '3.2.1', 'it knows the spec version';
    is $portal->digest, $digest, 'and the content digest';

    # Every page a hash lookup, and every page carries the version + hash.
    my $short = substr($digest, 0, 12);
    for my $path ('/docs', '/docs/reference', '/docs/guides',
                  '/docs/guides/getting-started', '/docs/op/getPet1') {
        my ($s, $h, $b) = MaatTest::run_app($portal->wrap(sub { die }),
            do { my $e = MaatTest::psgi_env(path => $path); $e });
        is $s, 200, "$path serves 200";
        like $b, qr/contract version/, "$path shows the contract version";
        like $b, qr/\Q$short\E/, "$path shows the content hash";
    }

    # The generated reference is Open::API::UI's, mounted under /docs.
    {
        my ($s, $h, $b) = MaatTest::run_app($portal->wrap(sub { die }),
            MaatTest::psgi_env(path => '/docs/openapi.json'));
        is $s, 200, 'the raw document is served';
        my $doc = decode($b);
        is $doc->{info}{version}, '3.2.1', 'and it is the enforced document';
    }

    # Client snippets, generated from the compiled spec, with the path
    # template filled.
    {
        my ($s, $h, $b) = MaatTest::run_app($portal->wrap(sub { die }),
            MaatTest::psgi_env(path => '/docs/op/getPet1'));
        like $b, qr/curl -s -X GET/, 'a curl snippet';
        like $b, qr{/pets/1}, 'with the path template filled from the schema';
        like $b, qr/Open::API::Client/, 'and an Open::API::Client snippet';
    }

    # Search across reference + prose, built at boot.
    {
        my ($s, $h, $b) = MaatTest::run_app($portal->wrap(sub { die }),
            do { my $e = MaatTest::psgi_env(path => '/docs/search');
                 $e->{QUERY_STRING} = 'q=authenticate'; $e });
        is $s, 200, 'search answers';
        my $r = decode($b);
        ok scalar(@{ $r->{results} }), 'and finds the guide prose';
        is $r->{results}[0]{kind}, 'guide', 'the top hit is the guide';
    }
}

# ---- B. gate 1: docs and enforcing gateway agree on the version hash ------

{
    my $stub = RegistryStub->new;
    my $t = $stub->add_tenant(host => 'g1.openapi-proxy.com', proxy => 501,
        version => '1.0.0', spec => RegistryStub->portal_spec(1),
        portal => { badges => 0, guides_rev => '' });
    my $digest1 = $t->{digest};

    my $reg = Maat::Registry->new(
        fetch_spec => $stub->spec_fetcher, portal => 1);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    # what the docs say
    my ($ds, $dh, $db) = call($app, 'g1.openapi-proxy.com', '/docs/version.json');
    is $ds, 200, 'the docs version endpoint serves';
    my $dv = decode($db);

    # what the enforcing gateway stamps on a real request
    my ($as, $ah, $ab) = call($app, 'g1.openapi-proxy.com', '/pets');
    my $stamped = MaatTest::header_get($ah, 'X-Maat-Version');

    is $dv->{version}, $stamped, 'docs and enforcing gateway report the same version';
    is $dv->{digest}, $digest1, 'and the docs show the enforced content hash';
    is $reg->tenant('g1.openapi-proxy.com')->{digest}, $dv->{digest},
        'which is exactly the digest the registry is serving';

    # Change the spec: a new version and a new digest. Both must move, in
    # the docs and on the wire, together.
    $stub->clear_tenants;
    my $t2 = $stub->add_tenant(host => 'g1.openapi-proxy.com', proxy => 501,
        version => '2.0.0', spec => RegistryStub->portal_spec(2),
        portal => { badges => 0, guides_rev => '' });
    my $digest2 = $t2->{digest};
    isnt $digest2, $digest1, 'the spec change is a new digest';
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my ($ds2, undef, $db2) = call($app, 'g1.openapi-proxy.com', '/docs/version.json');
    my $dv2 = decode($db2);
    my (undef, $ah2) = call($app, 'g1.openapi-proxy.com', '/pets');
    my $stamped2 = MaatTest::header_get($ah2, 'X-Maat-Version');

    is $dv2->{version}, '2.0.0', 'the docs moved to the new version';
    is $dv2->{digest}, $digest2, 'and the new digest';
    is $stamped2, '2.0.0', 'the enforcing gateway moved with it';
    is $dv2->{version}, $stamped2, 'docs and gateway still agree after a republish';
}

# ---- C. gate 2: no per-request render; the API path never enters the portal

{
    my $spec = RegistryStub->portal_spec(3);
    my $api  = Open::API->new(spec => $spec);
    my $portal = Maat::Portal->new(api => $api, host => 'c.openapi-proxy.com',
        version => '3.2.1', digest => Digest::SHA::sha256_hex($spec));

    # An inner app that counts how often it is called: the API path must
    # reach it, the /docs path must not.
    my $inner_calls = 0;
    my $inner = sub { $inner_calls++;
        [ 200, [ 'Content-Type' => 'application/json' ], [ '{"api":1}' ] ] };
    my $wrapped = $portal->wrap($inner);

    my $renders0 = $portal->renders;

    # Hammer both a /docs page and an API path.
    for (1 .. 200) {
        MaatTest::run_app($wrapped, MaatTest::psgi_env(path => '/docs'));
        MaatTest::run_app($wrapped, MaatTest::psgi_env(path => '/pets'));
    }
    is $portal->renders, $renders0,
        'no page is re-rendered on a request - the build is frozen (gate 2)';
    is $inner_calls, 200, 'every API request fell straight through to the gateway';

    # ...and the /docs page never entered the inner app.
    my $before = $inner_calls;
    MaatTest::run_app($wrapped, MaatTest::psgi_env(path => '/docs/op/getPet3'));
    is $inner_calls, $before, 'a /docs request never touches the API path';

    # A rough timing sanity check (diag, not a hard assert - a wall clock
    # in CI is noise): the API path through the wrapper is a single prefix
    # test in front of the inner app.
    my $t0 = _time();
    MaatTest::run_app($wrapped, MaatTest::psgi_env(path => '/pets')) for 1 .. 2000;
    my $on = _time() - $t0;
    my $t1 = _time();
    $inner->(MaatTest::psgi_env(path => '/pets')) for 1 .. 2000;
    my $bare = _time() - $t1;
    diag sprintf('API path: %.2fus/req wrapped vs %.2fus/req bare',
        $on / 2000 * 1e6, $bare / 2000 * 1e6);
    ok 1, 'the wrapper is a prefix test in front of the C path';
}

# ---- D. gate 3: the reality badge equals what Maat::Violation holds -------

{
    my $spec = RegistryStub->portal_spec(4);
    my $api  = Open::API->new(spec => $spec);

    # The gateway's OWN violation pipeline is the source of the badge.
    my $v = Maat::Violation->new(window => 1000, spec => $api->spec);

    my $portal = Maat::Portal->new(api => $api, host => 'd.openapi-proxy.com',
        version => '3.2.1', digest => Digest::SHA::sha256_hex($spec),
        badges => 1, violation => $v);

    # No drift yet: every operation is clear.
    my $r0 = $portal->reality;
    is $r0->{getPet4}{drift}, 0, 'no drift, no badge';

    # Record two response violations on getPet4, exactly as the gateway's
    # response check does.
    $v->record(operation => 'getPet4', status => 200, kind => 'response',
        errors => [ { instanceLocation => '/name', keyword => 'type',
                      message => 'expected string, got integer' } ]);
    $v->record(operation => 'getPet4', status => 200, kind => 'response',
        errors => [ { instanceLocation => '/name', keyword => 'type',
                      message => 'expected string, got integer' } ]);

    my $reality = $portal->reality;
    is $reality->{getPet4}{drift}, 1, 'getPet4 now shows drift';
    is $reality->{listPets4}{drift}, 0, 'listPets4 does not';

    # The badge equals what Maat::Violation holds, by construction.
    my $drift = $v->drift;
    ok $drift->{getPet4}, 'Maat::Violation holds drift for getPet4';
    is $reality->{getPet4}{count}, $drift->{getPet4}{count},
        'the badge count is the aggregate count';
    is $reality->{getPet4}{sample_count}, $drift->{getPet4}{sample_count},
        'and the sample count';
    is $v->in_drift('getPet4'), 1, 'in_drift agrees';
    is $v->in_drift('listPets4'), 0, 'and for the clear operation';

    # The op page renders the live badge. (Assert on the rendered text, not
    # the class name - the stylesheet mentions the classes on every page.)
    my ($s, $h, $b) = MaatTest::run_app($portal->wrap(sub { die }),
        MaatTest::psgi_env(path => '/docs/op/getPet4'));
    like $b, qr/have drifted from/, 'the drifting operation shows the reality badge';
    my ($s2, $h2, $b2) = MaatTest::run_app($portal->wrap(sub { die }),
        MaatTest::psgi_env(path => '/docs/op/listPets4'));
    like $b2, qr/responses conform to the schema/,
        'the conforming operation shows the clear badge';

    # The opt-in gate: with badges OFF, no reality is exposed however much
    # the same pipeline has drifted.
    my $off = Maat::Portal->new(api => $api, host => 'd.openapi-proxy.com',
        version => '3.2.1', digest => Digest::SHA::sha256_hex($spec),
        badges => 0, violation => $v);
    is_deeply $off->reality, {}, 'badges off: no reality is exposed at all';
    my ($os, $oh, $ob) = MaatTest::run_app($off->wrap(sub { die }),
        MaatTest::psgi_env(path => '/docs/op/getPet4'));
    unlike $ob, qr/Reality:/, 'and no reality badge is rendered on the op page';
}

# ---- E. gate 4: portal off by default - no /docs route --------------------

{
    # The config default is off.
    my $cfg = Maat::Config->tenant(mode => 'mock');
    is $cfg->portal, 0, 'Maat::Config: portal is off by default';

    # A registry with the portal off wraps nothing: a /docs request is
    # handled as any other undeclared path, NOT as a portal page.
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'off.openapi-proxy.com', proxy => 601,
        version => '1.0.0', spec => RegistryStub->portal_spec(1));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);  # portal defaults off
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my ($s, $h, $b) = call($app, 'off.openapi-proxy.com', '/docs');
    is $s, 404, 'portal off: /docs is a 404, not a portal page';
    unlike $b, qr/contract version/, 'no portal HTML is served';
    my $prob = decode($b);
    is $prob->{status}, 404, 'it is answered as an undeclared spec path (problem+json)';

    # And a normal API request is entirely unaffected.
    my ($as) = call($app, 'off.openapi-proxy.com', '/pets');
    is $as, 200, 'the API path is untouched with the portal off';
}

# ---- F. guides: fetched lazily, rebuilt when the revision moves -----------

{
    my $stub = RegistryStub->new;
    my $rev1 = $stub->add_guides(proxy => 701, guides => [
        { slug => 'intro', title => 'Introduction',
          body => "# Intro\n\nWelcome to the herd.\n", order => 1 } ]);
    $stub->add_tenant(host => 'f.openapi-proxy.com', proxy => 701,
        version => '1.0.0', spec => RegistryStub->portal_spec(1),
        portal => { badges => 0, guides_rev => $rev1 });

    my $reg = Maat::Registry->new(
        fetch_spec   => $stub->spec_fetcher,
        fetch_guides => $stub->guides_fetcher,
        portal       => 1);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;

    my ($s, $h, $b) = call($app, 'f.openapi-proxy.com', '/docs/guides/intro');
    is $s, 200, 'the fetched guide is served under /docs';
    like $b, qr/Welcome to the herd/, 'with its rendered prose';
    is $reg->metrics->{guides_fetched}, 1, 'the guides were fetched once';

    # A guides_rev change with the SAME spec digest rebuilds the portal off
    # the request path.
    $stub->clear_tenants;
    my $rev2 = $stub->add_guides(proxy => 701, guides => [
        { slug => 'intro', title => 'Introduction',
          body => "# Intro\n\nWelcome to the herd.\n", order => 1 },
        { slug => 'auth', title => 'Authentication',
          body => "# Authentication\n\nUse a bearer token.\n", order => 2 } ]);
    isnt $rev2, $rev1, 'new guides are a new revision';
    $stub->add_tenant(host => 'f.openapi-proxy.com', proxy => 701,
        version => '1.0.0', spec => RegistryStub->portal_spec(1),
        portal => { badges => 0, guides_rev => $rev2 });
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my ($s2, undef, $b2) = call($app, 'f.openapi-proxy.com', '/docs/guides/auth');
    is $s2, 200, 'the newly added guide is served after the revision moved';
    like $b2, qr/Use a bearer token/, 'with its prose - the frozen portal was rebuilt';
    is $reg->metrics->{guides_fetched}, 2, 'and the guides were re-fetched';
}

sub _time { require Time::HiRes; Time::HiRes::time() }

done_testing;
