use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Maat::Registry;

# The per-worker host map: lazy compile, hit/miss, digest verification,
# atomic publish (an in-flight request finishes against the old compiled
# object), and the LRU with its two caps.

# ---- lazy compile, hit vs miss --------------------------------------------

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    is $reg->metrics->{compiles}, 0, 'nothing compiled at publish (lazy)';
    is $reg->metrics->{specs_resident}, 0, 'no specs resident before first request';

    my ($app, $meta) = $reg->resolve('a.openapi-proxy.com');
    ok $app, 'first request resolves an app';
    is $meta->{proxy}, 1, 'meta carries the proxy id';
    is $reg->metrics->{misses}, 1, 'first request is a miss';
    is $reg->metrics->{compiles}, 1, 'first request compiled once';
    is $reg->metrics->{specs_resident}, 1, 'one spec now resident';

    $reg->resolve('a.openapi-proxy.com') for 1 .. 5;
    is $reg->metrics->{compiles}, 1, 'later requests do not recompile';
    is $reg->metrics->{hits}, 5, 'later requests are hits';

    is_deeply [ $reg->resolve('nope.openapi-proxy.com') ], [],
        'an unknown host resolves to nothing';
    is $reg->metrics->{unknown_host}, 1, 'unknown host is counted';
}

# ---- host is lower-cased and port-stripped --------------------------------

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'case.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    ok +($reg->resolve('CASE.openapi-proxy.com:443'))[0],
        'a mixed-case Host with a port still resolves';
}

# ---- digest verification --------------------------------------------------

{
    my $stub = RegistryStub->new;
    my $t = $stub->add_tenant(host => 'bad.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    # A bundle claiming a digest whose bytes will not hash to it: the
    # fetch returns something, but it will not match, and nothing compiles.
    $t->{digest} = '0' x 64;
    my $reg = Maat::Registry->new(fetch_spec => sub {
        # hand back a body that does not hash to the claimed digest
        return RegistryStub->tenant_spec(1);
    });
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my ($app) = $reg->resolve('bad.openapi-proxy.com');
    # poisoned -> a 503 app, and bad_digest counted
    my $res = $app->({});
    is $res->[0], 503, 'a digest mismatch is served 503, never a wrong spec';
    ok $reg->metrics->{bad_digest} >= 1, 'digest mismatch is counted';
}

# ---- atomic publish: an in-flight request finishes against the old spec ----

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'v.openapi-proxy.com', proxy => 1, version => 1,
        spec => RegistryStub->tenant_spec(1));           # body {"tenant":1}
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my ($old_app) = $reg->resolve('v.openapi-proxy.com');
    my $env = MaatTest::psgi_env(path => '/hello');
    my ($s1, $h1, $b1) = MaatTest::run_app($old_app, $env);
    like $b1, qr/"tenant":1/, 'the held app serves version 1';

    # Publish a new version of the SAME host: different spec, new digest.
    $stub->clear_tenants;
    $stub->add_tenant(host => 'v.openapi-proxy.com', proxy => 1, version => 2,
        spec => RegistryStub->tenant_spec(99));          # body {"tenant":99}
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    # The reference we are holding is unaffected - it finishes against the
    # object it resolved, which is the whole atomic-publish promise.
    my ($s2, $h2, $b2) = MaatTest::run_app($old_app,
        MaatTest::psgi_env(path => '/hello'));
    like $b2, qr/"tenant":1/,
        'an in-flight request keeps serving the version it resolved';

    # A fresh resolve gets the new version.
    my ($new_app) = $reg->resolve('v.openapi-proxy.com');
    my ($s3, $h3, $b3) = MaatTest::run_app($new_app,
        MaatTest::psgi_env(path => '/hello'));
    like $b3, qr/"tenant":99/, 'a new request gets the freshly published version';
    isnt $old_app, $new_app, 'the publish swapped the compiled entry';
}

# ---- a mode/upstream change with the SAME spec must recompile -------------
#
# The bug this guards: a mock given an upstream and switched to observe kept
# answering as a mock. Its spec never changed, so its digest never moved,
# and the reconcile keyed on the digest alone - the stale mock app was served
# on. build_rev makes mode/upstream/enforce part of the compiled app's
# identity even when the digest is not, so resolve rebuilds.

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'flip.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));            # no upstream -> mock
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my ($mock_app, $m1) = $reg->resolve('flip.openapi-proxy.com');
    is $m1->{mode}, 'mock', 'starts life as a mock';
    is $reg->metrics->{compiles}, 1, 'compiled once';
    my $digest = $m1->{digest};

    # The same spec bytes - so the same digest - now with an upstream and
    # observe mode, exactly what adding an upstream in the console produces.
    $stub->clear_tenants;
    $stub->add_tenant(host => 'flip.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1),             # identical bytes
        upstream => 'https://up.example', mode => 'observe');
    is $stub->{tenants}[0]{digest}, $digest,
        'the spec did not change, so neither did the digest';
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my ($obs_app, $m2) = $reg->resolve('flip.openapi-proxy.com');
    is $m2->{mode}, 'observe', 'the bundle now says observe';
    is $m2->{upstream}, 'https://up.example', '...carrying the upstream';
    isnt $mock_app, $obs_app,
        'the same-digest mode change rebuilt the app - the mock is gone';
    is $reg->metrics->{compiles}, 2, 'the change forced exactly one recompile';

    # ...and it settles: an unchanged bundle is a hit, not a recompile loop.
    $reg->resolve('flip.openapi-proxy.com') for 1 .. 3;
    is $reg->metrics->{compiles}, 2, 'a steady bundle does not recompile';
}

# ---- the MCP toggle arrives in a bundle and rebuilds the tenant ------------
#
# The control plane turns MCP on by moving a field in the bundle, not by
# republishing the document, so the spec digest does not move. Without the
# toggle being part of the compiled app's identity the gateway would go on
# serving the app it already had - a customer flicking the switch and seeing
# nothing happen, which is the same bug class mode and upstream have.
#
# Phase 02 put mcp.enabled and mcp.ops into _build_rev; nothing until now
# drove them through an actual bundle.

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'agents.openapi-proxy.com', proxy => 9,
        spec => RegistryStub->tenant_spec(9),
        upstream => 'https://api.example.com');
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    my $bundle = sub {
        { tenants => $stub->{tenants}, domains => [], challenges => [] } };

    $reg->apply_bundle($bundle->());
    $reg->resolve('agents.openapi-proxy.com');
    is $reg->metrics->{compiles}, 1, 'the tenant compiles once with MCP off';

    # The same document, the same digest: only the toggle moved.
    $stub->{tenants}[0]{mcp} = { enabled => 1, ops => [] };
    $reg->apply_bundle($bundle->());
    $reg->resolve('agents.openapi-proxy.com');
    is $reg->metrics->{compiles}, 2,
       'turning MCP on rebuilds the tenant, though the spec never changed';

    # Narrowing the tool list is the same kind of change.
    $stub->{tenants}[0]{mcp} = { enabled => 1, ops => ['getPet9'] };
    $reg->apply_bundle($bundle->());
    $reg->resolve('agents.openapi-proxy.com');
    is $reg->metrics->{compiles}, 3,
       'changing which operations are tools rebuilds it too';

    # And a bundle that says the same thing again does not.
    $reg->apply_bundle($bundle->());
    $reg->resolve('agents.openapi-proxy.com') for 1 .. 3;
    is $reg->metrics->{compiles}, 3, 'an unchanged toggle does not recompile';
}

# ---- a build_rev change RETIRES the compiled entry at poll time ------------
#
# resolve() rebuilding on build_rev covers the Perl path, but the C table
# serves a portal-off tenant from a DIRECT gateway pointer and skips resolve
# entirely - so resolve's build_rev check never runs for it. apply_bundle
# must therefore DROP a compiled entry whose build_rev moved, not only one
# whose digest moved: _drop retires the mirrored C entry, so the edge stops
# calling the old responder. Without this, clearing an upstream (proxy ->
# mock) kept the C path forwarding to the upstream the customer just removed.
#
# The observable, table-independent proof: after the poll, the compiled entry
# is already gone (dropped eagerly here), not still cached to be rebuilt on a
# later resolve.
{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'edge.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1),
        upstream => 'https://up.example', mode => 'observe');
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    $reg->resolve('edge.openapi-proxy.com');           # compile + cache
    ok $reg->{compiled}{'edge.openapi-proxy.com'},
        'a proxy with an upstream is compiled and cached';

    # Clear the upstream: same spec bytes, same digest, now a mock.
    $stub->clear_tenants;
    $stub->add_tenant(host => 'edge.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));          # no upstream -> mock
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    ok !$reg->{compiled}{'edge.openapi-proxy.com'},
        'clearing the upstream retired the stale entry at poll time - the C '
      . 'table drops its forwarding gateway rather than serving it on';

    my (undef, $m) = $reg->resolve('edge.openapi-proxy.com');
    is $m->{mode}, 'mock', 'the next request rebuilds the tenant as a mock';
}

# ---- LRU: the count cap ---------------------------------------------------

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => "n$_.x", proxy => $_,
        spec => RegistryStub->tenant_spec($_)) for 1 .. 3;
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher, max_specs => 2);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    $reg->resolve('n1.x');
    $reg->resolve('n2.x');
    $reg->resolve('n1.x');            # n1 is now more recently used than n2
    $reg->resolve('n3.x');            # over the cap of 2 -> evict the LRU (n2)

    is $reg->metrics->{specs_resident}, 2, 'the count cap holds resident specs at 2';
    is $reg->metrics->{evictions}, 1, 'one eviction happened';
    # n2 was the victim: resolving it again is a fresh compile (a miss).
    my $before = $reg->metrics->{compiles};
    $reg->resolve('n2.x');
    is $reg->metrics->{compiles}, $before + 1, 'the evicted host recompiles on its next request';
}

# ---- LRU: the bytes cap ---------------------------------------------------

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => "b$_.x", proxy => $_,
        spec => RegistryStub->tenant_spec($_)) for 1 .. 3;
    my $one = length RegistryStub->tenant_spec(1);
    # A cap that fits two specs but not three forces eviction on bytes even
    # though the count cap is generous.
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
        max_specs => 100, max_bytes => 2 * $one + 10);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    $reg->resolve("b$_.x") for 1 .. 3;
    ok $reg->resident_bytes <= 2 * $one + 10, 'resident bytes stay within the bytes cap';
    ok $reg->metrics->{evictions} >= 1, 'the bytes cap evicts';
}

# ---- environments ----------------------------------------------------------
#
# An environment is a named pointer at a version. The property worth
# protecting is that naming one can never take a gateway down: an
# unknown name, or one nobody has pointed anywhere, falls back to the
# published version rather than serving nothing.

{
    my $stub = RegistryStub->new;
    my $staged = $stub->add_version(version => 7,
        spec => RegistryStub->tenant_spec(99));
    $stub->add_tenant(host => 'env.x', proxy => 1,
        spec => RegistryStub->tenant_spec(1),
        environments => { staging => $staged });

    my $bundle = { tenants => $stub->{tenants}, domains => [],
                   challenges => [] };

    # no environment: the published version, exactly as before
    my $plain = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $plain->apply_bundle($bundle);
    is $plain->tenant('env.x')->{version}, 1,
        'a worker that names no environment serves the published version';

    # staging: the version staging points at
    my $stage = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
                                    environment => 'staging');
    $stage->apply_bundle($bundle);
    is $stage->tenant('env.x')->{version}, 7, 'staging serves what it points at';
    is $stage->tenant('env.x')->{digest}, $staged->{digest},
        '...and the digest moves with it, so the compile follows';

    # an environment this tenant has never heard of
    my $ghost = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
                                    environment => 'canary');
    $ghost->apply_bundle($bundle);
    is $ghost->tenant('env.x')->{version}, 1,
        'an unknown environment falls back to the published version';

    # ...and one that exists but points nowhere
    $stub->{tenants}[0]{environments}{canary} = { version => undef,
                                                  digest => undef };
    $ghost->apply_bundle($bundle);
    is $ghost->tenant('env.x')->{version}, 1,
        'an environment pointed nowhere is not an outage';
}

# Promotion and rollback are ordinary publishes: the digest moves, the
# compiled entry is dropped, the next request compiles the new one.
{
    my $stub = RegistryStub->new;
    my $v2 = $stub->add_version(version => 2,
        spec => RegistryStub->tenant_spec(2));
    $stub->add_tenant(host => 'promo.x', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    my $published = $stub->{tenants}[0]{digest};

    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
                                  environment => 'staging');
    my $bundle = sub { { tenants => $stub->{tenants}, domains => [],
                         challenges => [] } };

    $reg->apply_bundle($bundle->());
    my ($app) = $reg->resolve('promo.x');
    ok $app, 'it serves on the published version';
    is $reg->metrics->{compiles}, 1, 'compiled once';

    # point staging at v2
    $stub->{tenants}[0]{environments} = { staging => $v2 };
    $reg->apply_bundle($bundle->());
    is $reg->tenant('promo.x')->{digest}, $v2->{digest}, 'staging moved';
    ($app) = $reg->resolve('promo.x');
    is $reg->metrics->{compiles}, 2, 'and the new version compiled';

    # roll it back: the same action in the other direction
    $stub->{tenants}[0]{environments} = { staging =>
        { version => 1, digest => $published } };
    $reg->apply_bundle($bundle->());
    is $reg->tenant('promo.x')->{digest}, $published, 'rolled back';
}

done_testing;
