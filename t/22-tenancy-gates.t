use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Maat::Registry;
use Maat::Router;
use Maat::Config;

# The two headline phase-6 gates:
#
#   GATE 1: 1000 tenants on one worker, each a distinct compiled spec,
#           all serving, the registry inside its memory cap.
#   GATE 2: a tenant publishes a new version under sustained load on the
#           others - zero dropped requests, and every response
#           attributable to exactly one version, body and marker agreeing
#           (no half-applied request ever sees a mix).

my $N = $ENV{MAAT_TENANTS} || 1000;

# ---- gate 1 ----------------------------------------------------------------

{
    my $stub = RegistryStub->new;
    for my $i (1 .. $N) {
        $stub->add_tenant(host => "t$i.openapi-proxy.com", proxy => $i,
            version => 1, plan => ($i % 3 ? 'starter' : 'anon'),
            spec => RegistryStub->tenant_spec($i));
    }

    # A cap high enough for the whole fleet, so gate 1 keeps all 1000
    # resident and we can read the true resident-bytes figure the capacity
    # model rests on.
    my $reg = Maat::Registry->new(
        fetch_spec => $stub->spec_fetcher,
        max_specs  => $N + 10,
        max_bytes  => 512 * 1024 * 1024,
    );
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my $router = Maat::Router->new(registry => $reg);
    my $app    = $router->to_app;

    # Serve one request to every tenant: each compiles once, lazily, and
    # answers from ITS OWN spec.
    my $wrong = 0;
    for my $i (1 .. $N) {
        my $env = MaatTest::psgi_env(path => '/hello');
        $env->{HTTP_HOST} = "t$i.openapi-proxy.com";
        my ($s, $h, $b) = MaatTest::run_app($app, $env);
        $wrong++ unless $s == 200
            && $b =~ /"tenant":$i\b/
            && MaatTest::header_get($h, 'X-Maat-Proxy') == $i;
    }
    is $wrong, 0, "all $N tenants serve their own distinct spec, each attributable";
    is $reg->metrics->{specs_resident}, $N, "$N distinct specs are resident at once";
    is $reg->metrics->{compiles}, $N, 'each was compiled exactly once (lazy, no recompiles)';
    is $reg->metrics->{evictions}, 0, 'nothing was evicted - the fleet fits the cap';
    ok $reg->resident_bytes <= 512 * 1024 * 1024,
        'the registry is inside its memory cap';

    diag sprintf('gate 1: %d tenants, %.2f MB resident spec bytes, %.0f bytes/spec',
        $N, $reg->resident_bytes / (1024 * 1024), $reg->resident_bytes / $N);
}

# ---- gate 1b: the LRU keeps a worker bounded past its cap ------------------

{
    my $cap  = 200;
    my $over = 500;
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => "u$_.x", proxy => $_, spec => RegistryStub->tenant_spec($_))
        for 1 .. $over;
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher, max_specs => $cap);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    MaatTest::run_app(Maat::Router->new(registry => $reg)->to_app, do {
        my $e = MaatTest::psgi_env(path => '/hello'); $e->{HTTP_HOST} = "u$_.x"; $e;
    }) for 1 .. $over;

    is $reg->metrics->{specs_resident}, $cap,
        "a worker asked for $over tenants holds only its cap of $cap";
    is $reg->metrics->{evictions}, $over - $cap, 'the overflow was evicted by LRU';
}

# ---- gate 2: publish under sustained load ----------------------------------

{
    # Two versions of tenant A, each with a body marker that says which
    # version it is: v1 -> {"tenant":1}, v2 -> {"tenant":2}. The rest of
    # the fleet takes the "sustained load" while A is republished.
    my $spec_v1 = RegistryStub->tenant_spec(1);
    my $spec_v2 = RegistryStub->tenant_spec(2);

    my $stub = RegistryStub->new;
    my $A = $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 1,
        version => 1, spec => $spec_v1);
    $stub->add_spec($spec_v2);
    # background load tenants
    $stub->add_tenant(host => "load$_.openapi-proxy.com", proxy => 10 + $_,
        version => 1, spec => RegistryStub->tenant_spec(100 + $_)) for 1 .. 5;

    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    my $publish = sub {
        my ($ver, $spec) = @_;
        $A->{version} = $ver;
        $A->{digest}  = Digest::SHA::sha256_hex($spec);
        $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    };
    require Digest::SHA;
    $publish->(1, $spec_v1);

    my $router = Maat::Router->new(registry => $reg);
    my $app    = $router->to_app;

    my %marker = (1 => 1, 2 => 2);        # version -> expected body tenant marker
    my $dropped        = 0;
    my $mismatched     = 0;
    my $unversioned    = 0;
    my %versions_seen;

    # Interleave requests to A and the load tenants with republishes of A.
    for my $step (1 .. 600) {
        # Every 25 steps, flip A's version - a publish landing amid load.
        if ($step % 25 == 0) {
            my $to = ($step / 25) % 2 ? 2 : 1;
            $publish->($to, $to == 2 ? $spec_v2 : $spec_v1);
        }

        my $host = $step % 2 ? 'a.openapi-proxy.com'
                             : 'load' . (($step % 5) + 1) . '.openapi-proxy.com';
        my $env = MaatTest::psgi_env(path => '/hello');
        $env->{HTTP_HOST} = $host;
        my ($s, $h, $b) = MaatTest::run_app($app, $env);

        $dropped++ unless $s == 200;      # zero-dropped is the gate

        next unless $host eq 'a.openapi-proxy.com';
        my $v = MaatTest::header_get($h, 'X-Maat-Version');
        if (!defined $v) { $unversioned++; next }
        $versions_seen{$v}++;
        # The body must match the version stamped on the SAME response -
        # a half-applied publish would show v2 with a v1 body, or a torn
        # object. It never does, because the swap is atomic and each
        # request holds one compiled object start to finish.
        $mismatched++ unless $b =~ /"tenant":$marker{$v}\b/;
    }

    is $dropped, 0, 'gate 2: zero dropped requests through the publishes';
    is $unversioned, 0, 'every response to the republished tenant carried a version';
    is $mismatched, 0, 'every response body matched its own stamped version (no torn state)';
    ok +(keys %versions_seen) >= 2, 'both versions were actually served during the run'
        or diag 'versions seen: ' . join(',', sort keys %versions_seen);
}

# ---- gate: the plan decides how much is validated ----------------------------
#
# The same shape as the enforce gate. What a tenant may have is decided
# from its plan, here, and not by trusting the value that arrived beside
# it - so a bundle claiming `all` for a free tenant is clamped, not
# honoured. The control plane resolves '1%' into a divisor before it
# ships; this end only ever sees the gateway's own vocabulary.
{
    my @case = (
        # allowance      what the bundle said   what must be served
        [ '1%',          undef,        100,        'free gets 1-in-100'          ],
        [ '1%',          'all',        100,        '...even when the bundle says all' ],
        [ 'adaptive',    'all',        'adaptive', 'an adaptive plan stays adaptive'  ],
        [ 'configurable','250',        250,        'configurable is taken at its word' ],
        [ 'configurable',undef,        'adaptive', '...and defaults to adaptive'      ],
        [ undef,         undef,        'adaptive', 'no allowance leaves the default'  ],
    );

    for my $c (@case) {
        my ($allow, $said, $want, $why) = @$c;
        my $config = Maat::Config->tenant(
            limits   => { requests => 10_000, enforce => 0,
                          (defined $allow ? (sampling => $allow) : ()) },
            sampling => $said,
        );
        is $config->responses->{sample}, $want, $why;
    }
}

# And the seam between them: the bundle's `sampling` has to actually
# reach Config->tenant. The registry exposes the app and its meta but not
# the gateway it built, so this watches the call itself - which is the
# thing worth pinning, because a value that is carried the whole way and
# then dropped on the floor is exactly the bug this feature was.
{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'free.openapi-proxy.com', proxy => 91,
        spec => RegistryStub->tenant_spec(91),
        plan => 'free', sampling => 'all',
        limits => { requests => 10_000, enforce => 0, sampling => '1%' });

    my %seen;
    my $config;
    my $orig = \&Maat::Config::tenant;
    {
        no warnings 'redefine';
        local *Maat::Config::tenant = sub {
            my ($class, %o) = @_;
            %seen = %o;
            return $config = $orig->($class, %o);
        };

        my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
        $reg->apply_bundle({ tenants => $stub->{tenants},
                             domains => [], challenges => [] });
        my ($app) = $reg->resolve('free.openapi-proxy.com');
        ok $app, 'the free tenant resolves through the default builder';
    }

    is $seen{sampling}, 'all',
        'the builder hands the bundle sampling to Config->tenant';
    is $config->responses->{sample}, 100,
        '...which clamps it to the plan on the way in';
}

done_testing;
