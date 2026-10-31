use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;
use Time::HiRes ();

use Maat::Registry;
use Maat::Router;

# Isolation - the whole risk of shared hosting. Two gates here:
#
#   GATE 3: a spec pathological to compile is rejected by the budget
#           without a single request on any other tenant slowing down.
#   GATE 4: a tenant whose upstream hangs does not reduce others'
#           throughput beyond its own concurrency ceiling.

# ---- gate 3a: the size cap (ten megabytes of schemas) ---------------------

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'good.x', proxy => 1, spec => RegistryStub->tenant_spec(1));
    $stub->add_tenant(host => 'big.x', proxy => 2,
        spec => RegistryStub->oversized_spec(6 * 1024 * 1024));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
        compile_budget => { seconds => 2, max_spec_bytes => 5 * 1024 * 1024, fork => 1 });
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my ($big) = $reg->resolve('big.x');
    is $big->({})->[0], 503, 'an oversized spec is rejected and served 503';
    ok $reg->is_poisoned('big.x'), 'the oversized host is poisoned';
    is $reg->metrics->{compile_rejected}, 1, 'the rejection is counted';
    ok !$reg->is_poisoned('good.x'), 'the healthy neighbour is untouched';
    ok +($reg->resolve('good.x'))[0], 'and still resolves';
}

# ---- gate 3b: the wall-clock budget, and confinement ----------------------
#
# This compiler memoises $ref resolution, so a deep or exponential chain
# is not actually slow to compile - which is a good property of the
# compiler, and means the honest way to prove the DEADLINE mechanism is a
# deterministically slow compile. The registry compiles through an
# injectable hook exactly so this can be tested without inventing a spec
# the compiler happens to be pathological about.

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'ok1.x', proxy => 1, spec => RegistryStub->tenant_spec(1));
    $stub->add_tenant(host => 'ok2.x', proxy => 2, spec => RegistryStub->tenant_spec(2));
    $stub->add_tenant(host => 'slow.x', proxy => 3, spec => RegistryStub->tenant_spec(3));

    my $reg = Maat::Registry->new(
        fetch_spec     => $stub->spec_fetcher,
        compile_budget => { seconds => 0.3, fork => 1 },
        compile        => sub {
            my ($bytes) = @_;
            # tenant 3's spec compiles forever; the parent's deadline must
            # kill it, and nothing else must feel it.
            Time::HiRes::sleep(30) if $bytes =~ /"const": 3\b/;
            return Open::API->new(spec => $bytes);
        },
    );
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    # Warm the healthy tenants so their next requests are pure cache hits.
    $reg->resolve('ok1.x');
    $reg->resolve('ok2.x');

    my $t0 = Time::HiRes::time();
    my ($slow) = $reg->resolve('slow.x');
    my $rejected_in = Time::HiRes::time() - $t0;

    is $slow->({})->[0], 503, 'a compile that runs past the deadline is rejected 503';
    ok $reg->is_poisoned('slow.x'), 'the slow host is poisoned';
    ok $rejected_in < 1.5,
        sprintf('the rejection is bounded by the budget (%.2fs, budget 0.3s)', $rejected_in);

    # Confinement: the healthy tenants' latency does not move. They are
    # resident, so their requests never enter the compile path the slow
    # tenant blew - and the reject ran in a forked child, not here.
    my @lat;
    for (1 .. 30) {
        my $ta = Time::HiRes::time();
        $reg->resolve($_ % 2 ? 'ok1.x' : 'ok2.x');
        push @lat, Time::HiRes::time() - $ta;
    }
    @lat = sort { $a <=> $b } @lat;
    ok $lat[15] < 0.001,
        sprintf('a neighbour resolve stays sub-millisecond after the rejection (%.6fs)', $lat[15]);
    is $reg->metrics->{hits} >= 30, 1, 'the neighbours served from cache throughout';
}

# ---- gate 3c: poison lifts when the spec is republished -------------------

{
    my $stub = RegistryStub->new;
    my $t = $stub->add_tenant(host => 'fixme.x', proxy => 1,
        spec => RegistryStub->oversized_spec(6 * 1024 * 1024));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
        compile_budget => { seconds => 2, max_spec_bytes => 5 * 1024 * 1024 });
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    $reg->resolve('fixme.x');
    ok $reg->is_poisoned('fixme.x'), 'poisoned on the bad spec';

    # Republish with a spec that fits.
    $stub->clear_tenants;
    $stub->add_tenant(host => 'fixme.x', proxy => 1, version => 2,
        spec => RegistryStub->tenant_spec(5));
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    ok !$reg->is_poisoned('fixme.x'), 'the poison lifts when the digest changes';
    my ($app) = $reg->resolve('fixme.x');
    is $app->(MaatTest::psgi_env(path => '/hello'))->[0], 200,
        'and the fixed spec now serves';
}

# ---- gate 4: a hung upstream consumes at most its own ceiling -------------

{
    # A never-resolving future models a request parked on a hung upstream:
    # Fetch is non-blocking on the loop, so a hung upstream is a parked
    # future holding a slot, not a stuck worker.
    package HungFuture;
    sub new { bless {}, shift }
    sub then { $_[0] }               # never resolves
    sub can  { $_[1] eq 'then' ? \&then : undef }
}

{
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 'hung.x', proxy => 1, plan => 'anon',
        spec => RegistryStub->tenant_spec(1));
    $stub->add_tenant(host => 'healthy.x', proxy => 2, plan => 'starter',
        spec => RegistryStub->tenant_spec(2));

    my $reg = Maat::Registry->new(
        fetch_spec => $stub->spec_fetcher,
        builder    => sub {
            my ($api, $meta) = @_;
            return sub { HungFuture->new } if $meta->{host} eq 'hung.x';
            return sub { [ 200, [ 'Content-Type' => 'application/json' ], [ '{"ok":1}' ] ] };
        },
    );
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my $router = Maat::Router->new(registry => $reg,
        caps => { anon => { concurrency => 4 } });
    my $app = $router->to_app;

    # Saturate the hung tenant: 4 requests park, the rest are 429.
    my @codes;
    for (1 .. 7) {
        my $env = MaatTest::psgi_env(path => '/hello');
        $env->{HTTP_HOST} = 'hung.x';
        my $res = $app->($env);
        push @codes, ref $res eq 'ARRAY' ? $res->[0] : 'parked';
    }
    is scalar(grep { $_ eq 'parked' } @codes), 4,
        'the hung tenant holds exactly its ceiling of 4 slots';
    is scalar(grep { $_ eq 429 } @codes), 3,
        'everything past the ceiling is 429, not a stuck worker';
    is $router->inflight(1), 4, 'four slots remain held by the hung upstream';

    # The healthy tenant serves at full throughput throughout.
    my $served = 0;
    for (1 .. 100) {
        my $env = MaatTest::psgi_env(path => '/hello');
        $env->{HTTP_HOST} = 'healthy.x';
        my ($s) = MaatTest::run_app($app, $env);
        $served++ if $s == 200;
    }
    is $served, 100, 'the healthy tenant serves 100/100 while its neighbour is saturated';

    my $tm = $router->tenant_metrics(1);
    is $tm->{rejected_concurrency}, 3, 'the ceiling rejections are counted per-tenant';
    is $router->inflight(2), 0, 'the healthy tenant held no slots (all completed)';
}

done_testing;
