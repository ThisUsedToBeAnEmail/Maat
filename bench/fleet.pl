#!/usr/bin/env perl
use 5.010;
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../blib/arch";
use lib "$FindBin::Bin/../blib/lib";
use lib "$FindBin::Bin/../t/lib";
use lib "$FindBin::Bin/../lib";
use MaatTest;                 # puts the sibling blibs on @INC
use RegistryStub;
use Maat::Registry;
use Maat::Poller;
use Maat::Router;
use Time::HiRes ();

# Phase 12a: the dispatch toll, MEASURED before anything is built.
#
# A hosted request pays Perl frames between Hyperman and mt_serve -
# Fleet's wrapper, Router::_dispatch, Registry::resolve, the gateway
# app closure - to reach a request path that is C on both sides of
# them. This prints what those frames cost per request, which is the
# number phase 12 exists to delete and the number that says how much
# of 12d (response completion in C) the margin actually needs.
#
# Mock-mode tenants on purpose: a mock answers from the document in C
# with no upstream and no future, so the difference between the rows
# below is dispatch and nothing else.
#
# Run:  perl bench/fleet.pl [tenants] [iterations]
# and transcribe the block into bench/RESULTS.md, naming the machine.

my $TENANTS = $ARGV[0] || 1000;
my $ITERS   = $ARGV[1] || 200_000;
my $REPS    = $ARGV[2] || 7;

# ---- the fleet, as t/28 builds it -------------------------------------------

my $stub = RegistryStub->new(token => 'bench-token');
$stub->add_tenant(host => "t$_.openapi-proxy.com", proxy => $_,
    plan => 'team', spec => RegistryStub->tenant_spec($_))
    for 1 .. $TENANTS;

my $reg = Maat::Registry->new(
    fetch_spec => $stub->spec_fetcher,
    max_specs  => $TENANTS + 1,               # no evictions mid-measure
);
Maat::Poller->new(registry => $reg, url => 'http://bench/registry/bundle',
    token => 'bench-token', fetch => $stub->fetcher)->poll_once eq 'applied'
    or die "bench: the bundle did not apply\n";

my $router = Maat::Router->new(registry => $reg);
my $fleet_app = $router->to_app;

# Touch every tenant once so the measurement sees warm cache hits, not
# compiles - the miss cost is capacity.pl's number, not this one's.
sub env_for {
    my ($host) = @_;
    my $env = MaatTest::psgi_env(path => '/hello');
    $env->{HTTP_HOST} = $host;
    return $env;
}
for my $i (1 .. $TENANTS) {
    my ($s) = MaatTest::run_app($fleet_app, env_for("t$i.openapi-proxy.com"));
    die "bench: tenant $i answered $s" unless $s == 200;
}

# The bare floor: the same compiled gateway, called at its C entry with
# no dispatch in front - what a request costs once phase 12 lands.
my ($gw_app) = $reg->resolve('t1.openapi-proxy.com');

# ---- the clock --------------------------------------------------------------

# Best of REPS rounds, like bench/gateway.pl. A single round on a busy
# machine is not a measurement: three consecutive runs of this file gave
# tolls of 0.66, 2.60 and 1.62us, which is not a 4x change in the code.
# The best round is the one least disturbed by everything else running.
sub rate {
    my ($label, $iters, $code) = @_;
    my $best;
    for (1 .. $REPS) {
        my $t0 = Time::HiRes::time();
        $code->() for 1 .. $iters;
        my $dt = Time::HiRes::time() - $t0;
        $best = $dt if !defined $best || $dt < $best;
    }
    printf "  %-34s %8.0f req/s   %7.3f us/req\n",
        $label, $iters / $best, $best / $iters * 1e6;
    return $best / $iters * 1e6;
}

# Rotate hosts so the hash lookups see the whole table rather than one
# hot bucket; one env per host, built outside the timed loop.
my @envs = map { env_for("t$_.openapi-proxy.com") } 1 .. $TENANTS;
my $i = 0;

printf "fleet dispatch toll - %d tenants, %d iterations, best of %d\n\n",
    $TENANTS, $ITERS, $REPS;

my $bare = rate('bare gateway (mt_serve, no fleet)', $ITERS, sub {
    $gw_app->($envs[0]);
});

my $resolve = rate('registry resolve alone', $ITERS, sub {
    $reg->resolve($i++ % $TENANTS % 2 ? 't1.openapi-proxy.com'
                                      : 't2.openapi-proxy.com');
});

my $full = rate('full fleet dispatch (Router+resolve)', $ITERS, sub {
    $fleet_app->($envs[$i++ % $TENANTS]);
});

printf "\n  the toll: %.3f us/req (%.0f%% on top of the C path)\n",
    $full - $bare, ($full - $bare) / $bare * 100;
printf "  at 100kr/s/worker that is %.1f cores of pure dispatch per 10 workers\n",
    ($full - $bare) * 1e-6 * 100_000 * 10;
