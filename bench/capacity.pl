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
use Maat::Router;
use Open::API ();
use Time::HiRes ();

# The capacity model, MEASURED on this machine, not estimated. It answers
# the four questions the pricing rests on:
#
#   1. resident bytes per compiled spec (small / median / large)
#   2. tenants per worker at the LRU cap, and the cost of a miss
#   3. requests/second per box at 1% and 100% response sampling
#   4. GBP per million requests, from a named instance price
#
# Run:  perl bench/capacity.pl [copies]
# and transcribe the block it prints into bench/CAPACITY.md, naming the
# machine.

my $COPIES = $ARGV[0] || 2000;

# ---- RSS helper ------------------------------------------------------------
# Resident set size of this process, in bytes. macOS ps reports KB.
sub rss_bytes {
    my $kb = `ps -o rss= -p $$`;
    $kb =~ s/\D//g;
    return ($kb || 0) * 1024;
}

# ---- the three spec sizes --------------------------------------------------

my $small  = RegistryStub->tenant_spec(1);                     # ~0.4 KB, 1 op
my $median = do { open my $fh, '<', MaatTest::spec_path('petstore.json'); local $/; <$fh> };
my $large  = big_spec(60);                                     # 60 ops, refs

sub big_spec {
    my ($ops) = @_;
    my %paths;
    for my $i (1 .. $ops) {
        $paths{"/things/$i/{id}"} = {
            get => {
                operationId => "getThing$i",
                parameters  => [ { name => 'id', in => 'path', required => \1,
                                   schema => { type => 'integer' } } ],
                responses   => { '200' => { description => 'a thing',
                    content => { 'application/json' =>
                        { schema => { '$ref' => '#/components/schemas/Thing' } } } } },
            },
            post => {
                operationId => "putThing$i",
                requestBody => { required => \1, content => { 'application/json' =>
                    { schema => { '$ref' => '#/components/schemas/Thing' } } } },
                responses   => { '201' => { description => 'made',
                    content => { 'application/json' =>
                        { schema => { '$ref' => '#/components/schemas/Thing' } } } } },
            },
        };
    }
    my $doc = {
        openapi => '3.1.0', info => { title => 'Big', version => '1.0.0' },
        paths   => \%paths,
        components => { schemas => { Thing => {
            type => 'object', required => ['id', 'name'],
            properties => {
                id    => { type => 'integer' },
                name  => { type => 'string', minLength => 1, maxLength => 200 },
                tags  => { type => 'array', items => { type => 'string' } },
                meta  => { type => 'object', additionalProperties => { type => 'string' } },
                price => { type => 'number', minimum => 0 },
            },
        } } },
    };
    require File::Raw::JSON;
    return File::Raw::JSON::file_json_encode($doc);
}

# ---- 1. resident bytes per compiled spec -----------------------------------

sub measure_rss {
    my ($label, $spec, $copies) = @_;
    # Force each copy to be a genuinely distinct compiled object by giving
    # each a unique operationId prefix, so the compiler cannot share state.
    my @keep;
    my $before = rss_bytes();
    for my $i (1 .. $copies) {
        my $s = $spec;
        $s =~ s/"operationId": "/"operationId": "c${i}_/g;
        push @keep, Open::API->new(spec => $s);
    }
    my $after = rss_bytes();
    my $per   = ($after - $before) / $copies;
    return { label => $label, bytes => length($spec), per => $per,
             ops => scalar @{ $keep[0]->operations }, keep => \@keep };
}

my $rss_small  = measure_rss('small',  $small,  $COPIES);
my $rss_median = measure_rss('median', $median, $COPIES);
my $rss_large  = measure_rss('large',  $large,  int($COPIES / 4) || 1);

# ---- 2. cost of a miss (fetch stub + verify + compile) ---------------------

sub compile_time {
    my ($spec, $reps) = @_;
    my $stub = RegistryStub->new;
    my $t = $stub->add_tenant(host => 'x.openapi-proxy.com', proxy => 1, spec => $spec);
    my $best;
    for (1 .. $reps) {
        my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
        $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
        my $t0 = Time::HiRes::time();
        $reg->resolve('x.openapi-proxy.com');    # the whole miss: fetch+verify+compile+build
        my $dt = Time::HiRes::time() - $t0;
        $best = $dt if !defined $best || $dt < $best;
    }
    return $best;
}

my $miss_small  = compile_time($small,  20);
my $miss_median = compile_time($median, 20);
my $miss_large  = compile_time($large,  20);

# ---- 3. requests/second through the edge (routing + mock serve) ------------

sub serve_throughput {
    my ($n) = @_;
    my $stub = RegistryStub->new;
    $stub->add_tenant(host => 't.openapi-proxy.com', proxy => 1,
        spec => RegistryStub->tenant_spec(1));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });
    my $app = Maat::Router->new(registry => $reg)->to_app;
    my $env = MaatTest::psgi_env(path => '/hello');
    $env->{HTTP_HOST} = 't.openapi-proxy.com';
    $app->($env);   # warm (compile)

    my $best;
    for (1 .. 5) {
        my $t0 = Time::HiRes::time();
        for (1 .. $n) { $app->($env) }
        my $dt = Time::HiRes::time() - $t0;
        my $rps = $n / $dt;
        $best = $rps if !defined $best || $rps > $best;
    }
    return $best;
}

my $edge_rps = serve_throughput(50_000);

# ---- 4. response-validation cost, 1% vs 100% -------------------------------
# Reuse the phase-2 measured per-request figures (bench/RESULTS.md): the
# Maat-added request path is 2.32us, response validation adds 0.20us at
# the 1% default and 1.02us at 100%. req/s per CORE is 1e6 / us.
my $us_req_only = 2.32;
my $us_at_1pct  = 2.52;
my $us_at_100   = 3.34;

my $CORES = num_cores();
sub num_cores {
    my $n = `sysctl -n hw.ncpu 2>/dev/null` || `nproc 2>/dev/null` || 8;
    $n =~ s/\D//g;
    return $n || 8;
}

# ---- derive tenants/worker and GBP/million ---------------------------------
# A named instance: Hetzner CCX33 (dedicated vCPU), 8 vCPU / 32 GB, about
# EUR 64.34 / month at 2026 list, ~= GBP 55 / month (EUR->GBP 0.855). State
# the assumption; swap the constants to reprice.
my $INSTANCE   = 'Hetzner CCX33 (8 dedicated vCPU, 32 GB RAM)';
my $GBP_MONTH  = 55.0;
my $RAM_GB     = 32;
my $WORKER_RAM_BUDGET = 1.5 * 1024 * 1024 * 1024;   # 1.5 GB of compiled specs per worker

my $tenants_per_worker_median = int($WORKER_RAM_BUDGET / $rss_median->{per});
my $box_rps_1pct  = ($CORES * 1e6 / $us_at_1pct);
my $box_rps_100   = ($CORES * 1e6 / $us_at_100);
my $secs_month    = 30 * 86400;
# The pricing basis is a SUSTAINED throughput, not the microbenchmark
# ceiling: real traffic is bursty and a box run flat out all month is a
# fiction. Anchor on the MEASURED single-worker edge throughput as a
# conservative whole-box sustained rate (a box runs many workers but also
# does the socket I/O this mock-serve loop skips, so one worker's serve
# rate is a defensible floor for the whole box), at 20% sustained
# utilisation.
my $UTIL = 0.20;
my $sustained_rps   = $edge_rps;                          # measured, conservative
my $reqs_month_1pct = $sustained_rps * $UTIL * $secs_month;
my $gbp_per_million = $GBP_MONTH / ($reqs_month_1pct / 1e6);

# ---- print -----------------------------------------------------------------

printf "machine        : %s cores, %s\n", $CORES, `uname -sm` =~ s/\n//r;
printf "instance model : %s, GBP %.2f/mo\n\n", $INSTANCE, $GBP_MONTH;

print "1. RESIDENT BYTES PER COMPILED SPEC\n";
printf "   %-8s %6d B source, %2d ops -> %8.0f B resident/spec\n",
    $_->{label}, $_->{bytes}, $_->{ops}, $_->{per}
    for ($rss_small, $rss_median, $rss_large);

print "\n2. COST OF A MISS (fetch-stub + verify + compile + build)\n";
printf "   %-8s %7.3f ms\n", 'small',  $miss_small  * 1000;
printf "   %-8s %7.3f ms\n", 'median', $miss_median * 1000;
printf "   %-8s %7.3f ms\n", 'large',  $miss_large  * 1000;

printf "\n   tenants/worker at a %.1f GB compiled-spec budget (median spec): %d\n",
    $WORKER_RAM_BUDGET / (1024**3), $tenants_per_worker_median;

print "\n3. REQUESTS/SECOND\n";
printf "   edge routing + mock serve, one worker : %10.0f req/s\n", $edge_rps;
printf "   per-core ceiling (Maat-added path):\n";
printf "     request validation only  %5.2f us -> %10.0f req/s/core\n",
    $us_req_only, 1e6 / $us_req_only;
printf "     + response @ 1%%         %5.2f us -> %10.0f req/s/core\n",
    $us_at_1pct, 1e6 / $us_at_1pct;
printf "     + response @ 100%%       %5.2f us -> %10.0f req/s/core\n",
    $us_at_100, 1e6 / $us_at_100;
printf "   per-box (%d cores):  1%%: %11.0f req/s   100%%: %11.0f req/s\n",
    $CORES, $box_rps_1pct, $box_rps_100;

print "\n4. GBP PER MILLION REQUESTS\n";
printf "   sustained basis: %.0f req/s/box (measured single-worker serve), %.0f%% util\n",
    $sustained_rps, $UTIL * 100;
printf "   %.1f B requests/month/box -> GBP %.5f per million\n",
    $reqs_month_1pct / 1e9, $gbp_per_million;

print "\n5. STARTER MARGIN CHECK (1M requests/month at GBP 29)\n";
my $cogs_starter = 1 * $gbp_per_million;    # 1M requests
printf "   infra COGS of 1M requests: GBP %.5f  -> gross margin %.3f%%\n",
    $cogs_starter, 100 * (1 - $cogs_starter / 29);
printf "   (clears the 80%% margin bar: %s)\n",
    (100 * (1 - $cogs_starter / 29) >= 80 ? 'YES' : 'NO');
