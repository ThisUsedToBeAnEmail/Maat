#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use Time::HiRes ();
use File::Temp ();

use Maat::Config;
use Maat::Gateway;

# Phase 3, gate 1: violations at volume must not slow the customer down.
#
# The plan asks for 10,000 violations a minute with no measurable change
# to p99 against the same run with reporting off. 10,000/minute is 167 a
# second; this drives far more than that as fast as the machine will go,
# which is the harder version of the same question.
#
# What is being compared is the SAME work with the pipeline on and off,
# so the comparison holds even on a noisy machine: both arms proxy, both
# arms validate, both arms fail. Only the recording differs.

plan skip_all => 'set MAAT_LOAD to run the violation load gate'
    unless $ENV{MAAT_LOAD};

my $SECS = $ENV{MAAT_LOAD_SECS} || 3;   # per arm

# The upstream is a coderef, not a socket. A real round trip is hundreds
# of microseconds and would bury the thing being measured - and worse,
# would put the two arms' difference inside the network's noise, which is
# how a latency gate ends up passing because it measured nothing. What is
# under test is what RECORDING costs, so everything else is held still.
my $FORWARD = sub {
    return [ 200, [ 'Content-Type' => 'application/json',
                    'Content-Length' => 2 ], [ '{}' ] ];
};

sub gateway {
    my (%report) = @_;
    my $config = Maat::Config->from_hash({
        upstream => 'http://127.0.0.1:9',
        spec     => spec_path('petstore.json'),
        mode     => 'observe',
        report   => \%report,
    });
    my $g = Maat::Gateway->new(config => $config);
    $g->{proxy} = $FORWARD;
    return $g;
}

# Every request violates: limit=500 is over the declared maximum.
#
# Driven for a duration rather than a count, because the window is
# measured in whole seconds - a run that finishes inside one second
# closes no window, and a gate that never flushed would be measuring the
# cheap half of the pipeline and reporting it as the answer.
sub drive {
    my ($app, $seconds) = @_;
    my @us;
    my $until = Time::HiRes::time() + $seconds;
    while (Time::HiRes::time() < $until) {
        for (1 .. 200) {                       # check the clock in batches
            my $env = psgi_env(method => 'GET', path => '/pets',
                               query => 'limit=500');
            my $t0  = Time::HiRes::time();
            $app->($env);
            push @us, (Time::HiRes::time() - $t0) * 1e6;
        }
    }
    my @sorted = sort { $a <=> $b } @us;
    return {
        n   => scalar @sorted,
        p50 => $sorted[ int(@sorted * 0.50) ],
        p99 => $sorted[ int(@sorted * 0.99) ],
        max => $sorted[-1],
    };
}

# ---- the two arms -----------------------------------------------------------

my $spool_dir = File::Temp::tempdir(CLEANUP => 1);

# off: violations are counted and thrown away
my $off = gateway(window => 1_000_000);      # a window that never closes
$off->{violation}{max_keys} = 0;             # and nothing is remembered
my $off_app = $off->to_app;

# on: the shipped pipeline - aggregate, close windows, spool to disk.
#
# One second rather than the shipped ten, so several windows close
# inside the run. Every flush and every spool write then lands on the
# request path being timed - at the default a run this short would close
# no window at all, and the gate would pass having measured only the
# cheap half of the pipeline.
my $on = gateway(window => 1, spool => $spool_dir);
my $on_app = $on->to_app;

# warm both, so neither pays for the first-time paths
drive($off_app, 0.3);
drive($on_app, 0.3);

my $a = drive($off_app, $SECS);
my $b = drive($on_app, $SECS);

diag(sprintf "reporting off: p50 %.1fus  p99 %.1fus  max %.1fus",
     $a->{p50}, $a->{p99}, $a->{max});
diag(sprintf "reporting on:  p50 %.1fus  p99 %.1fus  max %.1fus",
     $b->{p50}, $b->{p99}, $b->{max});
diag(sprintf "%d violations, %d aggregated records, %d spool files",
     $on->counters->{occurrences}, $on->counters->{aggregated},
     $on->spool ? $on->spool->depth : 0);

ok($a->{n} > 1000, "$a->{n} requests through the arm with reporting off");
ok($b->{n} > 1000, "$b->{n} through the arm with it on");

# Both halves fail, and both are real: the query parameter is over its
# declared maximum, and the stub's `{}` is not the array the 200
# declares. A gateway seeing both ends of a contract break at once is
# the load this is supposed to survive. (Not one response violation per
# request - response checking is sampled, which is the point of it.)
cmp_ok($on->counters->{violation}, '>', $b->{n},
    'more violations than requests: both halves of the contract failed');
cmp_ok($on->counters->{response_violation}, '>', 0,
    '...including the sampled responses');

# The point of aggregation: what leaves is proportional to the number of
# distinct problems, not to the number of requests.
cmp_ok($on->counters->{aggregated}, '<', 200,
    sprintf('%d occurrences became %d records',
            $on->counters->{occurrences}, $on->counters->{aggregated}));
ok($on->counters->{windows} > 1,
    "windows actually closed during the run ($on->{violation}{counters}{windows})");
ok($on->spool->depth > 0 || $on->spool->counters->{spooled} > 0,
    'and reached the spool, so the flush is inside what was timed');

# Gate 1 itself. The bound is on p99 rather than the mean because the
# mean would hide exactly the failure that matters here - a flush that
# occasionally stalls one request while the rest stay fast.
my $p99_delta = $b->{p99} - $a->{p99};
diag(sprintf "p99 delta: %+.1fus (%.1f%%)",
     $p99_delta, 100 * $p99_delta / $a->{p99});

cmp_ok($b->{p99}, '<', $a->{p99} * 1.25 + 20,
    sprintf('p99 with reporting on (%.1fus) is not measurably worse than '
          . 'with it off (%.1fus)', $b->{p99}, $a->{p99}));

# And the same for the worst single request: the flush is on the request
# path, so if it were expensive it would show up here first.
cmp_ok($b->{max}, '<', 50_000,
    sprintf('no request was stalled by the pipeline (worst %.0fus)', $b->{max}));

done_testing();
