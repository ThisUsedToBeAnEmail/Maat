#!perl
use 5.010;
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib";
use Test::More;
use Maat::Sampler ();

# Choosing N for Open::API's 1-in-N gate. The two properties that matter:
# the validated rate per operation stays under the budget however much
# traffic arrives, and a quiet operation is still covered rather than
# merely cheap.

# A retune needs the interval to have elapsed, so the tests drive the
# clock rather than sleep through it.
sub cov { my %t = @_; return { map { $_ => { total => $t{$_} } } keys %t } }

# ---- under budget: validate everything --------------------------------------
{
    my $s = Maat::Sampler->new(budget => 50, floor => 10, interval => 1);
    my $t = time;
    $s->retune(cov(getPet => 0), $t);
    $s->retune(cov(getPet => 10), $t + 1);      # 10/s, well under 50
    is($s->divisor('getPet'), 1, '10 responses a second: validate all of them');
}

# ---- over budget: thin out to the budget ------------------------------------
{
    my $s = Maat::Sampler->new(budget => 50, floor => 10, interval => 1);
    my $t = time;
    $s->retune(cov(getPet => 0), $t);
    $s->retune(cov(getPet => 500), $t + 1);     # 500/s against a budget of 50
    is($s->divisor('getPet'), 10, '500/s at a budget of 50 is 1-in-10');

    $s->retune(cov(getPet => 500 + 5000), $t + 2);
    is($s->divisor('getPet'), 100, 'ten times the traffic, ten times the divisor');
}

# the point of all of it: the validated rate is bounded
{
    my $s = Maat::Sampler->new(budget => 50, floor => 10, interval => 1);
    my $t = time;
    my $total = 0;
    for my $rate (10, 200, 5_000, 250_000) {
        $s->retune(cov(getPet => $total), $t++);
        $total += $rate;
        $s->retune(cov(getPet => $total), $t);
        my $validated = $rate / $s->divisor('getPet');
        cmp_ok($validated, '<=', 50,
            "at $rate/s the validated rate is $validated, inside the budget");
    }
}

# ---- the floor: a quiet operation stays covered -----------------------------
{
    my $s = Maat::Sampler->new(budget => 50, floor => 10, interval => 1);
    my $t = time;
    $s->retune(cov(sleepy => 0), $t);
    $s->retune(cov(sleepy => 1), $t + 20);      # one response in twenty seconds
    is($s->divisor('sleepy'), 1,
        'a trickle is validated in full - there is nothing cheaper to do');
}

# whatever the traffic, N never grows past what the floor allows
{
    my $s = Maat::Sampler->new(budget => 0.01, floor => 10, interval => 1);
    my $t = time;
    $s->retune(cov(op => 0), $t);
    $s->retune(cov(op => 20), $t + 1);          # 20/s, an absurdly low budget
    my $n = $s->divisor('op');
    cmp_ok($n, '<=', 20 * 10,
        'the floor caps the divisor: one validated response per 10s at worst');
    cmp_ok(20 / $n, '>=', 1 / 10,
        '...which is what "at least one per floor seconds" means');
}

# ---- per operation, not per process -----------------------------------------
{
    my $s = Maat::Sampler->new(budget => 50, floor => 10, interval => 1);
    my $t = time;
    $s->retune(cov(hot => 0, cold => 0), $t);
    $s->retune(cov(hot => 5_000, cold => 3), $t + 1);
    is($s->divisor('hot'), 100, 'the busy operation is thinned');
    is($s->divisor('cold'), 1,
        'and the quiet one is untouched - one endpoint cannot spend '
      . 'the whole budget and leave the rest uncovered');
}

# ---- an unseen operation is validated until we know better ------------------
{
    my $s = Maat::Sampler->new;
    is($s->divisor('never-seen'), 1, 'no traffic history: validate');
}

# ---- the interval ------------------------------------------------------------
{
    my $s = Maat::Sampler->new(budget => 50, interval => 5);
    my $t = time;
    ok(!$s->retune(cov(op => 0), $t),
        'no retune before an interval has elapsed - there is no window '
      . 'to measure a rate over yet');
    ok($s->retune(cov(op => 0), $t + 5), 'the first one runs at the interval');
    ok(!$s->retune(cov(op => 10_000), $t + 6), 'too soon: no arithmetic');
    ok(!$s->retune(cov(op => 20_000), $t + 9), 'still too soon');
    is($s->divisor('op'), 1, 'and the divisor is untouched meanwhile');
    ok($s->retune(cov(op => 30_000), $t + 10), 'the interval elapsed');
    cmp_ok($s->divisor('op'), '>', 1, 'now it has moved');
}

# ---- the fixed and off modes -------------------------------------------------
#
# Fixed is a ceiling, not a promise to look away: the floor may lower the
# divisor, and nothing may raise it.
{
    my $s = Maat::Sampler->new(mode => 'fixed', fixed => 7);
    is($s->divisor('anything'), 7, 'fixed: the configured divisor to start');
    my $t = time;
    ok($s->retune(cov(anything => 1_000_000), $t + 60),
        'fixed retunes - the floor has to be able to reach it');
    is($s->divisor('anything'), 7,
        '...and busy traffic leaves the ceiling exactly where it was');
}
{
    # 1-in-100 against two responses a minute. Unclamped that is one
    # validated response every fifty minutes; the floor says ten seconds,
    # so the divisor has to come all the way down to 1.
    my $s = Maat::Sampler->new(mode => 'fixed', fixed => 100, floor => 10);
    my $t = time;
    $s->retune(cov(quiet => 0), $t);
    $s->retune(cov(quiet => 2), $t + 60);
    is($s->divisor('quiet'), 1,
        'fixed: the floor overrides the ceiling on a quiet operation');
}
{
    # The same sampler where the ceiling is the interesting number:
    # 500/s * floor 10 = 5000, well above 100, so 100 stands.
    my $s = Maat::Sampler->new(mode => 'fixed', fixed => 100, floor => 10);
    my $t = time;
    $s->retune(cov(busy => 0), $t);
    $s->retune(cov(busy => 5_000), $t + 10);
    is($s->divisor('busy'), 100, 'fixed: 1-in-100 stands at volume');
}
{
    my $s = Maat::Sampler->new(mode => 'fixed', fixed => 1);
    my $t = time;
    $s->retune(cov(all => 0), $t);
    $s->retune(cov(all => 100_000), $t + 1);
    is($s->divisor('all'), 1,
        '`sample: all` is 1 and stays 1 whatever the traffic');
}
{
    my $s = Maat::Sampler->new(mode => 'off');
    is($s->divisor('anything'), 0, 'off: nothing is validated');

    # The request path guards retune with next_at and builds the coverage
    # hash to pass in, so a next_at that never advances turns a
    # once-an-interval cost into a per-response one.
    my $t = time;
    my $was = $s->{next_at};
    ok(!$s->retune(cov(anything => 10), $t + 60), 'off does not recompute');
    cmp_ok($s->{next_at}, '>', $was, '...but it does advance its clock');
}
{
    my $s = Maat::Sampler->new(mode => 'fixed', fixed => 4);
    my $t = time;
    my $was = $s->{next_at};
    $s->retune(cov(op => 10), $t + 60);
    cmp_ok($s->{next_at}, '>', $was, 'fixed advances its clock too');
}

# ---- a counter that went backwards -------------------------------------------
# A recompiled spec resets Open::API's per-operation counters. The delta
# would be negative, which would make the rate negative and the divisor
# nonsense; the sampler treats it as a fresh start instead.
{
    my $s = Maat::Sampler->new(budget => 50, floor => 10, interval => 1);
    my $t = time;
    $s->retune(cov(op => 10_000), $t);
    $s->retune(cov(op => 5), $t + 1);
    is($s->divisor('op'), 1, 'a reset counter starts again, not below zero');
    cmp_ok($s->divisor('op'), '>=', 1, 'and the divisor stays usable');
}

done_testing();
