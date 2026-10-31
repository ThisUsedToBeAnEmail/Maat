use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use Time::HiRes ();

use Maat::Config;
use Maat::Gateway;

# The fail-open harness. Every injected failure below breaks Maat's own
# machinery, and the assertion is always the same: the request reached
# the upstream and the client got the upstream's answer.

my $up = start_upstream();

sub gateway {
    my (%o) = @_;
    my $report = delete $o{report};
    my $config = Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('petstore.json'),
        mode     => delete $o{mode} || 'observe',
        ($report ? (report => $report) : ()),
    });
    return Maat::Gateway->new(config => $config, %o);
}

# ---- freed: the spec handle is gone -----------------------------------------

{
    my $g   = gateway(chaos => 'freed');
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app,
        psgi_env(method => 'GET', path => '/pets/42'));
    is($status, 200, 'freed handle: request forwarded');
    is($body, "method=GET\ntarget=/pets/42\nbody=", 'upstream answered');
    is($g->counters->{failed}, 1, 'the failure was counted');
}

# ---- match: routing dies ----------------------------------------------------

{
    my $g   = gateway(chaos => 'match');
    my $app = $g->to_app;
    my ($status) = run_app($app, psgi_env(method => 'GET', path => '/pets/42'));
    is($status, 200, 'dying router: request forwarded');
    is($g->counters->{failed}, 1, 'counted');
}

# ---- validate: the validator dies -------------------------------------------

{
    my $g   = gateway(chaos => 'validate', mode => 'enforce');
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => '{not even json',
    ));
    is($status, 200, 'dying validator: even a malformed body forwards, '
                   . 'because a dead validator proves nothing');
    is($body, "method=POST\ntarget=/pets\nbody={not even json",
       'bytes untouched');
    is($g->counters->{failed}, 1, 'counted');
    is($g->counters->{rejected}, 0, 'enforce cannot reject on a failed check');
}

# ---- alloc: buffering the body fails ----------------------------------------

{
    my $g   = gateway(chaos => 'alloc', mode => 'enforce');
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => '{"name":"rex"}',
    ));
    is($status, 200, 'allocation failure: request forwarded');
    is($body, 'method=POST' . "\ntarget=/pets\nbody=" . '{"name":"rex"}',
       'body streamed through unread');
    is($g->counters->{failed}, 1, 'counted');
}

# ---- record: the reporter dies ----------------------------------------------

{
    my $g   = gateway(chaos => 'record');
    my $app = $g->to_app;
    my ($status) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=500',
    ));
    is($status, 200, 'dying reporter: the violating request still forwards');
    is($g->counters->{failed}, 1, 'counted');
    is($g->counters->{violation}, 0, 'the record itself was lost, as designed');
}

# ---- block: the reporter blocks forever -------------------------------------

{
    my $g   = gateway(chaos => 'block', record_timeout => 0.2);
    my $app = $g->to_app;
    my $t0  = Time::HiRes::time();
    my ($status) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=500',
    ));
    my $took = Time::HiRes::time() - $t0;
    is($status, 200, 'blocking reporter: request forwarded');
    cmp_ok($took, '<', 5, "the watchdog abandoned it (took ${\ sprintf '%.2f', $took}s)");
    is($g->counters->{failed}, 1, 'counted');
}

# A genuinely blocking sink - no chaos switch - is abandoned the same way.
#
# The sink is now reached through the window flush rather than through
# record(), so `window: 0` is what makes this request the one that
# closes a window and therefore the one that meets the blocking sink.
# The property under test is unchanged: somebody else's code, on the end
# of our reporting, cannot hold a request open.
{
    my $g = gateway(sink => sub { sleep 60 while 1 }, record_timeout => 0.2,
                    report => { window => 0 });
    my $app = $g->to_app;
    my $t0  = Time::HiRes::time();
    my ($status) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=500',
    ));
    is($status, 200, 'a real blocking sink cannot hold the request either');
    cmp_ok(Time::HiRes::time() - $t0, '<', 5, 'abandoned by the watchdog');
    is($g->counters->{failed}, 1, 'counted');
}

# ---- APIP_CHAOS=all under load: gate 2 --------------------------------------

for my $mode (qw(observe enforce)) {
    local $ENV{APIP_CHAOS} = 'all';
    my $g   = gateway(mode => $mode);      # picked up from the environment
    my $app = $g->to_app;

    my $before = () = upstream_log($up);
    my @corpus = (
        [ GET    => '/pets/42' ],
        [ GET    => '/pets', 'limit=500' ],
        [ POST   => '/pets', undef, '{"name":"rex"}' ],
        [ POST   => '/pets', undef, '{not json' ],
        [ DELETE => '/pets' ],
        [ GET    => '/undeclared/route' ],
    );
    my $n = 0;
    for (1 .. 5) {
        for my $c (@corpus) {
            my ($status) = run_app($app, psgi_env(
                method => $c->[0], path => $c->[1],
                (defined $c->[2] ? (query => $c->[2]) : ()),
                (defined $c->[3] ? (body  => $c->[3]) : ()),
            ));
            $n++;
            is($status, 200, "APIP_CHAOS=all [$mode] request $n forwarded");
        }
    }
    my $after = () = upstream_log($up);
    is($after - $before, $n,
       "APIP_CHAOS=all [$mode]: every one of $n requests reached the upstream");
    is($g->counters->{rejected}, 0,
       "APIP_CHAOS=all [$mode]: nothing was rejected");
    is($g->counters->{failed}, $n,
       "APIP_CHAOS=all [$mode]: every failure was counted, none was fatal");
}

# ---- rates ------------------------------------------------------------------

{
    my $g   = gateway(chaos => 'validate:0.5');
    my $app = $g->to_app;
    for (1 .. 40) {
        run_app($app, psgi_env(method => 'GET', path => '/pets/42'));
    }
    my $failed = $g->counters->{failed};
    my $fine   = $g->counters->{conforming};
    is($failed + $fine, 40, 'rated chaos: every request took one path');
    ok($failed > 0, "some failed ($failed)");
    ok($fine   > 0, "some validated ($fine)");
}

stop_upstream($up);
done_testing;
