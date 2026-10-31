use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;

use Maat::Config;
use Maat::Gateway;

my $up = start_upstream();

sub observing {
    my (%o) = @_;
    my $config = Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('petstore.json'),
        mode     => 'observe',
    });
    return Maat::Gateway->new(config => $config, %o);
}

# ---- a violation is recorded and the request forwarded untouched ------------

{
    my @seen;
    my $g   = observing(sink => sub { push @seen, @{ $_[0] } });
    my $app = $g->to_app;

    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=500',
    ));
    is($status, 200, 'the violating request was forwarded');
    is($body, "method=GET\ntarget=/pets?limit=500\nbody=",
       'and reached the upstream untouched');

    # Records leave on the window, not the request - see Maat::Violation.
    $g->violation->flush;

    is(scalar @seen, 1, 'one violation recorded');
    my $rec = $seen[0];
    is($rec->{operation_id}, 'listPets', 'record names the operation');
    is($rec->{method}, 'GET', 'record.method');
    is($rec->{path}, '/pets', 'record.path');
    is($rec->{request_id}, header_get($headers, 'X-Request-Id'),
       'the record carries the same request id the response echoes');
    is($rec->{name}, 'limit', 'the record names the parameter');
    is($rec->{keyword}, 'maximum', 'and the keyword that failed');
    is($rec->{pointer}, 'query/limit',
        'and where - a parameter is located by where it lives, since it
         has no document to point into');
    is($rec->{count}, 1, 'counted once');
    ok($rec->{first_seen}, 'record is timestamped');

    is($g->counters->{violation}, 1, 'violation counted');
    is($g->counters->{rejected}, 0, 'nothing rejected in observe');
}

# ---- a malformed body is forwarded in observe -------------------------------

{
    my $g   = observing();
    my $app = $g->to_app;
    my $bad = '{not json at all';
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => $bad,
    ));
    is($status, 200, 'malformed body still forwarded in observe');
    is($body, "method=POST\ntarget=/pets\nbody=$bad",
       'the exact bytes reached the upstream');
    is($g->counters->{violation}, 1, 'and the violation was recorded');
    $g->violation->flush;
    is(scalar @{ $g->violation->records }, 1, 'in the ring, absent a sink');
}

# ---- wrong method is forwarded in observe -----------------------------------

{
    my $g   = observing();
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'DELETE', path => '/pets',
    ));
    is($status, 200, 'wrong method forwarded in observe');
    is($body, "method=DELETE\ntarget=/pets\nbody=",
       'upstream answered it');
    is($g->counters->{wrong_method}, 1, 'counted wrong_method');
}

stop_upstream($up);
done_testing;
