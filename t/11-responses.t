#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Raw::JSON ();

use Maat::Config;
use Maat::Gateway;
use Maat::Sampler;

# Phase 2: the response half. The product's reason to exist is that a
# response which does not match its contract is recorded - and the one
# thing that must never happen is that recording it changes what the
# client receives. Every test here checks both halves.

my $PET     = File::Raw::JSON::file_json_encode({ id => 1, name => 'rex' });
my $NOT_PET = File::Raw::JSON::file_json_encode({ colour => 'red' });

sub json_upstream {
    my ($body, %o) = @_;
    return start_upstream(respond => sub {
        return ($o{status} || 200,
                [ 'Content-Type' => $o{type} || 'application/json',
                  'X-Upstream'   => 'maat-test' ],
                $body);
    });
}

# Records leave the aggregator when a window closes, so a test that wants
# to see them says so - see Maat::Violation.
sub recorded {
    my ($g, $records) = @_;
    $g->violation->flush;
    return $records;
}

sub gateway_for {
    my ($up, %o) = @_;
    my $records = delete $o{records} || [];
    my %responses = %{ delete $o{responses} || {} };
    my $config = Maat::Config->from_hash({
        upstream  => "http://127.0.0.1:$up->{port}",
        spec      => spec_path('petstore.json'),
        mode      => delete $o{mode} || 'observe',
        responses => { sample => 'all', %responses },
    });
    my $g = Maat::Gateway->new(config => $config,
                               sink => sub { push @$records, @{ $_[0] } }, %o);
    return ($g, $g->to_app, $records);
}

# ---- a violating response is recorded, and not touched ----------------------
{
    my $up = json_upstream($NOT_PET);
    my ($g, $app, $records) = gateway_for($up);

    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));

    is($res->[0], 200, 'the upstream status is what the client gets');
    is($res->[2][0], $NOT_PET, 'and the body, byte for byte');

    is(scalar @{ recorded($g, $records) }, 1, 'the mismatch was recorded');
    my $r = recorded($g, $records)->[0];
    is($r->{kind}, 'response', 'recorded as a response violation');
    is($r->{operation_id}, 'getPet', 'against the operation');
    is($r->{status}, 200, 'with the status it came back with');
    ok(defined $r->{request_id}, 'and the request id, to join the logs on');
    ok(defined $r->{pointer}, 'carrying the failing pointer');
    ok(defined $r->{keyword}, 'and the keyword that failed');
    is($g->counters->{response_violation}, 1, 'the counter moved');

    stop_upstream($up);
}

# The gate, properly: byte for byte against the upstream's own answer,
# header for header, with response validation on. Not an eyeball.
{
    my $up = json_upstream($NOT_PET);

    my ($direct_status, $direct_headers, $direct_body) =
        http_request($up->{port}, 'GET', '/pets/42', []);

    my ($g, $app) = gateway_for($up);
    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));

    is($res->[0], $direct_status, 'status identical to the direct response');
    is($res->[2][0], $direct_body, 'body identical, byte for byte');

    my %proxied = @{ $res->[1] };
    delete $proxied{'X-Request-Id'};      # ours, and the only addition
    my %direct = @$direct_headers;
    delete $direct{$_} for qw(Connection Transfer-Encoding Keep-Alive);
    for my $k (sort keys %direct) {
        is($proxied{$k}, $direct{$k}, "header $k identical");
    }

    stop_upstream($up);
}

# ---- a conforming response is checked and passes ----------------------------
{
    my $up = json_upstream($PET);
    my ($g, $app, $records) = gateway_for($up);

    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));
    is($res->[2][0], $PET, 'the body is forwarded');
    is(scalar @{ recorded($g, $records) }, 0, 'and nothing is recorded');

    my $cov = $g->coverage;
    is($cov->{getPet}{checked}, 1, 'it was checked');
    is($cov->{getPet}{violations}, 0, 'and it conformed');

    stop_upstream($up);
}

# ---- coverage: every response either checked or skipped for one reason ------
{
    my $up = json_upstream($PET, type => 'text/html');
    my ($g, $app) = gateway_for($up);

    $app->(psgi_env(method => 'GET', path => '/pets/42')) for 1 .. 3;

    my $cov = $g->coverage->{getPet};
    is($cov->{total}, 3, 'three responses seen');
    is($cov->{skip_ctype}, 3, 'all three skipped: not a JSON content type');
    is($cov->{checked}, 0, 'none decoded');
    is($cov->{divisor}, 1, 'the divisor in force is reported alongside');

    # the accounting has to add up, or coverage is a guess
    my $accounted = $cov->{checked} + $cov->{skip_ctype} + $cov->{skip_size}
                  + $cov->{skip_body} + $cov->{skip_schema}
                  + $cov->{skip_decode} + $cov->{unsampled};
    is($accounted, $cov->{total},
        'every response is accounted for exactly once');

    stop_upstream($up);
}

# ---- a body over the cap is never read --------------------------------------
{
    my $big = File::Raw::JSON::file_json_encode(
        { id => 1, name => 'x' x 4096 });
    my $up = json_upstream($big);
    my ($g, $app) = gateway_for($up, responses => { max_body => 1024 });

    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));
    is($res->[2][0], $big, 'the whole body still reaches the client');
    my $cov = $g->coverage->{getPet};
    is($cov->{skip_size}, 1, 'and it was skipped by size');
    is($cov->{checked}, 0, 'never decoded');

    stop_upstream($up);
}

# ---- sampling: the divisor decides how much is looked at --------------------
{
    my $up = json_upstream($NOT_PET);
    my ($g, $app, $records) = gateway_for($up, responses => { sample => 4 });

    $app->(psgi_env(method => 'GET', path => '/pets/42')) for 1 .. 12;

    my $cov = $g->coverage->{getPet};
    is($cov->{total}, 12, 'all twelve seen');
    is($cov->{sampled}, 3, 'one in four sampled');
    my $recs = recorded($g, $records);
    is(scalar @$recs, 1,
        'the three sampled failures are one problem, so one record');
    is($recs->[0]{sample_count}, 3, '...carrying all three sampled responses');
    is($g->counters->{request}, 12, 'every request still served');

    stop_upstream($up);
}

# ---- turning it off ---------------------------------------------------------
{
    my $up = json_upstream($NOT_PET);
    my ($g, $app, $records) = gateway_for($up,
        responses => { validate => 0, sample => 'all' });

    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));
    is($res->[2][0], $NOT_PET, 'the response is forwarded');
    is(scalar @{ recorded($g, $records) }, 0, 'nothing recorded');
    is_deeply($g->coverage, {}, 'and nothing was even counted');

    stop_upstream($up);
}

# ---- an undeclared path is reported as observe-only drift -------------------
# It has no contract to VALIDATE against, and it is still forwarded untouched
# and still counted `undeclared`. What changed (Maat::Observe): the API
# surface the contract does not cover is no longer invisible - it is
# recorded by its templated shape, never a value, as observe-only drift.
{
    my $up = json_upstream($NOT_PET);
    my ($g, $app, $records) = gateway_for($up);

    $app->(psgi_env(method => 'GET', path => '/not-in-the-document'));
    my $rec = recorded($g, $records);
    is(scalar @$rec, 1, 'an undeclared path is recorded as observe-only drift');
    is($rec->[0]{keyword}, 'undeclared-endpoint', '...as an undeclared endpoint');
    is($rec->[0]{kind},    'undeclared',          '...of the undeclared kind');
    is($rec->[0]{pointer}, 'GET /not-in-the-document',
        '...by method and templated path, not a value');
    is($g->counters->{undeclared}, 1, 'still counted undeclared, as before');
    is($g->counters->{observed},   1, 'and counted an observation, not a violation');

    stop_upstream($up);
}

# ---- enforce does not reject on a response ----------------------------------
# A response cannot be un-sent, and answering 502 because the upstream's
# body drifted would turn a documentation bug into an outage - ours,
# suffered by them. Recorded in both modes, rejected in neither.
{
    my $up = json_upstream($NOT_PET);
    my ($g, $app, $records) = gateway_for($up, mode => 'enforce');

    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));
    is($res->[0], 200, 'enforce mode still returns the upstream response');
    is($res->[2][0], $NOT_PET, '...unchanged');
    is(scalar @{ recorded($g, $records) }, 1, 'and records the violation');
    is($g->counters->{rejected}, 0, 'nothing was rejected');

    stop_upstream($up);
}

# ---- chaos: a broken check loses the sample, never the response -------------
{
    for my $point (qw(response record)) {
        my $up = json_upstream($NOT_PET);
        my ($g, $app, $records) = gateway_for($up, chaos => $point);

        my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));
        is($res->[0], 200, "APIP_CHAOS=$point: the response is still served");
        is($res->[2][0], $NOT_PET, "APIP_CHAOS=$point: ...unchanged");
        ok($g->counters->{failed} >= 1, "APIP_CHAOS=$point: counted failed");

        stop_upstream($up);
    }
}

# a reporter that blocks forever is abandoned, and the response is fine
{
    my $up = json_upstream($NOT_PET);
    my ($g, $app) = gateway_for($up, chaos => 'block', record_timeout => 1);

    my $res = $app->(psgi_env(method => 'GET', path => '/pets/42'));
    is($res->[0], 200, 'APIP_CHAOS=block: the response is served');
    is($res->[2][0], $NOT_PET, '...unchanged');
    is($g->counters->{failed}, 1, 'and the watchdog counted the abandonment');

    stop_upstream($up);
}

# ---- the sampler is wired to the configuration ------------------------------
{
    my $up = json_upstream($PET);
    for my $case (
        [ { sample => 'adaptive' }, 'adaptive' ],
        [ { sample => 'all' },      'fixed'    ],
        [ { sample => 10 },         'fixed'    ],
        [ { validate => 0 },        'off'      ],
    ) {
        my ($responses, $mode) = @$case;
        my ($g) = gateway_for($up, responses => $responses);
        is($g->sampler->mode, $mode,
            "responses.$_: sampler mode $mode") for join ',', %$responses;
    }
    stop_upstream($up);
}

done_testing();
