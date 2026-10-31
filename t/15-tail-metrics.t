#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Temp ();
use File::Raw::JSON ();

use Maat::Config;
use Maat::Gateway;
use Maat::Spool;

# The two ways a gateway tells you what it is seeing without a control
# plane: a live feed on a terminal, and a self-report endpoint. Both
# exist so the product is useful on day one, before anybody has signed up
# for anything.

my $up = start_upstream();

sub gateway {
    my (%o) = @_;
    my $report = delete $o{report} || {};
    my $config = Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('petstore.json'),
        mode     => delete $o{mode} || 'observe',
        report   => $report,
    });
    return Maat::Gateway->new(config => $config, %o);
}

# ---- /metrics ---------------------------------------------------------------
{
    my $g   = gateway(report => { metrics => '/_maat/metrics', window => 0 });
    my $app = $g->to_app;

    # some traffic, one of it violating
    run_app($app, psgi_env(method => 'GET', path => '/pets'));
    run_app($app, psgi_env(method => 'GET', path => '/pets', query => 'limit=500'));

    my ($status, $headers, $body) =
        run_app($app, psgi_env(method => 'GET', path => '/_maat/metrics'));

    is($status, 200, 'the metrics path answers');
    is(header_get($headers, 'Content-Type'), 'application/json', 'as json');
    is(header_get($headers, 'Cache-Control'), 'no-store',
        'and is never cached - it is a live reading');

    my $m = File::Raw::JSON::file_json_decode($body);
    ok($m->{counters}, 'the counters are there');
    is($m->{counters}{violation}, 1, 'with the violation counted');
    ok($m->{counters}{request} >= 2, 'and the requests');
    ok(exists $m->{counters}{occurrences}, 'the pipeline reports itself too');
    ok(exists $m->{counters}{keys_dropped}, '...including what it dropped');
    ok(exists $m->{window}{open_keys}, 'and what the open window holds');
    ok(exists $m->{coverage}, 'response coverage is in the same reading');
}

# it does not exist unless it is asked for, because it shadows a path
{
    my $g   = gateway();
    my $app = $g->to_app;
    my ($status, $headers, $body) =
        run_app($app, psgi_env(method => 'GET', path => '/_maat/metrics'));
    is($status, 200, 'without the option the path is proxied like any other');
    is($body, "method=GET\ntarget=/_maat/metrics\nbody=",
        'straight to the upstream - we do not silently intercept paths');
}

# the spool and the shipper report themselves when they exist
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $g   = gateway(report => { metrics => '/m', spool => $dir,
                                  url => 'https://cp.example/v1', window => 0 });
    my $app = $g->to_app;
    run_app($app, psgi_env(method => 'GET', path => '/pets', query => 'limit=500'));

    my (undef, undef, $body) = run_app($app, psgi_env(method => 'GET', path => '/m'));
    my $m = File::Raw::JSON::file_json_decode($body);

    ok(exists $m->{spool}{depth}, 'spool depth is reported');
    ok(exists $m->{spool}{dropped}, 'and what the spool dropped');
    ok(exists $m->{shipper}{ship_failed}, 'and what the shipper failed to send');
    ok(exists $m->{shipper}{backoff_until}, 'and whether it is backing off');
}

# ---- the spool is where a closed window lands -------------------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $g   = gateway(report => { spool => $dir, window => 0 });
    my $app = $g->to_app;

    run_app($app, psgi_env(method => 'GET', path => '/pets', query => 'limit=500'));
    $g->violation->flush;

    my $spool = Maat::Spool->new(dir => $dir);
    ok($spool->depth >= 1, 'the violation reached the spool');
    my ($batch) = $spool->take(1);
    is($batch->[1][0]{operation_id}, 'listPets', 'as an aggregated record');
    is($batch->[1][0]{pointer}, 'query/limit', 'with where it failed');
}

# ---- apip tail --------------------------------------------------------------
{
    my $root = dist_root();
    my $dir  = File::Temp::tempdir(CLEANUP => 1);
    my $cfg  = File::Temp::tempdir(CLEANUP => 1) . '/tail.yml';

    write_file($cfg, <<"YML");
upstream: http://127.0.0.1:$up->{port}
spec: @{[ spec_path('petstore.json') ]}
report:
  spool: $dir
YML

    my $spool = Maat::Spool->new(dir => $dir);
    $spool->push_batch([
        { last_seen => time, count => 40312, operation_id => 'createPet',
          kind => 'request', pointer => '/name', keyword => 'type',
          expected => 'string', got_type => 'number' },
        { last_seen => time, count => 7, operation_id => 'getPet',
          kind => 'response', status => 200, pointer => '/items/*/sku',
          keyword => 'required', example => 'rex' },
    ]);

    local $ENV{PERL5LIB} = join ':', "$root/lib", "$root/blib/lib",
        "$root/blib/arch", sibling_inc(),
        (defined $ENV{PERL5LIB} ? $ENV{PERL5LIB} : ());

    my $out = `$^X $root/bin/apip tail --violations --once $cfg 2>&1`;
    is($? >> 8, 0, 'apip tail exits 0');

    like($out, qr/x40312/, 'the count leads - forty thousand is a different '
                         . 'problem from one');
    like($out, qr/createPet/, 'the operation');
    like($out, qr{/name}, 'where');
    like($out, qr/type/, 'and what failed');
    like($out, qr/expected string, got number/, 'with the drift spelled out');
    like($out, qr{/items/\*/sku}, 'the collapsed pointer, as recorded');
    like($out, qr/example=rex/, 'and the example when there is one');

    # it must not consume: the shipper has not sent these yet
    is(Maat::Spool->new(dir => $dir)->depth, 1,
        'tailing leaves the spool alone - it is not ours to consume');

    my $json = `$^X $root/bin/apip tail --json --once $cfg 2>&1`;
    my ($first) = split /\n/, $json;
    my $rec = eval { File::Raw::JSON::file_json_decode($first) };
    is($rec->{operation_id}, 'createPet', '--json emits one record per line');
}

# tail says what to do when there is no spool to read
{
    my $root = dist_root();
    my $cfg  = File::Temp::tempdir(CLEANUP => 1) . '/nospool.yml';
    write_file($cfg, <<"YML");
upstream: http://127.0.0.1:$up->{port}
spec: @{[ spec_path('petstore.json') ]}
YML
    local $ENV{PERL5LIB} = join ':', "$root/lib", "$root/blib/lib",
        "$root/blib/arch", sibling_inc(),
        (defined $ENV{PERL5LIB} ? $ENV{PERL5LIB} : ());
    my $out = `$^X $root/bin/apip tail --once $cfg 2>&1`;
    is($? >> 8, 1, 'no spool configured is an error');
    like($out, qr/there is no spool to read/, 'said plainly');
    like($out, qr/report:\s*\n\s*spool:/, 'with the configuration to add');
}

# ---- metering: hours out of the request counter ----------------------------
#
# The gateway's half of the bill. It samples the counter the C request
# path already keeps rather than adding one, and reports a RUNNING TOTAL
# per hour - the control plane replaces rather than adds, so a retry
# writes the same number instead of doubling it.

{
    my $g   = gateway();
    my $app = $g->to_app;

    is($g->usage, undef, 'a gateway that has served nothing meters nothing');

    run_app($app, psgi_env(method => 'GET', path => '/pets')) for 1 .. 3;

    my $u = $g->usage;
    is(ref $u, 'ARRAY', 'traffic produces an hour');
    is(scalar @$u, 1, 'one bucket');
    is($u->[0]{requests}, 3, 'holding every request served');
    is($u->[0]{hour} % 3600, 0, 'the bucket is on the hour');
    ok(length($u->[0]{gateway} // ''), 'and says which reporter it is - '
     . 'every worker meters its own share and the control plane sums');

    # Unshipped, so still on offer: the same hour, the same number.
    is_deeply($g->usage, $u, 'an uncommitted hour keeps being offered');

    $g->usage_shipped($u);
    is($g->usage, undef,
        'once the control plane has it, an unchanged hour is not re-sent - '
      . 'an idle tenant must not post a heartbeat every five seconds');

    run_app($app, psgi_env(method => 'GET', path => '/pets'));
    my $again = $g->usage;
    is($again->[0]{requests}, 4,
        'more traffic re-offers the hour as a running total, not a delta - '
      . 'which is what makes the replace on the far side safe');
    is($again->[0]{hour}, $u->[0]{hour}, '...the same hour');
}

# A worker that restarted has counters back at zero. The hour it is
# reporting must not go negative because of it.
{
    my $g = gateway();
    my $app = $g->to_app;
    run_app($app, psgi_env(method => 'GET', path => '/pets')) for 1 .. 2;
    $g->usage_shipped($g->usage);

    $g->{violation}->counters->{request} = 0;   # as a fresh worker sees it
    my $u = $g->usage;
    ok(!$u || $u->[0]{requests} >= 0,
        'a counter that went backwards never reports a negative hour');
}

stop_upstream($up);
done_testing();

# ---- doubles ----------------------------------------------------------------

{
    package FakeUA;
    sub new  { my ($c, $cb) = @_; bless { cb => $cb }, $c }
    sub post { my ($self, $url, %args) = @_; return $self->{cb}->($url, \%args) }

    package FakeRes;
    sub new  { my ($c, $code) = @_; bless { code => $code }, $c }
    sub code { $_[0]{code} }
}
