use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;
use File::Temp ();
use File::Raw::JSON ();

use Maat::Log;
use Maat::Registry;
use Maat::Fleet;

# What a fleet says about itself.
#
# Before this it said one thing - a banner at start - and then nothing,
# while Registry, Poller and Router each kept counters nobody could
# read. An evening went into diagnosing a hung compile from the outside
# that one line pair would have found. So the events under test here are
# the ones that were missing when they were wanted, not a sample of what
# is easy to emit.

# ---- the emitter -------------------------------------------------------------
{
    # Parenthesised: `is Maat::Log->event(...)` parses as an
    # indirect-object call to Maat::Log->is.
    is(Maat::Log->event(ev => 'x'), 0,
        'silent until enabled - a library that writes to STDERR on load '
      . 'is one that ruins somebody\'s CLI output');

    open my $fh, '>', \my $buf or die $!;
    Maat::Log->enable(1, $fh);

    ok(Maat::Log->event(ev => 'compile', phase => 'start', host => 'a.test'),
        'an event is written');

    my $line = (split /\n/, $buf)[0];
    my $got  = eval { File::Raw::JSON::file_json_decode($line) };
    ok $got, 'one line, and it is JSON';
    is $got->{ev}, 'compile', '...carrying the event name';
    is $got->{host}, 'a.test', '...and its detail';
    is $got->{worker}, $$,
        '...and the pid, because four workers interleave in one log and '
      . 'a line that cannot be attributed is half an answer';
    ok $got->{t}, '...and a timestamp';

    # It is called from failure paths. One that throws inside an error
    # handler turns a bad minute into an outage.
    my $before = $buf;
    my $ok = eval { Maat::Log->event(ev => 'bad', v => sub { 1 }); 1 };
    ok $ok, 'an unencodable value does not die';
    is $buf, $before, '...and writes nothing rather than a broken line';

    Maat::Log->enable(0);
}

# ---- the compile pair --------------------------------------------------------
#
# The one that matters: a `start` with no terminator is a compile that
# never came back, which is the shape of a wedged fetch. Nothing else in
# the log distinguishes that from a fleet with nothing to do.
{
    open my $fh, '>', \my $buf or die $!;
    Maat::Log->enable(1, $fh);

    my $stub = RegistryStub->new(token => 't');
    $stub->add_tenant(host => 't1.test', proxy => 1, plan => 'team',
        spec => RegistryStub->tenant_spec(1));

    my $reg = Maat::Registry->new(fetch_spec => sub { undef });
    $reg->apply_bundle({ tenants => $stub->{tenants},
                         domains => [], challenges => [] });
    $reg->resolve('t1.test');          # compiles, and fails to
    Maat::Log->enable(0);

    my @ev = map { File::Raw::JSON::file_json_decode($_) }
             grep { length } split /\n/, $buf;
    my @compile = grep { $_->{ev} eq 'compile' } @ev;
    is scalar @compile, 2, 'a compile emits exactly two lines';
    is $compile[0]{phase}, 'start', '...a start';
    is $compile[1]{phase}, 'fail',  '...and a terminator';
    like $compile[1]{err}, qr/spec/i, '...saying what went wrong';
    ok defined $compile[1]{took}, '...and how long it took';

    my ($poison) = grep { $_->{ev} eq 'poison' } @ev;
    ok $poison, 'and the host being poisoned is said separately';
    is $poison->{host}, 't1.test',
        '...because a failed compile is an event and a 503 until the '
      . 'digest moves is a longer-lived fact';

    my ($bundle) = grep { $_->{ev} eq 'bundle' } @ev;
    ok $bundle, 'applying a bundle says so';
    is $bundle->{added}, 1, '...as a diff, not a total';
    is_deeply $bundle->{added_hosts}, ['t1.test'], '...naming the host';
}

# ---- an unchanged bundle is not an event -------------------------------------
{
    open my $fh, '>', \my $buf or die $!;
    my $stub = RegistryStub->new(token => 't');
    $stub->add_tenant(host => 't1.test', proxy => 1, plan => 'team',
        spec => RegistryStub->tenant_spec(1));
    my $reg = Maat::Registry->new(fetch_spec => sub { undef });
    my $apply = sub { $reg->apply_bundle({ tenants => $stub->{tenants},
                                           domains => [], challenges => [] }) };
    $apply->();
    Maat::Log->enable(1, $fh);
    $apply->();                       # nothing moved
    Maat::Log->enable(0);
    # `$buf` stays undef when nothing was written, which is the point.
    my @ev = grep { length } split /\n/, ($buf // '');
    is scalar @ev, 0,
        'a bundle that changed nothing writes nothing - a fleet polls '
      . 'every interval on every worker and steady state must be quiet';
}

# ---- the snapshot ------------------------------------------------------------
{
    my $stub = RegistryStub->new(token => 't');
    my $fleet = Maat::Fleet->new(
        config => { control_plane => 'http://c.invalid', registry_token => 't' },
        fetch  => $stub->fetcher, fetch_spec => $stub->spec_fetcher);
    my $s = $fleet->registry->snapshot(router => $fleet->router,
                                       poller => $fleet->poller);
    is $s->{worker}, $$, 'the snapshot says which worker it is';
    ok exists $s->{registry}{tenants}, '...with the registry counters';
    ok exists $s->{router},            '...the router\'s';
    ok exists $s->{poller},            '...and the poller\'s';
    is_deeply $s->{poisoned_hosts}, [],
        'and poisoned hosts by name - a count is a worry, the names are '
      . 'the thing to act on';
}

# ---- the stats file ----------------------------------------------------------
{
    my $dir  = File::Temp->newdir;
    my $stub = RegistryStub->new(token => 't');
    my $fleet = Maat::Fleet->new(
        config => { control_plane => 'http://c.invalid', registry_token => 't',
                    stats_dir => "$dir/stats", interval => 15 },
        fetch  => $stub->fetcher, fetch_spec => $stub->spec_fetcher);

    ok $fleet->write_stats(1), 'a worker writes its counters';
    my $file = "$dir/stats/worker-$$.json";
    ok -f $file, '...to a file named for the process';
    ok -d "$dir/stats", '...creating the directory when it is not there';

    open my $fh, '<', $file or die $!;
    local $/;
    my $got = eval { File::Raw::JSON::file_json_decode(scalar <$fh>) };
    close $fh;
    ok $got, 'the file is JSON';
    is $got->{worker}, $$, '...for this worker';

    # Throttled: this is called from the request path, and a fleet under
    # load must not rewrite it per request.
    is $fleet->write_stats, 0, 'a second write inside the interval is skipped';
    ok $fleet->write_stats(1), '...and forced when asked';
}

{
    # Without stats_dir it is a no-op rather than a guess at a path.
    my $stub = RegistryStub->new(token => 't');
    my $fleet = Maat::Fleet->new(
        config => { control_plane => 'http://c.invalid', registry_token => 't' },
        fetch  => $stub->fetcher, fetch_spec => $stub->spec_fetcher);
    is $fleet->write_stats(1), 0, 'no stats_dir, no file, no complaint';
}

{
    # Reporting must never break serving: it runs on the request path,
    # so an unwritable directory costs a metric, not a request.
    my $stub = RegistryStub->new(token => 't');
    my $fleet = Maat::Fleet->new(
        config => { control_plane => 'http://c.invalid', registry_token => 't',
                    stats_dir => '/proc/nonexistent/nope' },
        fetch  => $stub->fetcher, fetch_spec => $stub->spec_fetcher);
    my $ok = eval { $fleet->write_stats(1); 1 };
    ok $ok, 'an unwritable stats_dir does not die on the request path';
}

done_testing;
