#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Temp ();
use File::Spec ();

use Maat::Spool;
use Maat::Shipper;
use Maat::Violation;

# The spool and the shipper. What is being tested is not "does it deliver
# violations" - that is the easy half - but what it does when the control
# plane will not take them: stay bounded, keep proxying, count honestly,
# and send everything once it comes back.

sub recs {
    my ($n, $tag) = @_;
    return [ map { { fingerprint => "fp-$tag-$_", count => $_,
                     operation_id => 'op', pointer => "/f$_",
                     keyword => 'type' } } 1 .. $n ];
}

# ---- the spool holds and returns what it was given -------------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $s = Maat::Spool->new(dir => $dir);

    is($s->depth, 0, 'a fresh spool is empty');
    ok($s->push_batch(recs(3, 'a')), 'a batch goes on');
    is($s->depth, 1, 'and is there');
    is($s->counters->{spooled}, 1, 'counted');

    is($s->push_batch([]), undef, 'an empty batch is not a file');
    is($s->depth, 1, '...and does not count as one');

    my @batches = $s->take(10);
    is(scalar @batches, 1, 'take returns it');
    is(scalar @{ $batches[0][1] }, 3, 'with every record');
    is($batches[0][1][0]{fingerprint}, 'fp-a-1', 'and their contents');

    is($s->depth, 1, 'taking does not remove it - nothing is acknowledged yet');
    $s->done($batches[0][0]);
    is($s->depth, 0, 'done does');
}

# order is preserved: the oldest batch is the first out
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $s = Maat::Spool->new(dir => $dir);
    $s->push_batch(recs(1, $_)) for qw(first second third);
    my @b = $s->take(10);
    is(scalar @b, 3, 'all three');
    is($b[0][1][0]{fingerprint}, 'fp-first-1', 'oldest first');
    is($b[2][1][0]{fingerprint}, 'fp-third-1', 'newest last');
}

# ---- the bounds hold, and dropping is counted ------------------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $s = Maat::Spool->new(dir => $dir, max_files => 5);
    $s->push_batch(recs(1, $_)) for 1 .. 20;

    is($s->depth, 5, 'the spool never exceeds max_files');
    is($s->counters->{dropped}, 15, 'and every drop is counted');

    my @b = $s->take(10);
    is($b[0][1][0]{fingerprint}, 'fp-16-1',
        'what was kept is the newest: during an outage the recent '
      . 'violations are the ones describing what is happening now');
}

{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $s = Maat::Spool->new(dir => $dir, max_files => 1000, max_bytes => 2000);
    $s->push_batch(recs(20, $_)) for 1 .. 30;
    cmp_ok($s->bytes, '<=', 2000 + 1,
        'the spool stays inside max_bytes (one batch may exceed it alone)');
    ok($s->counters->{dropped} > 0, 'by dropping, and counting it');
}

# ---- a restart finds what was left behind ----------------------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    {
        my $s = Maat::Spool->new(dir => $dir);
        $s->push_batch(recs(1, $_)) for 1 .. 3;
    }
    my $s2 = Maat::Spool->new(dir => $dir);
    is($s2->depth, 3, 'a new process sees the spool that was there');
    $s2->push_batch(recs(1, 'after'));
    my @b = $s2->take(10);
    is(scalar @b, 4, 'and adds to it');
    is($b[-1][1][0]{fingerprint}, 'fp-after-1',
        'after what was already there, not before it');
}

# ---- a file that cannot be read does not wedge the queue -------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $s = Maat::Spool->new(dir => $dir);
    $s->push_batch(recs(1, 'good'));

    # a corrupt file that sorts BEFORE the good one, so it is met first
    open my $fh, '>', File::Spec->catfile($dir, '000000000000.json') or die;
    print {$fh} 'this is not json';
    close $fh;

    my @b = $s->take(10);
    is(scalar @b, 1, 'the unreadable file is skipped, not retried forever');
    is($s->counters->{read_failed}, 1, 'and counted');
    is($s->depth, 1, 'and removed, so nothing queues behind it');
}

# ---- the shipper: what it sends --------------------------------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    $spool->push_batch(recs(2, 'a'));
    $spool->push_batch(recs(2, 'b'));

    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(202) });
    my $shipper = Maat::Shipper->new(url => 'https://cp.example/v1',
                                     token => 'tok-123',
                                     spool => $spool, ua => $ua, gzip => 0);

    is($shipper->drain, 2, 'both batches went in one request');
    is(scalar @sent, 1, 'one request, not one per batch');
    like($sent[0][1]{headers}{Authorization}, qr/\ABearer tok-123\z/,
        'the token travels as a bearer');
    is($sent[0][1]{headers}{'Content-Type'}, 'application/json', 'as json');
    like($sent[0][1]{body}, qr/fp-a-1/, 'carrying the records');
    like($sent[0][1]{body}, qr/fp-b-2/, '...from both batches');

    is($spool->depth, 0, 'accepted, so the spool is empty');
    is($shipper->counters->{shipped}, 2, 'batches counted');
    is($shipper->counters->{records}, 4, 'and records');
}

# gzip, when it is worth it
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    $spool->push_batch(recs(200, 'big'));

    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(200) });
    my $shipper = Maat::Shipper->new(url => 'https://cp.example/v1',
                                     spool => $spool, ua => $ua);
    $shipper->drain;

    is($sent[0][1]{headers}{'Content-Encoding'}, 'gzip', 'a big batch is gzipped');
    ok($shipper->counters->{gzip_saved} > 0, 'and the saving is counted');

    # it really is gzip - the header, and the records back out of it
    is(unpack("H4", $sent[0][1]{body}), "1f8b", "with the gzip magic");
    require IO::Uncompress::Gunzip;
    my $out;
    ok(IO::Uncompress::Gunzip::gunzip(\$sent[0][1]{body} => \$out),
        "and it gunzips");
    like($out, qr/fp-big-1/, "back to what was spooled");
}

{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    $spool->push_batch([ { fingerprint => 'tiny' } ]);
    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(200) });
    Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
                       ua => $ua)->drain;
    ok(!exists $sent[0][1]{headers}{'Content-Encoding'},
        'a small batch is sent as it is - the cpu is not worth it');
}

# ---- gate 2: the control plane is unreachable ------------------------------
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir, max_files => 20);

    my $up = 0;
    my $tries = 0;
    my $ua = FakeUA->new(sub { $tries++;
                               return $up ? FakeRes->new(200) : FakeRes->new(503) });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
                                     ua => $ua, gzip => 0, batch => 5);

    # ten minutes of an outage, one batch every ten seconds
    my $t = time;
    for my $minute (0 .. 9) {
        for my $tick (0 .. 5) {
            $spool->push_batch(recs(1, "m$minute-t$tick"));
            $shipper->tick($t + $minute * 60 + $tick * 10);
        }
    }

    cmp_ok($spool->depth, '<=', 20, 'the spool bound held through the outage');
    ok($spool->counters->{dropped} > 0, 'the overflow was dropped');
    is($spool->counters->{spooled},
       $spool->depth + $spool->counters->{dropped},
       'and the arithmetic is exact: everything spooled was kept or dropped');
    ok($shipper->counters->{ship_failed} > 0, 'the failures were counted');
    cmp_ok($tries, '<', 60,
        "the backoff kept it from hammering ($tries attempts in ten minutes)");
    is($shipper->counters->{shipped}, 0, 'nothing was reported as shipped');

    # and everything since reconnection arrives
    $up = 1;
    my $held = $spool->depth;
    $shipper->drain($t + 3600);            # past any backoff
    $shipper->drain($t + 3601) while $spool->depth;
    is($spool->depth, 0, 'after reconnection the spool drains completely');
    is($shipper->counters->{shipped}, $held, 'everything it still held arrived');
}

# a shipper with nowhere to send is not an error, it just does nothing
{
    my $shipper = Maat::Shipper->new;
    ok(!$shipper->enabled, 'no url: not enabled');
    is($shipper->drain, 0, 'and draining is a no-op');
}

# one flight at a time: a slow control plane must not stack up requests
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    $spool->push_batch(recs(1, $_)) for 1 .. 5;
    my $calls = 0;
    my $ua = FakeUA->new(sub { $calls++; return PendingFuture->new });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
                                     ua => $ua, batch => 1);
    $shipper->drain($_) for 1 .. 5;
    is($calls, 1, 'a second drain does not start while one is in flight');
}

# ---- coverage rides the same channel ----------------------------------------
#
# The question it answers is the one an empty drift page cannot: a
# customer with no violations is either covered and conforming, or not
# being looked at.
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);

    my $cov = { getOrder => { total => 100, checked => 4, sampled => 4,
                              skip_unsampled => 96, divisor => 25 } };
    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(202) });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
                                     ua => $ua, gzip => 0,
                                     coverage_interval => 60,
                                     coverage => sub { $cov });

    my $t = time;
    $shipper->drain($t);
    is(scalar @sent, 1, 'coverage ships with nothing on the spool at all');
    my $body = File::Raw::JSON::file_json_decode($sent[0][1]{body});
    is(ref $body, 'HASH', 'an envelope rather than a bare array');
    is_deeply($body->{records}, [], 'no records');
    is($body->{coverage}{getOrder}{checked}, 4, 'the coverage snapshot');
    is($shipper->counters->{coverage_shipped}, 1, 'and it is counted');

    # not again until the interval is up
    $shipper->drain($t + 1);
    is(scalar @sent, 1, 'the snapshot does not repeat every drain');

    $shipper->drain($t + 61);
    is(scalar @sent, 2, 'and does go again when the interval is up');

    # with records, both travel in one request
    $spool->push_batch(recs(2, 'c'));
    $shipper->drain($t + 122);
    $body = File::Raw::JSON::file_json_decode($sent[-1][1]{body});
    is(scalar @{ $body->{records} }, 2, 'records ride the same request');
    ok($body->{coverage}, '...alongside the coverage');
}

# a snapshot that did not land is retried on the next drain, not skipped
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    my $ok = 0;
    my @sent;
    my $ua = FakeUA->new(sub {
        push @sent, [ @_ ];
        return FakeRes->new($ok ? 202 : 500);
    });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
                                     ua => $ua, gzip => 0,
                                     coverage_interval => 3600,
                                     coverage => sub { { op => { total => 1 } } });
    my $t = time;
    $shipper->drain($t);
    is(scalar @sent, 1, 'the first attempt goes');
    is($shipper->counters->{coverage_shipped}, 0, 'and is not counted as landed');

    $ok = 1;
    $shipper->drain($t + 1000);      # past the backoff, well inside the hour
    is(scalar @sent, 2, 'it is tried again rather than waiting out the hour');
    is($shipper->counters->{coverage_shipped}, 1, 'and now it has landed');
}

# a gateway that reports no coverage behaves exactly as before
{
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(202) });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
                                     ua => $ua, gzip => 0);
    is($shipper->drain, 0, 'an empty spool and no coverage sends nothing');

    $spool->push_batch(recs(1, 'plain'));
    $shipper->drain;
    my $body = File::Raw::JSON::file_json_decode($sent[0][1]{body});
    is(ref $body, 'ARRAY', 'and records still travel as a bare array');
}

# ---- metering: the only writer of the bill ---------------------------------
#
# The site has accepted { usage: [...] } since phase 5 and the gateway
# never sent it, so the account page's meter read zero for every customer
# forever. These are the properties that make it a billing channel rather
# than a counter: it can ship on its own, a retry cannot double-bill, a
# failed POST does not lose an hour, and an idle tenant is silent.

{
    my $dir   = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);

    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(200) });

    my @committed;
    my @usage = ({ hour => 1754000000, requests => 42, gateway => 'box-a/7' });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
        ua => $ua, gzip => 0,
        usage      => sub { @usage ? [ @usage ] : undef },
        usage_done => sub { push @committed, @{ $_[0] } });

    # Nothing on the spool at all: conforming traffic produces no
    # violations, and that customer still has a bill.
    ok($shipper->drain >= 0, 'a drain happens with an empty spool');
    is(scalar @sent, 1, 'usage alone causes a request');
    my $body = File::Raw::JSON::file_json_decode($sent[0][1]{body});
    is(ref $body, 'HASH', 'so the body is the envelope, not a bare array');
    is_deeply($body->{records}, [], '...with no records');
    is_deeply($body->{usage}, \@usage, '...and the hours, with their reporter');
    is($shipper->counters->{usage_shipped}, 1, 'counted');
    is_deeply(\@committed, \@usage,
        'and committed only after the control plane took it');
}

# A gateway with NO SPOOL still meters, and this is the one that made the
# meter read zero in production. A hosted tenant never gets a spool
# directory of its own - Maat::Config->tenant has nowhere to put one - and
# drain used to return early without one, so the whole reporting channel
# was inert in the fleet: no usage, no coverage, for every customer.
# Violations still need the disk, because they are accumulated detail
# rather than a running total.
{
    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(200) });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', ua => $ua,
        gzip => 0,
        usage    => sub { [ { hour => 1754000000, requests => 7 } ] },
        coverage => sub { { listPets => { total => 7, checked => 1 } } });

    ok(!$shipper->spool, 'no spool at all');
    $shipper->drain;
    is(scalar @sent, 1, 'and it still ships');
    my $body = File::Raw::JSON::file_json_decode($sent[0][1]{body});
    is($body->{usage}[0]{requests}, 7, 'the hour is there');
    ok($body->{coverage}{listPets}, 'and what was weighed');
}

# a refusal must not commit: an hour marked shipped that never landed is
# an hour nobody is billed for
{
    my $dir   = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    my $ua = FakeUA->new(sub { FakeRes->new(503) });
    my @committed;
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
        ua => $ua, gzip => 0,
        usage      => sub { [ { hour => 1754000000, requests => 42 } ] },
        usage_done => sub { push @committed, @{ $_[0] } });

    $shipper->drain;
    is_deeply(\@committed, [], 'a rejected batch commits nothing');
    is($shipper->counters->{usage_shipped}, 0, 'and counts nothing');
}

# and an idle tenant says nothing at all
{
    my $dir   = File::Temp::tempdir(CLEANUP => 1);
    my $spool = Maat::Spool->new(dir => $dir);
    my @sent;
    my $ua = FakeUA->new(sub { push @sent, [ @_ ]; FakeRes->new(200) });
    my $shipper = Maat::Shipper->new(url => 'https://cp/v1', spool => $spool,
        ua => $ua, gzip => 0, usage => sub { undef });
    is($shipper->drain, 0, 'no records, no moved hours, no drain');
    is(scalar @sent, 0, 'nothing is sent - no five-second heartbeat');
}

done_testing();

# ---- doubles ----------------------------------------------------------------

{
    package FakeUA;
    sub new { my ($c, $cb) = @_; bless { cb => $cb }, $c }
    sub post {
        my ($self, $url, %args) = @_;
        return $self->{cb}->($url, \%args);
    }

    package FakeRes;
    sub new  { my ($c, $code) = @_; bless { code => $code }, $c }
    sub code { $_[0]{code} }

    # A future that never resolves, for the in-flight test.
    package PendingFuture;
    sub new     { bless {}, shift }
    sub on_done { $_[0] }
    sub on_fail { $_[0] }
    sub can     { my ($s, $m) = @_; return $m eq 'on_done' ? sub {1} : undef }
}
