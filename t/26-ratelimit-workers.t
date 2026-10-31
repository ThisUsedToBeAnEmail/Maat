use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;   # puts the sibling blibs (Legba included) on @INC
use Test::More;

use Maat::RateLimit ();
use File::Temp ();
use Time::HiRes ();
use POSIX ();

# GATE 1: a limit of 100/min holds across FOUR workers under concurrent
# load - exact to one request, not "roughly".
#
# The counter is process-shared through an flock'd file, so four separate
# processes hammering the same (key, operation) share one count. This is
# the faithful multi-process test the gate asks for: four real forked
# workers, each trying more than the whole limit, and the total admitted
# is exactly the limit - which is only possible if they share the counter
# and the increment is atomic across processes.

my $WORKERS  = 4;
my $LIMIT    = 100;
my $PER_WORK = 100;   # each worker alone tries the whole limit; shared, they get 1/4 each on average

my $dir = File::Temp::tempdir('maat-rl26-XXXXXX', TMPDIR => 1, CLEANUP => 1);

# One pinned window shared by every worker (set before the fork, so each
# inherits the same value): the test must not straddle a minute boundary.
my $t0 = 1_700_000_000;

# A wall-clock start a moment in the future, so the workers begin together
# and genuinely contend rather than running one after another.
my $go = Time::HiRes::time() + 0.3;

sub worker {
    my ($id) = @_;
    my $rl = Maat::RateLimit->new(dir => $dir, now => sub { $t0 });
    Time::HiRes::sleep($go - Time::HiRes::time()) if Time::HiRes::time() < $go;
    my $allowed = 0;
    for (1 .. $PER_WORK) {
        my ($ok) = $rl->allow('key-shared', 'op-shared', $LIMIT);
        $allowed++ if $ok;
        # a hair of jitter so the four interleave inside each other's
        # read-modify-write windows rather than lining up
        Time::HiRes::sleep(0.0005) if $_ % 7 == 0;
    }
    return $allowed;   # 0..100, fits an exit code
}

my @pids;
for my $id (1 .. $WORKERS) {
    my $pid = fork;
    die "fork: $!" unless defined $pid;
    if (!$pid) {
        my $allowed = worker($id);
        POSIX::_exit($allowed);
    }
    push @pids, $pid;
}

my $total = 0;
for my $pid (@pids) {
    waitpid $pid, 0;
    $total += ($? >> 8);
}

is $total, $LIMIT,
    "gate 1: exactly $LIMIT requests admitted across $WORKERS workers "
  . "(each tried $PER_WORK, $WORKERS*$PER_WORK = @{[ $WORKERS*$PER_WORK ]} total)";

# The count in the shared file agrees: every attempt was recorded, allowed
# or not, so the window count is the total attempts and the admitted count
# is exactly the limit.
my $rl = Maat::RateLimit->new(dir => $dir, now => sub { $t0 });
is $rl->peek('key-shared', 'op-shared'), $WORKERS * $PER_WORK,
    'every attempt from every worker landed in the one shared counter';

# Control: the same load in ONE process against a FRESH dir admits exactly
# the limit too - proving the number above is the limiter being exact, not
# an artifact of the fork.
{
    my $d2 = File::Temp::tempdir('maat-rl26b-XXXXXX', TMPDIR => 1, CLEANUP => 1);
    my $rl2 = Maat::RateLimit->new(dir => $d2, now => sub { $t0 });
    my $allowed = 0;
    for (1 .. $WORKERS * $PER_WORK) {
        my ($ok) = $rl2->allow('k', 'o', $LIMIT);
        $allowed++ if $ok;
    }
    is $allowed, $LIMIT, "single-process control: exactly $LIMIT admitted";
}

# Control the other way: if the workers did NOT share (a dir each), each
# would admit the whole limit, so the total would be WORKERS*LIMIT. This
# is what makes the shared result above meaningful.
{
    my $unshared_total = 0;
    for my $id (1 .. $WORKERS) {
        my $d = File::Temp::tempdir('maat-rl26c-XXXXXX', TMPDIR => 1, CLEANUP => 1);
        my $rl3 = Maat::RateLimit->new(dir => $d, now => sub { $t0 });
        my $allowed = 0;
        for (1 .. $PER_WORK) {
            my ($ok) = $rl3->allow('k', 'o', $LIMIT);
            $allowed++ if $ok;
        }
        $unshared_total += $allowed;
    }
    is $unshared_total, $WORKERS * $LIMIT,
        "unshared counters would admit $WORKERS x $LIMIT - so sharing is what held the line";
}

done_testing;
