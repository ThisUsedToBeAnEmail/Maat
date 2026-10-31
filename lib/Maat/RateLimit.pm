package Maat::RateLimit;

use 5.010;
use strict;
use warnings;
use Carp ();
use Fcntl qw(:flock :seek O_RDWR O_CREAT);
use Digest::SHA ();
use File::Spec ();
use File::Temp ();
use Legba ();

our $VERSION = '0.05';

# The rate limiter's state, deliberately NOT in the compiled-spec object.
#
# A rate limit has to be true across the workers of one gateway (gate 1)
# and it has to survive a spec publish (gate 2), and those two facts
# decide where the counter lives:
#
#   PROCESS-SHARED, NOT PER-WORKER. Four Hyperman workers serving one
#   gateway must share one count or a 100/min limit becomes 400/min. So
#   the count is not a Perl variable in a worker - a fork gives each
#   worker its own copy of those - but a small fixed-window record in a
#   file the workers share, incremented under flock. flock is the
#   arbitration; the read-modify-write between LOCK_EX and LOCK_UN is
#   atomic across processes, so the total across every worker is exact to
#   one request, which is what gate 1 asks for.
#
#   ANCHORED IN LEGBA, OUTLIVING THE SPEC. Maat::Registry swaps compiled
#   Open::API objects atomically on every publish and rebuilds a tenant's
#   app around the new one - so anything the limiter held INSIDE that app
#   would reset on a deploy. The limiter is anchored in a Legba slot
#   instead (Legba slots are process-global and untouched by
#   apply_bundle), and its counts live in files keyed by (key-id,
#   operation) - both independent of the compiled-spec object. A publish
#   therefore cannot reset a count: gate 2.
#
# Legba 0.08 is not itself process-shared across a fork (its slots are
# copy-on-write, by its own POD), so it is used here for what it IS - a
# process-global anchor that a registry swap does not touch - while the
# cross-process arithmetic is done in the flock'd file. See the report /
# POD note on that division of labour.

my $WINDOW = 60;   # the fixed window, in seconds: "per minute"
my $SLOT   = 'maat_ratelimit';

sub new {
    my ($class, %o) = @_;

    my $dir = $o{dir};
    if (!defined $dir) {
        # A per-fleet directory, made once. When a gateway process makes
        # it before Hyperman forks its workers, every worker inherits the
        # same path and so shares the same counters; a test makes one and
        # hands it to the children it forks.
        $dir = File::Temp::tempdir('maat-rl-XXXXXX', TMPDIR => 1, CLEANUP => 1);
    }
    elsif (!-d $dir) {
        mkdir $dir or Carp::croak("Maat::RateLimit: cannot make '$dir': $!");
    }

    return bless {
        dir    => $dir,
        window => $o{window} || $WINDOW,
        now    => $o{now},     # test hook: a coderef returning the epoch
        fh     => {},          # counter path -> open filehandle, cached
    }, $class;
}

# The single limiter for this process, anchored in a Legba slot so a
# registry swap (which rebuilds tenant apps) reuses the SAME instance and
# its counts rather than a fresh one. Created once, on first ask.
sub shared {
    my ($class, %o) = @_;
    Legba::add($SLOT) unless Legba::exists($SLOT);
    my $rl = Legba::get($SLOT);
    if (!$rl || !ref $rl) {
        $rl = $class->new(%o);
        Legba::set($SLOT, $rl);
    }
    return $rl;
}

# For tests: forget the anchored instance so the next shared() builds a
# fresh one (a new process would not need this; one test process reusing
# the slot across cases does).
sub _reset_shared {
    Legba::set($SLOT, undef) if Legba::exists($SLOT);
    return;
}

sub dir    { $_[0]{dir} }
sub window { $_[0]{window} }

sub _now { my ($self) = @_; return $self->{now} ? $self->{now}->() : time }

# One counter file per (key-id, operation). The name is a digest so an
# operationId with a slash or an odd byte never escapes the directory.
sub _path {
    my ($self, $key_id, $op) = @_;
    my $tag = Digest::SHA::sha1_hex(
        (defined $key_id ? $key_id : '') . "\0" . (defined $op ? $op : ''));
    return File::Spec->catfile($self->{dir}, "$tag.cnt");
}

sub _fh {
    my ($self, $path) = @_;
    return $self->{fh}{$path} if $self->{fh}{$path};
    sysopen(my $fh, $path, O_RDWR | O_CREAT, 0600)
        or Carp::croak("Maat::RateLimit: cannot open '$path': $!");
    binmode $fh;
    return $self->{fh}{$path} = $fh;
}

# One hit against (key-id, operation) under a per-minute limit.
#
# Returns ($ok, $limit, $remaining, $reset):
#   $ok        1 if this request is within the limit, 0 if it is over
#   $limit     the limit in force (echoed for the X-RateLimit-Limit header)
#   $remaining requests left in this window, never below zero
#   $reset     epoch at which the window rolls and the count resets
#
# A limit of 0 (or undef) means unlimited: no file is touched. The count
# is incremented for every hit, allowed or not, so a client that keeps
# hammering past the limit does not get a fresh allowance until the window
# rolls - a fixed window, the smallest honest limiter.
sub allow {
    my ($self, $key_id, $op, $limit) = @_;
    return (1, 0, -1, 0) if !$limit || $limit <= 0;      # unlimited

    my $now    = $self->_now;
    my $window = $self->{window};
    my $wstart = $now - ($now % $window);
    my $reset  = $wstart + $window;

    my $fh = $self->_fh($self->_path($key_id, $op));

    # flock is the arbitration between workers: the read, the decision and
    # the write all happen while we hold LOCK_EX, so two workers can never
    # both read the same count and both write count+1. A lock we cannot
    # get is a failure of the limiter, not of the request - fail open, the
    # same principle as the rest of the gateway.
    if (!flock($fh, LOCK_EX)) {
        return (1, $limit, $limit - 1, $reset);
    }

    my ($fw, $count) = (0, 0);
    sysseek($fh, 0, SEEK_SET);
    my $buf = '';
    sysread($fh, $buf, 64);
    if (defined $buf && $buf =~ /\A(\d+):(\d+)/) {
        ($fw, $count) = ($1 + 0, $2 + 0);
    }
    # A window we have rolled past starts clean. This is the whole of the
    # reset: no timer, no sweep - the window is a function of the clock,
    # and the first request of a new one finds a stale record and zeroes
    # it.
    if ($fw != $wstart) { $fw = $wstart; $count = 0; }
    $count++;
    my $ok = $count <= $limit ? 1 : 0;

    # Fixed width, so a shorter count (100 -> 99, a new window) never
    # leaves a trailing digit of the old one behind.
    my $rec = sprintf "%-63s\n", "$fw:$count";
    sysseek($fh, 0, SEEK_SET);
    syswrite($fh, $rec);
    flock($fh, LOCK_UN);

    my $remaining = $limit - $count;
    $remaining = 0 if $remaining < 0;
    return ($ok, $limit, $remaining, $reset);
}

# The current count for (key-id, operation) in the live window, without
# incrementing. For tests and introspection.
sub peek {
    my ($self, $key_id, $op) = @_;
    my $now    = $self->_now;
    my $window = $self->{window};
    my $wstart = $now - ($now % $window);
    my $path   = $self->_path($key_id, $op);
    return 0 unless -e $path;
    my $fh = $self->_fh($path);
    flock($fh, LOCK_SH) or return 0;
    sysseek($fh, 0, SEEK_SET);
    my $buf = '';
    sysread($fh, $buf, 64);
    flock($fh, LOCK_UN);
    return 0 unless defined $buf && $buf =~ /\A(\d+):(\d+)/;
    return $1 + 0 == $wstart ? $2 + 0 : 0;
}

1;

__END__

=head1 NAME

Maat::RateLimit - a process-shared, publish-surviving fixed-window limiter

=head1 SYNOPSIS

    my $rl = Maat::RateLimit->shared(dir => '/run/maat/rl');

    my ($ok, $limit, $remaining, $reset) =
        $rl->allow($key_id, $operation_id, $per_minute);
    # $ok == 0 -> answer 429, Retry-After: $reset - time

=head1 DESCRIPTION

A fixed-window rate limiter for the data plane: at most C<$per_minute>
requests per C<(key, operation)> in each wall-clock minute. It is the
minimum a gateway needs before it fronts a public API, and it is
deliberately the smallest version of one.

=head2 Shared across the workers of one gateway

The count is not a Perl variable - a C<fork> would give each worker its
own copy and a 100/min limit would become C<workers> x 100/min. It is a
small record in a file the workers share, incremented under C<flock>: the
read-modify-write between C<LOCK_EX> and C<LOCK_UN> is atomic across
processes, so the total across every worker is exact to one request.

It is B<not> shared across gateways. Two gateways each keep their own
files, so N gateways behind a load balancer admit up to N x the limit.
That is an honest number an operator can reason about, and it is stated
plainly rather than dressed up as a distributed limit this version does
not implement.

=head2 Surviving a publish

L<Maat::Registry> swaps a tenant's compiled spec atomically on every
publish and rebuilds the tenant's app around the new one. A counter held
inside that app would reset on a deploy. So the limiter is anchored in a
L<Legba> slot - process-global, untouched by C<apply_bundle> - via
C<shared>, and its counts live in files keyed by C<(key-id, operation)>,
both independent of the compiled-spec object. A publish cannot reset a
count.

Legba's own slots are copy-on-write across a fork rather than shared
memory, so Legba is used here for what it is - the process-global anchor
that a registry swap does not touch - while the cross-process arithmetic
is done in the C<flock>'d file.

=head2 Off is off

A limit of C<0> (a key marked C<rate_per_min: 0>) is unlimited: C<allow>
touches no file and returns at once. A gateway with no keys never
constructs a limiter at all.

=head1 METHODS

=head2 new(dir => $path, window => 60, now => \&clock)

C<dir> is where the counter files live; without one a private temp
directory is used (fine for a single process, useless across a fork -
give a real shared path in production). C<now> overrides the clock for
tests.

=head2 shared(%args)

The one limiter for this process, anchored in a Legba slot so a registry
swap reuses it. Built once, on first call.

=head2 allow($key_id, $operation, $per_minute)

Count one hit and decide it. Returns
C<($ok, $limit, $remaining, $reset)>.

=head2 peek($key_id, $operation)

The current count in the live window, without incrementing.

=cut
