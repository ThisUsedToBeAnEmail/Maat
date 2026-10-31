package Maat::Sampler;

use 5.010;
use strict;
use warnings;
use POSIX ();

our $VERSION = '0.03';

# How much response validation to do, per operation.
#
# Open::API's gate takes a divisor: validate one response in N for this
# operation, counted deterministically. What is left is choosing N, and
# the honest answer depends on traffic - 1-in-1 is right for an endpoint
# serving two requests a minute and ruinous for one serving twenty
# thousand a second.
#
# So N is recomputed from observed traffic on a timer and looked up per
# request. Two numbers control it:
#
#   budget   at most this many validated responses per second per
#            operation. This is the cost ceiling: whatever the traffic,
#            the work per operation is bounded.
#   floor    and never let an operation go longer than this many seconds
#            without a validated response, so a quiet endpoint is still
#            covered rather than merely cheap.
#
# The budget is per operation rather than per process on purpose: a
# customer's one hot endpoint must not spend the whole validation budget
# and leave the other ninety uncovered. Coverage is the product.

sub new {
    my ($class, %o) = @_;
    my $mode = defined $o{mode} ? $o{mode} : 'adaptive';
    my $interval = defined $o{interval} ? $o{interval} : 1;
    my $self = bless {
        mode     => $mode,
        budget   => defined $o{budget}   ? $o{budget}   : 50,
        floor    => defined $o{floor}    ? $o{floor}    : 10,
        interval => $interval,
        fixed    => defined $o{fixed}    ? $o{fixed}    : 1,
        max_body => defined $o{max_body} ? $o{max_body} : 1024 * 1024,
        n        => {},     # operationId -> current divisor
        opts     => {},     # operationId -> the options hashref to pass
        seen     => {},     # operationId -> total at the last retune
        at       => time,

        # ---- the hot-path contract ----
        # These two are read directly, by field, on every proxied
        # response. They are documented and supported for that: a method
        # call costs 0.08us and the C check it guards costs 0.06us, so
        # going through an accessor would make asking the question dearer
        # than answering it. Nothing outside this file writes them.
        next_at    => time + $interval,   # when a retune becomes due
        generation => 0,                  # bumped when any divisor moves
    }, $class;
    return $self;
}

sub mode     { $_[0]{mode} }
sub budget   { $_[0]{budget} }
sub floor    { $_[0]{floor} }
sub divisors { $_[0]{n} }

# The divisor for an operation right now. A hash lookup: the arithmetic
# happened at the last retune.
sub divisor {
    my ($self, $op) = @_;
    return 0 if $self->{mode} eq 'off';
    my $n = $self->{n}{$op};
    return $n if defined $n;
    # Unseen. A fixed sampler starts at what it was asked for; an
    # adaptive one validates everything until the first retune tells it
    # otherwise.
    return $self->{mode} eq 'fixed' ? $self->{fixed} : 1;
}

# The options hashref for check_response, cached per operation and rebuilt
# only when the divisor changes.
#
# It is cached because the alternative is an allocation per request. A
# two-key hash is nothing on its own, and 0.11us on the hot path of a
# gateway that costs 2.4us in total is not nothing - it is most of what
# sampling was supposed to save. Returns undef when nothing is to be
# validated, which is the caller's signal to skip the check entirely.
sub options {
    my ($self, $op) = @_;
    return undef if $self->{mode} eq 'off';
    my $o = $self->{opts}{$op};
    return $o if $o;
    return $self->{opts}{$op} =
        { sample => $self->divisor($op), max_body => $self->{max_body} };
}

# Is a retune due? Asked per request, so it must be a clock read and an
# integer comparison and nothing else - in particular the caller must not
# have to build the coverage hash to find out, which costs more than the
# check it is feeding.
sub due {
    my ($self, $now) = @_;
    return 0 if $self->{mode} eq 'off';
    $now = time unless defined $now;
    return ($now - $self->{at}) >= $self->{interval} ? 1 : 0;
}

# Recompute every divisor from the coverage counters, if the interval has
# elapsed. Returns 1 when it ran, 0 when it was too soon.
#
# Fixed mode retunes too, and only for the floor: a fixed divisor is a
# ceiling on how much is looked at, never a reason to look at less than
# the floor demands. `sample: 100` on an operation serving two requests
# an hour would otherwise validate one response every fifty hours, which
# is a coverage report that reads empty rather than clean.
#
# Off mode still returns early, but advances the clock on its way out.
# The request path guards this call with `$now >= $sampler->{next_at}`
# and builds the coverage hash to pass in - so a next_at that never
# moves turns a once-an-interval cost into a per-response one.
sub retune {
    my ($self, $coverage, $now) = @_;
    $now = time unless defined $now;

    my $elapsed = $now - $self->{at};
    return 0 if $elapsed < $self->{interval};
    $self->{at}      = $now;
    $self->{next_at} = $now + $self->{interval};
    return 0 if $self->{mode} eq 'off';
    $elapsed = $self->{interval} if $elapsed <= 0;

    my $fixed  = $self->{mode} eq 'fixed' ? $self->{fixed} : 0;
    my $budget = $self->{budget};
    my $floor  = $self->{floor};

    for my $op (keys %$coverage) {
        my $total = $coverage->{$op}{total} || 0;
        my $prev  = $self->{seen}{$op};
        $self->{seen}{$op} = $total;

        # A counter that went backwards means a fresh spec object under
        # this operationId. Start again rather than compute from a
        # negative delta.
        $prev = 0 if !defined $prev || $prev > $total;

        my $rate = ($total - $prev) / $elapsed;    # responses per second

        # Fixed: the configured divisor is where we start, and the floor
        # below is the only thing that may lower it. Adaptive: under
        # budget validate everything, over it thin out just enough that
        # the validated rate lands on the budget.
        my $n = $fixed ? $fixed
              : $rate <= $budget ? 1
              : POSIX::ceil($rate / $budget);

        # The floor. Sampling 1-in-N at r/s validates one every N/r
        # seconds, so N must not exceed r*floor. At any sane budget this
        # never binds - the divisor is already smaller - but it is the
        # rule that makes "covered, not merely cheap" a property rather
        # than a hope, so it is enforced instead of assumed.
        my $cap = int($rate * $floor);
        $cap = 1 if $cap < 1;
        $n = $cap if $n > $cap;

        $n = 1 if $n < 1;
        if (!defined $self->{n}{$op} || $self->{n}{$op} != $n) {
            $self->{n}{$op} = $n;
            delete $self->{opts}{$op};    # rebuilt on the next request
            $self->{generation}++;        # tells the request path to re-look
        }
    }

    # An operation that has stopped being served keeps its divisor; it
    # costs one hash slot and is right again the moment traffic returns.
    return 1;
}

1;

__END__

=head1 NAME

Maat::Sampler - how much response validation to do, per operation

=head1 SYNOPSIS

    my $s = Maat::Sampler->new(budget => 50, floor => 10);

    $s->retune($api->response_coverage);       # cheap; runs on a timer
    my $n = $s->divisor('getPet');             # a hash lookup

    my $errors = $api->check_response($op, $trip, { sample => $n });

=head1 DESCRIPTION

Open::API's sampling gate takes a divisor - validate one response in N
for this operation - and this chooses N from observed traffic.

Two numbers control it. C<budget> is at most that many validated
responses per second per operation, which bounds the cost whatever the
traffic does. C<floor> is the other direction: never let an operation go
longer than that many seconds without a validated response, so a quiet
endpoint is covered rather than merely cheap.

The budget is per operation, not per process. A customer's one hot
endpoint must not spend the whole validation budget and leave the other
ninety uncovered - coverage across the contract is the product, not
validated requests per second.

=head2 Why a timer

C<retune> does the arithmetic for every operation at once, at most once
per C<interval> seconds; C<divisor> is then a hash lookup. Calling
C<retune> on every request is fine and is what the gateway does: all but
one call in a second's traffic compares two integers and returns.

=head1 METHODS

=head2 new(mode => ..., budget => 50, floor => 10, interval => 1, fixed => 1)

C<mode> is C<adaptive> (the default), C<fixed> (C<fixed> as a ceiling -
see below) or C<off> (no response validation at all).

=head2 The floor applies in fixed mode too

C<fixed> is a ceiling on how much is looked at, not a reason to look at
less than C<floor> demands. C<sample: 100> against an operation serving
two requests an hour would otherwise validate one response every fifty
hours, and a coverage report built from that reads empty rather than
clean. So a fixed sampler retunes as well, and the only thing that
moves its divisor is the floor lowering it.

At any volume where the ceiling is the interesting number - where
C<rate * floor> exceeds it - the divisor is exactly what was asked for.

=head2 divisor($op_id)

The divisor for that operation now. An operation not yet seen gets the
fixed divisor in fixed mode, and 1 in adaptive - validate everything
until there is enough traffic to say otherwise.

=head2 retune(\%coverage, $now?)

Recompute from L<Open::API/response_coverage>, if the interval has
elapsed. Returns 1 when it ran, 0 when it was too soon.

An C<off> sampler returns 0 without recomputing, but still advances its
clock. The request path guards this call with C<next_at> and builds the
coverage hash to pass in, so a C<next_at> that never moved would turn a
once-an-interval cost into a per-response one.

=head2 mode / budget / floor / divisors

=cut
