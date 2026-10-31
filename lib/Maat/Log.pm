package Maat::Log;

use 5.010;
use strict;
use warnings;

use Time::HiRes ();

our $VERSION = '0.06';

# One JSON object per line, on STDERR.
#
# The fleet used to say one thing - a banner at start - and then nothing
# for the rest of its life, while Maat::Registry, Maat::Poller and
# Maat::Router each kept counters nobody could read. An hour of
# diagnosing a hung compile from the outside is what this file is for.
#
# STDERR rather than a file of its own because both supervisors already
# have somewhere for it to go: bin/fleet_server redirects to
# /var/log/maat/fleet.log, and examples/apip-fleet.service sends it to
# journald. A log this module opened itself would be a third convention
# and a fourth thing to rotate.
#
# ---- three rules ----
#
# OFF UNLESS ASKED. A library that writes to STDERR the moment it is
# loaded is a library that ruins somebody's CLI output. Maat::Fleet turns
# it on; `apip run` and the test suite stay quiet.
#
# NEVER DIES, NEVER WARNS. Every interesting call site is an error path -
# a compile that failed, a bundle that would not verify. An emitter that
# throws there turns a bad minute into an outage, and one that warns
# turns a structured log into a mixed one. A line that cannot be encoded
# is dropped.
#
# NEVER ON THE HOT PATH. Nothing here is called per request. The
# per-request facts - routed, unknown_host, rejected - stay counters and
# reach an operator through the stats dump, because a line per unknown
# host is a log-flooding lever any stranger can pull with a made-up
# hostname.

my $ENABLED = 0;
my $FH;

# enable(1) / enable(0), or enable(1, $handle) to send it somewhere else -
# which is how the tests read what was written without capturing STDERR.
sub enable {
    my ($class, $on, $fh) = @_;
    $ENABLED = $on ? 1 : 0;
    $FH = $fh;
    return $ENABLED;
}

sub enabled { $ENABLED }

# event(ev => 'compile', phase => 'fail', host => ..., err => ...)
#
# `ev` names the thing that happened and everything else is its detail.
# `worker` and `t` are always stamped: four workers interleave in one
# log, so a line that does not say which process wrote it cannot be
# attributed, and half of an incident is working out whether one worker
# is behaving differently from its siblings.
sub event {
    my ($class, %f) = @_;
    return 0 unless $ENABLED;

    $f{worker} = $$;
    $f{t}      = sprintf '%.3f', Time::HiRes::time();

    my $line = eval {
        require File::Raw::JSON;
        File::Raw::JSON::file_json_encode(\%f, sort_keys => 1);
    };
    return 0 unless defined $line;

    # Local $\ and $, : a caller that set either would otherwise corrupt
    # every line this writes, and one malformed line breaks a parser for
    # the whole file.
    local ($\, $,) = (undef, undef);
    my $out = $FH || \*STDERR;
    eval { print {$out} $line, "\n"; 1 } or return 0;
    return 1;
}

# The duration helper the timing fields want, so every call site rounds
# the same way and a reader can compare two of them.
sub since { return sprintf '%.3f', Time::HiRes::time() - $_[1] }

1;

__END__

=head1 NAME

Maat::Log - structured events, one JSON object per line

=head1 SYNOPSIS

    Maat::Log->enable(1);

    Maat::Log->event(ev => 'compile', phase => 'start', host => $host);
    Maat::Log->event(ev => 'compile', phase => 'fail',
                     host => $host, err => $why,
                     took => Maat::Log->since($t0));

    {"ev":"compile","host":"a.example","phase":"start","t":"...","worker":100118}

=head1 DESCRIPTION

The fleet's event log. One JSON object per line on C<STDERR>, which is
where both supervisors already point: F<bin/fleet_server> redirects to
F</var/log/maat/fleet.log> and F<examples/apip-fleet.service> sends it to
journald.

Counters are the other half and live elsewhere - see
L<Maat::Registry/snapshot> and C<apip-fleet stats>. Events say what
happened and when; counters say how much. The per-request facts are
counters on purpose: a line per unknown host would let a stranger flood
this log with a made-up hostname.

=head2 Off unless asked

Loading this module writes nothing. L<Maat::Fleet> enables it from its
configuration; C<apip run> and the test suite stay silent.

=head2 It never dies and never warns

Every interesting call site is a failure path. An emitter that throws
inside an error handler turns a bad minute into an outage, and one that
warns puts unstructured text in the middle of a structured log. A line
that will not encode is dropped.

=head1 METHODS

=head2 enable($on, $fh?)

Turn it on or off. An optional handle sends lines somewhere other than
C<STDERR>, which is how the tests read them.

=head2 enabled

=head2 event(%fields)

Write one line. C<ev> names the event; C<worker> (the pid) and C<t> (a
high-resolution epoch) are always added, because four workers interleave
in one log and an unattributable line is half an answer. Returns true
when a line was written.

=head2 since($t0)

Seconds since C<$t0>, to three places - so every duration in the log
rounds the same way and two of them can be compared.

=head1 SEE ALSO

L<Maat::Fleet>, L<Maat::Registry>.

=head1 AUTHOR

LNATION <email@lnation.org>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by LNATION <email@lnation.org>.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
