package Maat::Shipper;

use 5.010;
use strict;
use warnings;
use Maat::Spool ();

our $VERSION = '0.03';

# Getting violations to the control plane, without the gateway ever
# waiting for it.
#
# Everything here runs on the worker's own loop, between requests: the
# window is flushed onto the spool, and the spool is drained by HTTP when
# there is something to drain and the backoff allows it. The request path
# calls `tick`, which in the overwhelmingly common case looks at the
# clock and returns.
#
# The failure that matters is the control plane being down. When it is:
# nothing is retried in a tight loop (the backoff doubles to a ceiling),
# nothing accumulates in memory (the spool is on disk and bounded), and
# no request is affected (the send is a future, and its failure only
# leaves the batch on the spool for next time). A control plane outage
# should be invisible from the customer's side except as a delay in their
# dashboard.

my $DEFAULT_INTERVAL = 5;      # seconds between drain attempts
my $DEFAULT_BATCH    = 10;     # spool files per request
my $BACKOFF_START    = 1;
my $BACKOFF_MAX      = 300;    # five minutes; a deploy is usually less

# Coverage rides the same channel but on its own, much slower clock. It
# is a snapshot rather than an accumulation - "how much of my traffic
# are you actually looking at, right now" - so shipping it at the
# violation cadence would be the same answer sixty times a minute.
my $DEFAULT_COVERAGE = 60;

sub new {
    my ($class, %o) = @_;

    my $self = bless {
        url      => $o{url},
        token    => $o{token},
        spool    => $o{spool},
        ua       => $o{ua},              # a Fetch, or anything with ->post
        interval => defined $o{interval} ? $o{interval} : $DEFAULT_INTERVAL,
        batch    => defined $o{batch}    ? $o{batch}    : $DEFAULT_BATCH,
        gzip     => defined $o{gzip}     ? $o{gzip}     : 1,
        timeout  => defined $o{timeout}  ? $o{timeout}  : 10,

        # A callback returning the coverage hash, or undef for a gateway
        # that does not report it. Called only when a report is due, so
        # building it costs nothing on the drains in between.
        coverage          => $o{coverage},
        coverage_interval => defined $o{coverage_interval}
                                ? $o{coverage_interval} : $DEFAULT_COVERAGE,
        coverage_at       => 0,          # due immediately: the first
                                         # report is the interesting one

        # Metering. `usage` returns the hours whose totals have moved
        # (or undef), `usage_done` is told which of them the control
        # plane took - a commit rather than a timestamp, because the
        # source has to know exactly which hours landed. No interval of
        # its own: it rides whatever drain is happening, and can cause
        # one, since conforming traffic produces no violations and still
        # produces a bill.
        usage      => $o{usage},
        usage_done => $o{usage_done},

        next_at  => time + (defined $o{interval} ? $o{interval}
                                                 : $DEFAULT_INTERVAL),
        backoff  => 0,                   # 0 = healthy
        inflight => 0,
        counters => {
            shipped      => 0,   # batches the control plane accepted
            records      => 0,   # records inside them
            ship_failed  => 0,   # attempts that did not land
            bytes_sent   => 0,
            gzip_saved   => 0,
            coverage_shipped => 0,   # snapshots the control plane took
            usage_shipped    => 0,   # hour totals it took
        },
    }, $class;

    return $self;
}

sub spool    { $_[0]{spool} }
sub counters { $_[0]{counters} }
sub backoff  { $_[0]{backoff} }
sub enabled  { defined $_[0]{url} && length $_[0]{url} ? 1 : 0 }

# Called from the request path. It has to be cheap enough that a gateway
# doing nothing else pays nothing for having a shipper: a clock read and
# a comparison, and on the interval, one drain.
sub tick {
    my ($self, $now) = @_;
    $now = time unless defined $now;
    return 0 if $now < $self->{next_at};
    $self->{next_at} = $now + $self->{interval};
    return $self->drain($now);
}

# Send what is on the spool. Returns the number of batches attempted.
sub drain {
    my ($self, $now) = @_;
    $now = time unless defined $now;

    return 0 unless $self->enabled;
    return 0 if $self->{inflight};                 # one flight at a time
    return 0 if $self->{backoff} && $now < $self->{backoff};

    # A spool is what makes VIOLATIONS durable - they are accumulated
    # detail, and losing a batch loses it for good, so they go to disk
    # before they go anywhere. Coverage and usage are not like that: each
    # is a running total that the next drain restates, so a gateway with
    # no spool configured can still meter and still report what it
    # weighed. It used to bail here instead, which meant a hosted tenant
    # - who never gets a spool directory of their own - shipped nothing
    # at all, and the account page's meter read zero for every customer.
    my @batches = $self->{spool} ? $self->{spool}->take($self->{batch}) : ();

    # Coverage goes even when nothing is wrong - especially then. A
    # customer with no violations is either covered and conforming, or
    # not being looked at, and those are opposite situations that an
    # empty drift page renders identically.
    my $coverage;
    if ($self->{coverage} && $now >= $self->{coverage_at}) {
        $coverage = eval { $self->{coverage}->() };
        undef $coverage unless ref $coverage eq 'HASH' && %$coverage;
    }

    # Metering rides the same batches, on no clock of its own: the
    # source returns only the hours whose totals have moved, so a busy
    # tenant meters every drain and an idle one adds nothing. It also
    # gets to CAUSE a drain - a proxy can serve a million conforming
    # requests and produce not one violation, and that customer still
    # has a bill.
    my $usage;
    if ($self->{usage}) {
        $usage = eval { $self->{usage}->() };
        undef $usage unless ref $usage eq 'ARRAY' && @$usage;
    }

    return 0 unless @batches || $coverage || $usage;

    my @names   = map { $_->[0] } @batches;
    my @records = map { @{ $_->[1] } } @batches;

    my ($body, $encoding) = $self->_body(
        ($coverage || $usage)
            ? { records => \@records,
                ($coverage ? (coverage => $coverage) : ()),
                ($usage    ? (usage    => $usage)    : ()) }
            : \@records);
    return 0 unless defined $body;

    $self->{inflight} = 1;
    my $future = eval { $self->_send($body, $encoding) };
    if (!$future) {                                # could not even start
        $self->{inflight} = 0;
        $self->_failed($now);
        return scalar @batches;
    }

    # The response is handled when it arrives. Nothing waits for it: the
    # gateway is a proxy, and the one thing the reporting pipeline may
    # never do is make a request wait for a third party.
    my $done = sub {
        my ($res) = @_;
        $self->{inflight} = 0;
        if ($res && $self->_accepted($res)) {
            $self->{spool}->done(@names) if $self->{spool} && @names;
            $self->{counters}{shipped} += scalar @batches;
            $self->{counters}{records} += scalar @records;
            $self->{counters}{bytes_sent} += length $body;
            $self->{backoff} = 0;
            if ($coverage) {
                $self->{counters}{coverage_shipped}++;
                # Only on success, and only here: a snapshot that did not
                # land should be re-sent on the next drain rather than
                # waiting out a whole interval for its replacement.
                $self->{coverage_at} = time + $self->{coverage_interval};
            }
            if ($usage) {
                $self->{counters}{usage_shipped} += scalar @$usage;
                # The same rule, and the reason it is a callback rather
                # than a timestamp: the source has to know WHICH hours
                # landed, so an unshipped one keeps being offered. An
                # hour dropped here is an hour nobody is billed for.
                eval { $self->{usage_done}->($usage) } if $self->{usage_done};
            }
        }
        else {
            $self->_failed(time);          # the batches stay on the spool
        }
        return $res;
    };

    if (ref $future && eval { $future->can('on_done') }) {
        $future->on_done($done);
        $future->on_fail(sub { $self->{inflight} = 0; $self->_failed(time) });
    }
    else {
        $done->($future);                  # a plain response, for tests
    }

    return scalar @batches;
}

sub _accepted {
    my ($self, $res) = @_;
    my $code = eval { $res->can('code') ? $res->code : $res->{status} };
    return 0 unless defined $code;
    return $code >= 200 && $code < 300 ? 1 : 0;
}

# Doubling backoff to a ceiling. The ceiling exists because a control
# plane that has been down for an hour is being deployed or is broken,
# and either way the useful behaviour is to keep trying every few
# minutes rather than to give up or to hammer it.
sub _failed {
    my ($self, $now) = @_;
    $self->{counters}{ship_failed}++;
    my $wait = $self->{backoff_wait} ||= $BACKOFF_START;
    $self->{backoff} = $now + $wait;
    $wait *= 2;
    $wait = $BACKOFF_MAX if $wait > $BACKOFF_MAX;
    $self->{backoff_wait} = $wait;
    return;
}

sub _recovered {
    my ($self) = @_;
    $self->{backoff} = 0;
    delete $self->{backoff_wait};
    return;
}

# The batch on the wire: JSON, gzipped when it is worth it. Violations
# are extremely repetitive - the same operation, pointer and keyword over
# and over - so they compress by an order of magnitude, and the customer
# is paying for that bandwidth.
sub _body {
    my ($self, $records) = @_;
    require File::Raw::JSON;
    my $json = eval { File::Raw::JSON::file_json_encode($records) };
    return (undef, undef) unless defined $json;

    return ($json, undef) unless $self->{gzip};
    return ($json, undef) if length $json < 512;      # not worth the cpu

    my $gz = eval { _gzip($json) };
    return ($json, undef) unless defined $gz && length $gz < length $json;

    $self->{counters}{gzip_saved} += length($json) - length($gz);
    return ($gz, 'gzip');
}

# IO::Compress::Gzip rather than Compress::Raw::Zlib, because the first
# version of this used the latter and produced a raw deflate stream with
# no gzip header while labelling it `Content-Encoding: gzip` - which a
# control plane would reject, silently, for as long as nobody looked.
#
# The trap is that WANT_GZIP is a flag to be ADDED to the window size,
# not a window size, and `MAX_WBITS + WANT_GZIP` without parentheses
# parses as `MAX_WBITS(+WANT_GZIP())` and quietly yields 15. Both
# mistakes produce a plausible-looking compressed string. t/14 inflates
# what this returns rather than trusting its length, which is the only
# reason any of that was noticed.
sub _gzip {
    my ($data) = @_;
    require IO::Compress::Gzip;
    my $out;
    IO::Compress::Gzip::gzip(\$data => \$out, Level => 1) or return undef;
    return $out;
}

sub _send {
    my ($self, $body, $encoding) = @_;
    my $ua = $self->{ua} ||= $self->_ua;
    return undef unless $ua;

    my %headers = ( 'Content-Type' => 'application/json' );
    $headers{'Content-Encoding'} = $encoding if defined $encoding;
    $headers{'Authorization'} = "Bearer $self->{token}"
        if defined $self->{token} && length $self->{token};

    return $ua->post($self->{url}, headers => \%headers, body => $body);
}

sub _ua {
    my ($self) = @_;
    # On a Hyperman worker the agent must share the worker's loop, or the
    # send future sits on Fetch's standalone loop - which only a blocking
    # ->get ever pumps - and "a future nobody waits on" becomes a request
    # nobody ever sends. That was the fleet's whole reporting channel:
    # violations, coverage and usage all shipped into a loop nothing
    # drove. Off a worker, Hyperman->loop answers undef and the
    # standalone agent's blocking behaviour is unchanged.
    my $ua = eval {
        require Fetch;
        my $loop = eval { Hyperman->loop };
        Fetch->new(timeout => $self->{timeout},
                   ($loop ? (loop => $loop) : ()));
    };
    return $ua;
}

sub stats {
    my ($self) = @_;
    return {
        %{ $self->{counters} },
        backoff_until => $self->{backoff} || 0,
        inflight      => $self->{inflight},
    };
}

1;

__END__

=head1 NAME

Maat::Shipper - get violations to the control plane without waiting for it

=head1 SYNOPSIS

    my $shipper = Maat::Shipper->new(
        url   => 'https://openapi-proxy.com/v1/violations',
        token => $token,
        spool => Maat::Spool->new(dir => '/var/spool/maat'),
    );

    $shipper->tick;      # from the request path; usually returns at once

=head1 DESCRIPTION

Everything here runs on the worker's own loop, between requests: a
flushed window goes onto the L<Maat::Spool>, and the spool is drained by
HTTP when there is something to drain and the backoff allows it. The
request path calls C<tick>, which in the overwhelmingly common case
reads the clock and returns.

Nothing ever waits for the control plane. The send is a future; its
failure leaves the batch on the spool for next time and moves a counter.
A control plane outage should be invisible from the customer's side
except as a delay in their dashboard.

=head2 When the control plane is down

Nothing is retried in a tight loop - the backoff doubles from one second
to a five-minute ceiling. Nothing accumulates in memory - the spool is
on disk and bounded. And no request is affected.

The ceiling exists because a control plane that has been unreachable for
an hour is either being deployed or is broken, and either way the useful
behaviour is to keep trying every few minutes rather than to give up or
to hammer it.

=head2 gzip

Violations are extremely repetitive - the same operation, pointer and
keyword over and over - so a batch compresses by an order of magnitude,
and the customer is paying for that bandwidth. Bodies under 512 bytes
are sent as they are: the CPU is not worth it.

=head1 METHODS

=head2 new(url => ..., token => ..., spool => ..., ua => ..., interval => 5, batch => 10, gzip => 1, timeout => 10, coverage => sub {...}, coverage_interval => 60, usage => sub {...}, usage_done => sub {...})

C<ua> is anything with a C<post> returning a future - a L<Fetch> by
default.

C<coverage> is a callback returning the hash from
L<Maat::Gateway/coverage>, or undef for a gateway that does not report
it. It is called only when a snapshot is due, so building the hash costs
nothing on the drains in between.

C<usage> is a callback returning C<< [ { hour, requests, gateway }, ... ] >>
- the hours whose totals have moved since the control plane last took
them - or undef. C<usage_done> is called with exactly that list once the
control plane has accepted it. See L</Metering>.

=head2 Coverage

Coverage rides the violation channel - same token, same retry story -
but on its own, much slower clock, because it is a snapshot rather than
an accumulation.

It ships even when there is nothing on the spool, which is the whole
point of it: a customer with no violations is either covered and
conforming or not being looked at, and an empty drift page renders those
two opposite situations identically.

When coverage is included the body is C<< { records => [...], coverage
=> {...} } >> rather than a bare array. The clock only advances on an
accepted request, so a snapshot that did not land is re-sent on the next
drain rather than waiting out a whole interval for its replacement.

=head2 Metering

Usage rides the same channel for the same reasons, and on no clock at
all: L<Maat::Gateway/usage> returns only the hours whose totals have
moved, so a busy tenant meters on every drain and an idle one contributes
nothing. It may also CAUSE a drain - a proxy can serve a million
conforming requests, produce no violations, and still have a bill.

The number for an hour is that reporter's running total, never a delta,
because the control plane replaces rather than adds: a retried batch
writes the same number again, which is what makes a retry safe on a
billing path. Every worker of every instance meters only its own share
and says who it is, and the control plane keys the row by that and sums.

C<usage_done> is the commit, and it is a callback rather than a
timestamp because the source has to know precisely which hours landed.
An hour dropped here is an hour nobody is billed for, so it is only
marked once the control plane has taken it.

=head2 tick($now?)

Drain if the interval has elapsed. Cheap enough to call per request.

=head2 drain($now?)

Drain now, if there is anything to drain, nothing is in flight and the
backoff allows it. Returns the number of batches attempted.

=head2 enabled / backoff / counters / spool / stats

C<stats> is C<shipped>, C<records>, C<ship_failed>, C<bytes_sent>,
C<gzip_saved>, C<backoff_until> and C<inflight>, for C</metrics>.

=cut
