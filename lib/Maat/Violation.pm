package Maat::Violation;

use 5.010;
use strict;
use warnings;
use Time::HiRes ();
use Maat::Redact ();

our $VERSION = '0.06';

# What happens to a request that did not match its contract.
#
# The pressure this is written against is not correctness, it is volume.
# One upstream deploy that changes a field's type turns every request
# into a violation, and a gateway that emits one record per violation
# under that load is a gateway that has become the outage. So violations
# are aggregated in the process, keyed by what makes two of them the same
# problem, and one record per key per window leaves. A million identical
# violations become six records a minute.
#
# The key - the fingerprint - is
#
#     (spec_version, operation_id, status, pointer, keyword)
#
# with array indices in the pointer collapsed to `*`, because
# /items/3/sku and /items/4/sku are one bug and 500 of them must not be
# 500 fingerprints. NO VALUE FROM THE PAYLOAD EVER ENTERS A KEY: keys
# travel to the control plane, are stored, indexed and shown in a UI, and
# nothing derived from a customer's data may end up there. An example
# value is kept on the record instead - one, redacted, and only for the
# first occurrence in a window. See Maat::Redact.
#
# Two rules that outrank everything else here:
#
#   1. Recording may not fail a request. Every path is bounded and
#      non-blocking; the caller wraps it besides.
#   2. Nothing here may grow without bound. The window's table is
#      capped, and past the cap the fingerprint is counted as dropped
#      rather than remembered.

my $WINDOW      = 10;      # seconds
my $MAX_KEYS    = 1000;    # distinct fingerprints held in one window
my $MAX_RECORDS = 1000;    # the in-process ring, when there is no sink

# The window runs on the fractional clock. `window` is allowed to be
# sub-second (the load gate closes windows every 50ms to put the flush
# inside what it times), and integer time() cannot see a boundary closer
# than a second away.
sub now { Time::HiRes::time() }

sub new {
    my ($class, %o) = @_;
    my $now = now();
    return bless {
        sink        => $o{sink},          # where a flushed window goes
        max         => $o{max}         || $MAX_RECORDS,
        max_keys    => $o{max_keys}    || $MAX_KEYS,
        window      => defined $o{window} ? $o{window} : $WINDOW,
        redact      => $o{redact} || Maat::Redact->new(spec => $o{spec}),

        # stamped onto every record: which contract, which gateway, which
        # environment. The control plane groups by these before it groups
        # by anything else - "is this all one box" is the first question.
        spec_version => defined $o{spec_version} ? $o{spec_version} : undef,
        gateway_id   => defined $o{gateway_id} ? $o{gateway_id}
                                               : _default_gateway_id(),
        environment  => $o{environment},

        open_at  => $now,                 # the current window opened here
        close_at => $now + (defined $o{window} ? $o{window} : $WINDOW),
        agg      => {},                   # fingerprint -> the aggregate
        nkeys    => 0,

        # The reality view (phase 10): a per-operation tally of RESPONSE
        # drift that outlives the window, so "this operation's responses
        # have been violating their schema" can be answered by the docs
        # portal's badge. Keyed by operation id alone - bounded by the
        # spec's operation count, never by anything from a payload - and
        # NOT cleared on flush, because the window is the shipping unit and
        # this is the standing state a reader asks about. The control plane
        # is fed the same per-window records, so the badge and the control
        # plane's drift view reconcile by construction.
        drift    => {},                   # operation_id -> { count, ... }

        records  => [],
        counters => {
            request      => 0,   # requests seen
            # Delivered tool results, a SUBSET of `request` rather than
            # an addition: a tool call re-enters the gateway and is
            # counted above like anything else. Seeded here like every
            # other counter, because the first increment of a key that
            # is not here reads an undef.
            mcp          => 0,
            conforming   => 0,   # matched and validated
            violation    => 0,   # matched and failed validation
            observed     => 0,   # observe-only drift (undeclared/deprecated)
            undeclared   => 0,   # no operation for the path
            wrong_method => 0,   # path exists, method does not (405 shape)
            rejected     => 0,   # answered by us, never forwarded
            skipped      => 0,   # body too large to buffer, etc
            failed       => 0,   # our own machinery failed; request went on
            dropped      => 0,   # records the ring threw away
            response_violation => 0,

            # the pipeline's own health, phase 3
            occurrences  => 0,   # individual errors seen, before aggregation
            aggregated   => 0,   # records emitted after aggregation
            keys_dropped => 0,   # fingerprints a full window could not hold
            windows      => 0,   # windows closed
        },
    }, $class;
}

sub count    { my ($self, $k, $n) = @_;
               $self->{counters}{$k} += defined $n ? $n : 1 }
sub counters { $_[0]{counters} }
sub records  { $_[0]{records} }
sub redact   { $_[0]{redact} }
sub window   { $_[0]{window} }

sub spec_version { $_[0]{spec_version} }
sub gateway_id   { $_[0]{gateway_id} }

# The standing per-operation reality view: which operations' responses
# have drifted from their schema, and how much. The docs portal's badge
# reads exactly this, so the badge equals what the pipeline holds by
# construction (phase 10, gate 3). Keyed by operation id; nothing from a
# payload is in it. Not cleared on flush - the window is the shipping
# unit, this is the standing state.
sub drift     { $_[0]{drift} }
sub in_drift  { my ($s, $op) = @_; defined $op && $s->{drift}{$op} ? 1 : 0 }

# How many fingerprints the open window is holding. The control plane
# asks; so does anyone wondering whether the cap is being hit.
sub open_keys { $_[0]{nkeys} }

# ---- the fingerprint --------------------------------------------------------

# /items/3/sku -> /items/*/sku. A 500-element array is one bug, not 500.
sub collapse_pointer {
    my ($class, $pointer) = @_;
    return '' unless defined $pointer;
    $pointer =~ s{/\d+(?=/|\z)}{/*}g;
    return $pointer;
}

# A request path with its value-like segments collapsed to `*`. An
# undeclared endpoint is reported by its SHAPE, never its values: the same
# no-payload-in-a-key rule the fingerprint lives by, applied to the one
# place a value hides in plain sight - the path. `/users/42/orders/9` and
# `/users/7/orders/3` are one undocumented shape, `GET /users/*/orders/*`,
# and `/users/alice@example.com` must not travel as a key at all.
#
# A segment is kept only when it reads as a static route name: starts with
# a letter, no digit, nothing but word characters and dashes, not too long.
# Anything numeric, long, or carrying `.@%~:` (an id, a uuid, an email, an
# encoded value) becomes `*`. `v1`/`v2` version segments are kept by name,
# since an API version is structure, not a value.
sub template_path {
    my ($class, $path) = @_;
    return '/' unless defined $path && length $path;
    $path =~ s/[?#].*//s;                  # a query/fragment is never a path
    my @seg = split m{/}, $path, -1;
    for my $s (@seg) {
        next if $s eq '';                  # keep leading/trailing empties
        $s = '*' unless $class->_static_segment($s);
    }
    my $out = join '/', @seg;
    return length $out ? $out : '/';
}

sub _static_segment {
    my ($class, $s) = @_;
    return 1 if $s =~ /^v\d+\z/;            # an API version: v1, v2beta stays
    return 0 if length $s > 32;             # long -> opaque
    return 0 if $s =~ /[^A-Za-z0-9_-]/;     # dot/@/%/~/: etc -> a value
    return 0 if $s =~ /\d/;                 # any digit -> an id
    return 0 if $s !~ /^[A-Za-z]/;          # must read as a name
    return 1;
}

# Where the failure was, as one string that identifies it inside the
# operation.
#
# A body error already says: instanceLocation is a JSON pointer into the
# payload. A parameter error does not - Open::API reports it with an
# empty instanceLocation and the parameter in `name`, because there is
# no document for it to point into. Left as it comes, every query
# parameter failing the same keyword on the same operation would share a
# fingerprint, and `limit` being too large would be indistinguishable
# from `offset` being too large. So a parameter's location is written
# where it lives: `query/limit`.
sub pointer_for {
    my ($class, $e) = @_;
    my $loc = $e->{instanceLocation};
    return $class->collapse_pointer($loc) if defined $loc && length $loc;
    return join '/', grep { defined && length } $e->{in}, $e->{name};
}

# The key two violations must share to be the same problem. Joined with a
# character that cannot appear in an operationId or a pointer, so the
# parts cannot run together and forge a collision.
sub fingerprint {
    my ($class, %f) = @_;
    return join "\x1f", map { defined $_ ? $_ : '' }
        $f{spec_version}, $f{operation}, $f{status}, $f{pointer}, $f{keyword};
}

# ---- recording --------------------------------------------------------------

# Called on the request path, only for a request or response that has
# already failed. Cheap in the common case, which is the second and
# subsequent time a fingerprint is seen in a window: a hash lookup and
# two increments. The expensive things - extracting an example, walking
# the schema - happen once per fingerprint per window, on the first
# occurrence, and never again inside it.
sub record {
    my ($self, %r) = @_;

    # An observation is drift the contract permits - an undeclared query
    # param, a field not in the schema, a deprecated field still in use, a
    # path with no operation. It is aggregated, shipped and shown exactly
    # like a validation failure, but it is NOT one: it must not inflate the
    # violation counter a rate is drawn from, nor mark the operation's
    # standing response-drift tally. Everything else below is identical.
    my $observe = $r{observe} ? 1 : 0;
    $self->{counters}{ $observe ? 'observed' : 'violation' }++;

    my $now    = defined $r{now} ? $r{now} : now();
    my $errors = $r{errors} || [];
    my $kind   = defined $r{kind} ? $r{kind} : 'request';

    $self->flush($now) if $now >= $self->{close_at};

    my $spec_version = defined $r{spec_version} ? $r{spec_version}
                                                : $self->{spec_version};
    my @out;
    for my $e (@$errors) {
        $self->{counters}{occurrences}++;

        my $pointer = __PACKAGE__->pointer_for($e);
        my $fp = __PACKAGE__->fingerprint(
            spec_version => $spec_version,
            operation    => $r{operation},
            status       => $r{status},
            pointer      => $pointer,
            keyword      => $e->{keyword},
        );

        my $a = $self->{agg}{$fp};
        if ($a) {
            $a->{count}++;
            $a->{last_seen} = $now;
            next;
        }

        # A new fingerprint. Past the cap the window stops remembering
        # and starts counting: a bound that is enforced by dropping is a
        # bound, and one enforced by growing is a wish.
        if ($self->{nkeys} >= $self->{max_keys}) {
            $self->{counters}{keys_dropped}++;
            next;
        }

        my $value = exists $r{payload}
            ? Maat::Redact->value_at($r{payload}, $e->{instanceLocation})
            : undef;

        $a = $self->{agg}{$fp} = {
            fingerprint  => $fp,
            first_seen   => $now,
            last_seen    => $now,
            count        => 1,
            sample_count => 0,          # requests, filled in below
            operation_id => $r{operation},
            method       => $r{method},
            path         => $r{path},
            kind         => $kind,
            # The tool an agent called, when the request was a tool call
            # rather than a customer's own client. Attribution only: it
            # is deliberately NOT in the fingerprint, because the same
            # drift reached through two tools is one drift in the
            # upstream, not two.
            tool         => $r{tool},
            status       => $r{status},
            pointer      => $pointer,
            keyword      => $e->{keyword},
            in           => $e->{in},
            name         => $e->{name},
            message      => $e->{message},
            expected     => $self->_expected($e),
            got_type     => (exists $r{payload}
                                ? Maat::Redact->type_of($value) : undef),
            request_id   => $r{request_id},
            spec_version => $spec_version,
            gateway_id   => $self->{gateway_id},
            environment  => $self->{environment},
            # Which window this record is. The control plane needs it to
            # be idempotent: a batch that is shipped, accepted, and then
            # shipped again because the acknowledgement was lost must
            # not count twice. (gateway_id, fingerprint, window) is that
            # record's identity, and it is stable because the record is
            # built once, here, and the spool replays those exact bytes.
            window       => $self->{open_at},
        };
        my $example = $self->{redact}->example(
            $e->{instanceLocation}, $value, $e->{schemaLocation});
        $a->{example} = $example if defined $example;

        $self->{nkeys}++;
        push @out, $a;
    }

    # One request contributing 500 errors to one fingerprint is one
    # sample of the problem, not 500. Counted per fingerprint touched,
    # which is what makes `count: 500, sample_count: 1` readable as
    # "one request, five hundred bad elements".
    my %touched;
    for my $e (@$errors) {
        my $fp = __PACKAGE__->fingerprint(
            spec_version => $spec_version,
            operation    => $r{operation},
            status       => $r{status},
            pointer      => __PACKAGE__->pointer_for($e),
            keyword      => $e->{keyword},
        );
        next if $touched{$fp}++;
        $self->{agg}{$fp}{sample_count}++ if $self->{agg}{$fp};
    }

    # The standing reality tally. A response that drifted from its schema
    # marks its operation, and the mark persists past the window flush so
    # the portal's badge can say "this operation has been violating".
    # Bounded by the operation count; nothing from a payload enters it.
    if (!$observe && $kind eq 'response' && @$errors
        && defined $r{operation} && length $r{operation}) {
        my $d = $self->{drift}{ $r{operation} } ||= {
            operation_id => $r{operation},
            count        => 0,
            sample_count => 0,
            first_seen   => $now,
            statuses     => {},
        };
        $d->{count}        += scalar @$errors;
        $d->{sample_count} += 1;
        $d->{last_seen}     = $now;
        $d->{statuses}{ defined $r{status} ? $r{status} : '' }++;
    }

    return \@out;
}

# What the schema asked for, when it can be said in one word. Safe to
# report whatever the field holds: it comes from the document, not the
# payload.
sub _expected {
    my ($self, $e) = @_;
    my $loc = $e->{schemaLocation};
    return undef unless defined $loc;

    # The last segment of a schemaLocation is the keyword that failed, so
    # the schema itself is one level up: /$defs/Pet/properties/id/type
    # -> /$defs/Pet/properties/id, whose `type` is what was expected.
    my $parent = $loc;
    $parent =~ s{/[^/]+\z}{};
    my $schema = $self->{redact}->schema_at($parent);
    return undef unless ref $schema eq 'HASH';

    my $kw = $e->{keyword};
    return undef unless defined $kw;
    my $v = $schema->{$kw};
    return undef unless defined $v;
    return join ', ', @$v if ref $v eq 'ARRAY';
    return undef if ref $v;
    return "$v";
}

# ---- the window -------------------------------------------------------------

# Close the open window: every aggregate leaves as one record, and the
# table is emptied. Called from the request path when the clock has
# passed the window's end, and by the shipper on its timer so a quiet
# gateway still reports what it saw.
sub flush {
    my ($self, $now) = @_;
    $now = now() unless defined $now;

    my @out = values %{ $self->{agg} };
    $self->{agg}      = {};
    $self->{nkeys}    = 0;
    $self->{open_at}  = $now;
    $self->{close_at} = $now + $self->{window};
    $self->{counters}{windows}++;

    return [] unless @out;
    $self->{counters}{aggregated} += @out;

    # Biggest first: if anything downstream is ever forced to drop, the
    # thing it keeps should be the problem that happened most.
    @out = sort { $b->{count} <=> $a->{count} } @out;

    if ($self->{sink}) {
        $self->{sink}->(\@out);
    }
    else {
        push @{ $self->{records} }, @out;
        while (@{ $self->{records} } > $self->{max}) {
            shift @{ $self->{records} };
            $self->{counters}{dropped}++;
        }
    }
    return \@out;
}

# Is the open window due to close? The shipper asks on its own timer;
# the request path asks implicitly inside record().
sub due { my ($self, $now) = @_;
          (defined $now ? $now : now()) >= $self->{close_at} ? 1 : 0 }

sub _default_gateway_id {
    require Sys::Hostname;
    my $host = eval { Sys::Hostname::hostname() } || 'unknown';
    return "$host/$$";
}

1;

__END__

=head1 NAME

Maat::Violation - aggregate what did not match the contract

=head1 SYNOPSIS

    my $v = Maat::Violation->new(
        spec_version => $api->spec->{info}{version},
        environment  => 'production',
        window       => 10,
        sink         => sub { my ($records) = @_; ... },
    );

    $v->record(
        request_id => $rid,
        operation  => 'createPet',
        status     => 400,
        errors     => $errors,        # Open::API's own error list
        payload    => $decoded,       # optional, for the example value
    );

=head1 DESCRIPTION

The pressure this is written against is not correctness, it is volume.
One upstream deploy that changes a field's type turns every request into
a violation, and a gateway that emits a record per violation under that
load has become the outage it was installed to detect. So violations are
aggregated in the process and one record per fingerprint per window
leaves: a million identical violations become six records a minute.

=head2 The fingerprint

    (spec_version, operation_id, status, pointer, keyword)

C<pointer> has array indices collapsed to C<*> - C</items/3/sku> and
C</items/4/sku> are one bug, and five hundred of them must not be five
hundred fingerprints.

B<No value from the payload ever enters a key.> Keys travel to the
control plane, are stored, indexed and displayed; nothing derived from a
customer's data may end up there. An example value is kept on the record
instead - one, redacted, and only for the first occurrence in a window.
See L<Maat::Redact>.

=head2 The record's identity

    (gateway_id, fingerprint, window)

C<window> is the moment the window that produced the record opened. It
is on the record so the control plane can be idempotent: the spool
replays a batch whenever the acknowledgement did not arrive, and it
replays the exact bytes it built here, so a receiver that has already
counted that triple can recognise it and count nothing.

Without it the pipeline's own retry - the thing that makes it reliable -
would be indistinguishable from the traffic getting worse.

=head2 count and sample_count

C<count> is how many individual errors were aggregated; C<sample_count>
is how many requests contributed them. One request with an array of 500
bad elements is C<< count => 500, sample_count => 1 >> - which reads as
what it is, rather than as five hundred separate problems.

=head2 What is bounded

The window's table holds at most C<max_keys> distinct fingerprints
(default 1000). Past that, a new fingerprint is counted in
C<keys_dropped> rather than remembered: a bound enforced by dropping is
a bound, and one enforced by growing is a wish.

Without a C<sink>, flushed records go to an in-process ring of C<max>
(default 1000), which drops oldest and counts the drops.

=head2 Cost

The common case is the second and subsequent occurrence of a fingerprint
inside a window: a hash lookup and two increments. Extracting an example
value and walking the schema for C<expected> happen once per fingerprint
per window and never again inside it.

=head1 METHODS

=head2 new(...)

C<sink>, C<window> (seconds), C<max_keys>, C<max>, C<redact> (a
L<Maat::Redact>), C<spec>, C<spec_version>, C<gateway_id>,
C<environment>.

=head2 record(%fields)

C<request_id>, C<operation>, C<method>, C<path>, C<kind>
(C<request>|C<response>), C<status>, C<errors>, and optionally
C<payload> (decoded) for the example value. Returns the aggregates that
were newly created by this call.

=head2 flush($now?) / due($now?)

Close the open window, emitting one record per fingerprint to the sink;
and whether it is time to.

=head2 drift / in_drift($operation_id)

The standing per-operation reality view: C<drift> is a hashref keyed by
operation id, each value C<< { operation_id, count, sample_count,
first_seen, last_seen, statuses } >>, recording every B<response> that
drifted from its schema. Unlike the window aggregate it is B<not> cleared
on flush - the window is the shipping unit, and this is the standing
state a reader of the docs portal asks about. Bounded by the spec's
operation count; nothing derived from a payload is in it.

L<Maat::Portal>'s reality badge reads exactly this, so the badge equals
what the pipeline holds by construction (phase 10, gate 3), and because
the same per-window records are shipped to the control plane the badge
also reconciles with the control plane's drift view. C<in_drift> is the
boolean a badge needs.

=head2 counters / records / redact / window / open_keys / spec_version / gateway_id

=head2 collapse_pointer($pointer) / fingerprint(%parts)

Class methods, exposed because the control plane has to compute the same
fingerprint from the other end.

=cut
