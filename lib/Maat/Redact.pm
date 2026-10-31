package Maat::Redact;

use 5.010;
use strict;
use warnings;

our $VERSION = '0.03';

# What may leave the process.
#
# A violation record carries at most one example value, and that value
# came out of a customer's payload. This decides whether it may travel at
# all, and what is left of it if it does.
#
# The rule everything here follows: B<when in doubt, drop it>. A missing
# example costs someone one extra minute working out which field was
# wrong. An example that should not have left costs them a disclosure
# notice. Those are not comparable, so the code does not treat them as a
# balanced trade - every branch that cannot prove the value is safe
# returns undef.
#
# Two independent tests, and a value has to pass both:
#
#   the schema   the document itself says this is a secret -
#                `writeOnly: true` or `format: password`
#   the name     the field is called something people call secrets.
#                This exists because the first test only works when the
#                document is honest, and a document that forgot to mark
#                its password field is exactly the document whose
#                password field we must not ship.

# Names that are secret often enough that the default is to assume they
# are. Matched case-insensitively against the last pointer segment, as a
# substring, so `customer_password` and `apiKey` are both caught.
my @DEFAULT_NAMES = qw(
    password passwd pwd secret token auth credential
    api_key apikey key_id private cookie session
    ssn social_security card cardnumber pan cvv cvc iban sort_code
    authorization bearer signature otp pin
);

my $MAX_STRING = 200;      # the plan's truncation point

sub new {
    my ($class, %o) = @_;
    my @names = @DEFAULT_NAMES;
    push @names, map { lc } @{ $o{names} || [] };
    return bless {
        mode     => defined $o{mode} ? $o{mode} : 'default',  # default|strict
        names    => \@names,
        max      => defined $o{max} ? $o{max} : $MAX_STRING,
        spec     => $o{spec},        # the OpenAPI document, for the schema test
    }, $class;
}

sub mode { $_[0]{mode} }

# The example value for a violation, or undef when there must not be one.
#
#   $pointer         the JSON pointer the error names (uncollapsed)
#   $value           the value at that pointer, already extracted
#   $schema_location the error's schemaLocation, when there is one
sub example {
    my ($self, $pointer, $value, $schema_location) = @_;

    return undef unless defined $value;
    return undef if ref $value eq 'CODE' || ref $value eq 'GLOB';

    # `redact: strict` keeps no example at all. For an operator who has
    # decided that no payload-derived byte leaves their estate, this is
    # the setting that means it, rather than a promise about our
    # cleverness in the branches below.
    return undef if $self->{mode} eq 'strict';

    return undef if $self->name_is_secret($pointer);
    return undef if $self->schema_is_secret($schema_location);

    return $self->_shape($value);
}

# Does the field's own name say secret? The last pointer segment, because
# that is the field; `/user/password/hash` is about `hash`, but anything
# under a password is a password, so every segment is checked.
sub name_is_secret {
    my ($self, $pointer) = @_;
    return 0 unless defined $pointer && length $pointer;
    for my $seg (split m{/}, $pointer) {
        next unless length $seg;
        my $lc = lc $seg;
        $lc =~ s/[^a-z0-9]//g;          # apiKey, api-key, api_key alike
        for my $n (@{ $self->{names} }) {
            (my $bare = $n) =~ s/[^a-z0-9]//g;
            return 1 if index($lc, $bare) >= 0;
        }
    }
    return 0;
}

# Does the document say so? `writeOnly: true` means the client sends it
# and the server never returns it - a password, a token - and
# `format: password` says it outright.
#
# schemaLocation points into the compiled schema, where Open::API has
# rewritten `#/components/schemas/X` to `#/$defs/X`; mapping it back is
# that substitution and a walk.
sub schema_is_secret {
    my ($self, $location) = @_;
    my $schema = $self->schema_at($location) or return 0;
    return 0 unless ref $schema eq 'HASH';
    return 1 if $schema->{writeOnly};
    return 1 if defined $schema->{format} && $schema->{format} eq 'password';
    return 0;
}

# The document's subschema for a schemaLocation, or undef when it cannot
# be resolved - which is itself a reason to drop the value, since an
# unresolvable location means we cannot say the field is safe.
sub schema_at {
    my ($self, $location) = @_;
    my $spec = $self->{spec};
    return undef unless $spec && defined $location && length $location;

    my @seg = grep { length } split m{/}, $location;
    return undef unless @seg;

    # /$defs/Name/... is /components/schemas/Name/...
    if ($seg[0] eq '$defs') {
        shift @seg;
        unshift @seg, 'components', 'schemas';
    }

    my $node = $spec;
    for my $s (@seg) {
        $s =~ s/~1/\//g;    # JSON pointer escapes
        $s =~ s/~0/~/g;
        if (ref $node eq 'HASH')     { $node = $node->{$s} }
        elsif (ref $node eq 'ARRAY') { return undef unless $s =~ /\A\d+\z/;
                                       $node = $node->[$s] }
        else                         { return undef }
        return undef unless defined $node;
    }
    return $node;
}

# What is left of a value that is allowed to travel: a string truncated,
# a number as it is, a structure described rather than reproduced.
#
# A hash or an array is never sent whole. The useful thing about a
# structural violation is its shape, and the shape is what this keeps -
# a nested object could hold anything, including the secret two levels
# down that the name test never saw.
sub _shape {
    my ($self, $value) = @_;

    if (ref $value eq 'HASH') {
        return sprintf '{object with %d key%s}',
               scalar keys %$value, (keys %$value) == 1 ? '' : 's';
    }
    if (ref $value eq 'ARRAY') {
        return sprintf '[array of %d]', scalar @$value;
    }
    if (ref $value eq 'SCALAR') {            # JSON booleans decode to these
        return $$value ? 'true' : 'false';
    }
    return 'null' if !defined $value;

    my $s = "$value";
    return $s if length $s <= $self->{max};
    return substr($s, 0, $self->{max}) . '...';
}

# The value at a JSON pointer inside a decoded payload, or undef. Used
# only when a fingerprint is new in a window, so it is allowed to walk.
sub value_at {
    my ($class, $payload, $pointer) = @_;
    return undef unless defined $payload;
    return $payload unless defined $pointer && length $pointer && $pointer ne '/';

    my $node = $payload;
    for my $s (grep { length } split m{/}, $pointer) {
        $s =~ s/~1/\//g;
        $s =~ s/~0/~/g;
        if (ref $node eq 'HASH')     { $node = $node->{$s} }
        elsif (ref $node eq 'ARRAY') { return undef unless $s =~ /\A\d+\z/;
                                       $node = $node->[$s] }
        else                         { return undef }
        return undef unless defined $node;
    }
    return $node;
}

# The JSON type of a value, for `got_type` - which is safe to report
# whatever the field is, because a type is not a value.
sub type_of {
    my ($class, $value) = @_;
    return 'null'    if !defined $value;
    return 'object'  if ref $value eq 'HASH';
    return 'array'   if ref $value eq 'ARRAY';
    return 'boolean' if ref $value eq 'SCALAR' || ref $value eq 'JSON::PP::Boolean';
    return 'number'  if $value =~ /\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?\z/;
    return 'string';
}

1;

__END__

=head1 NAME

Maat::Redact - what may leave the process

=head1 SYNOPSIS

    my $r = Maat::Redact->new(mode => 'default', spec => $api->spec,
                              names => [ 'account_ref' ]);

    my $example = $r->example('/user/password', 'hunter2',
                              '/$defs/User/properties/password/type');
    # undef - both tests say secret

=head1 DESCRIPTION

A violation record carries at most one example value, and that value
came out of a customer's payload. This decides whether it may travel and
what is left of it.

Everything here follows one rule: B<when in doubt, drop it>. A missing
example costs someone a minute working out which field was wrong; an
example that should not have left costs them a disclosure notice. Those
are not comparable, so no branch here treats them as a balanced trade -
anything that cannot prove a value safe returns undef.

=head2 The two tests

B<The schema.> The document says so: C<writeOnly: true> (the client
sends it, the server never returns it) or C<format: password>.

B<The name.> The field is called something people call secrets -
C<password>, C<token>, C<api_key>, C<cvv> and their spellings, matched
case-insensitively and with punctuation removed, against every segment
of the pointer.

The second exists because the first only works when the document is
honest, and a document that forgot to mark its password field is exactly
the document whose password field must not be shipped.

=head2 What is left of a value

A string is truncated at 200 bytes. A number travels as it is. A hash or
an array is B<never sent whole> - it becomes C<{object with 3 keys}> or
C<[array of 500]>, because the useful thing about a structural violation
is its shape, and a nested object can hold the secret two levels down
that the name test never saw.

=head2 strict

C<< mode => 'strict' >> keeps no example at all, for an operator who has
decided that no payload-derived byte leaves their estate. It is a
setting rather than a promise about the cleverness of the branches above.

=head1 METHODS

=head2 new(mode => ..., names => \@extra, spec => $document, max => $bytes)

=head2 example($pointer, $value, $schema_location)

The example to record, or undef when there must not be one.

=head2 name_is_secret($pointer) / schema_is_secret($location) / schema_at($location)

The individual tests, exposed because a customer asking "why is there no
example on this record" deserves to be able to find out.

=head2 value_at($payload, $pointer) / type_of($value)

Class methods: the value at a JSON pointer in a decoded payload, and the
JSON type name of a value. A type is not a value, so C<type_of> is safe
to report for any field.

=cut
