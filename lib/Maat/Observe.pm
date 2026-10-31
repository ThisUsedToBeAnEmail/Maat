package Maat::Observe;

use 5.010;
use strict;
use warnings;

use Maat::Violation ();

our $VERSION = '0.01';

# Observe-only drift: what a request or response the contract PERMITS still
# tells you. OpenAPI does not reject an undeclared query parameter, a
# response field the schema never mentions, a deprecated field still in
# use, or a path with no operation at all - so validation is silent on all
# of it, and yet each is drift a team wants to see. This records them
# through Maat::Violation exactly as a validation error is recorded, with
# distinct keywords, and with `observe => 1` so none of it inflates the
# violation counter or the operation's standing response-drift tally.
#
# Two rules carry over from the pipeline and are enforced here:
#
#   1. Nothing derived from a payload VALUE may enter a fingerprint key.
#      Parameter and property NAMES are identifiers (like the schema
#      property names already in a pointer) and are allowed; a request
#      PATH carries values and is templated first - see
#      Maat::Violation::template_path.
#   2. Recording may not fail a request. The caller wraps every entry
#      point in an eval with the watchdog; this stays cheap and total.

# ---- undeclared endpoints and wrong-method (no operation) -------------------

# A path with no operation, forwarded to the upstream: the API surface the
# contract does not cover. Reported by SHAPE (templated path + method),
# never by the raw path, so `/users/42` and `/users/7` are one row.
sub record_undeclared {
    my (%a) = @_;
    my $v = $a{v} or return;
    my $method = _method($a{method});
    my $tpath  = Maat::Violation->template_path($a{path});
    $v->record(
        observe      => 1,
        operation    => undef,
        status       => 0,
        method       => $method,
        path         => $tpath,
        kind         => 'undeclared',
        spec_version => $a{spec_version},
        errors       => [ {
            keyword          => ($a{keyword} || 'undeclared-endpoint'),
            in               => 'path',
            # method rides in the pointer so GET and POST to the same
            # undocumented path are two rows, not one.
            instanceLocation => "$method $tpath",
        } ],
    );
    return;
}

# ---- undeclared and deprecated request parameters (matched operation) ------

sub request_params {
    my (%a) = @_;
    my ($v, $api, $op, $env) = @a{qw(v api op env)};
    return unless $v && $api && defined $op && ref $env eq 'HASH';

    my $info = eval { $api->operation_info($op) } or return;
    my $spec = eval { $api->spec }                or return;
    my $declared = _declared_params($spec, $info);

    my @errors;

    # Query: a name the contract never declared is undeclared drift; a
    # declared-but-deprecated name still arriving is deprecation drift.
    my %q = _query_names($env->{QUERY_STRING});
    for my $name (sort keys %q) {
        if (!exists $declared->{query}{$name}) {
            push @errors, {
                in => 'query', name => $name,
                keyword => 'undeclared-parameter',
                message => 'query parameter not declared in the contract',
            };
        }
        elsif ($declared->{query}{$name}) {
            push @errors, {
                in => 'query', name => $name,
                keyword => 'deprecated-usage',
                message => 'a deprecated query parameter is still in use',
            };
        }
    }

    # Headers: only DEPRECATED declared ones - "undeclared header" is
    # meaningless, since every request carries headers no contract mentions.
    for my $name (sort keys %{ $declared->{header} || {} }) {
        next unless $declared->{header}{$name};
        my $h = 'HTTP_' . uc $name;
        $h =~ tr/-/_/;
        next unless exists $env->{$h};
        push @errors, {
            in => 'header', name => lc $name,
            keyword => 'deprecated-usage',
            message => 'a deprecated header parameter is still in use',
        };
    }

    return unless @errors;
    $v->record(
        observe   => 1,
        operation => ($info->{operationId} // $op),
        status    => 0,
        method    => _method($env->{REQUEST_METHOD}),
        path      => Maat::Violation->template_path($env->{PATH_INFO}),
        kind      => 'request',
        errors    => \@errors,
    );
    return;
}

# ---- helpers ----------------------------------------------------------------

sub _method {
    my ($m) = @_;
    $m = defined $m ? uc "$m" : 'GET';
    $m =~ s/[^A-Z]//g;
    $m = substr $m, 0, 12;
    return length $m ? $m : 'GET';
}

# The query string's parameter NAMES (decoded), as a set. Values are never
# looked at - only whether a name is present.
sub _query_names {
    my ($qs) = @_;
    my %n;
    return %n unless defined $qs && length $qs;
    for my $pair (split /[&;]/, $qs) {
        next unless length $pair;
        my ($k) = split /=/, $pair, 2;
        next unless defined $k && length $k;
        $k =~ tr/+/ /;
        $k =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
        $n{$k}++;
    }
    return %n;
}

# { in => { name => deprecated(0|1) } }. Path-item parameters first,
# operation parameters second, so an operation-level override wins - the
# order OpenAPI merges them in.
sub _declared_params {
    my ($spec, $info) = @_;
    my %d;
    my $pi = (ref $spec eq 'HASH' ? $spec->{paths} : {}) || {};
    $pi = $pi->{ $info->{path} // '' };
    return \%d unless ref $pi eq 'HASH';

    my $method = lc($info->{method} // '');
    my $op     = ref $pi->{$method} eq 'HASH' ? $pi->{$method} : {};
    for my $p (@{ _aref($pi->{parameters}) }, @{ _aref($op->{parameters}) }) {
        $p = _resolve($spec, $p);
        next unless ref $p eq 'HASH' && defined $p->{name} && defined $p->{in};
        $d{ $p->{in} }{ $p->{name} } = $p->{deprecated} ? 1 : 0;
    }
    return \%d;
}

sub _aref { ref $_[0] eq 'ARRAY' ? $_[0] : [] }

# ---- undeclared and deprecated response-body fields ------------------------

# A decoded response body walked against the schema its status declares:
# object keys the schema never named (undeclared-property) and declared keys
# whose schema is `deprecated` (deprecated-usage). Runs only on the sampled
# response path (Maat::Gateway::_check_response), and only on a JSON body it
# already holds decoded - never a second decode of the client's bytes.
sub response_extras {
    my (%a) = @_;
    my ($v, $api, $op, $status, $body) = @a{qw(v api op status body)};
    return unless $v && $api && defined $op;
    return unless ref $body eq 'HASH' || ref $body eq 'ARRAY';

    my $spec = eval { $api->spec }                or return;
    my $info = eval { $api->operation_info($op) } or return;
    my $schema = _response_schema($spec, $info, $status) or return;

    my @errors;
    _walk_extras($spec, $schema, $body, '', \@errors, 0);
    return unless @errors;

    $v->record(
        observe   => 1,
        operation => ($info->{operationId} // $op),
        status    => ($status || 0),
        method    => _method($info->{method}),
        path      => Maat::Violation->template_path($info->{path}),
        kind      => 'response',
        errors    => \@errors,
    );
    return;
}

# The response schema for an operation and status: the exact status, then
# `default`, then the lowest declared 2xx - the same precedence Open::API
# answers a mock with. Content is taken from the first JSON media type.
sub _response_schema {
    my ($spec, $info, $status) = @_;
    my $pi = (ref $spec eq 'HASH' ? $spec->{paths} : {}) || {};
    $pi = $pi->{ $info->{path} // '' };
    return undef unless ref $pi eq 'HASH';
    my $op = $pi->{ lc($info->{method} // '') };
    return undef unless ref $op eq 'HASH' && ref $op->{responses} eq 'HASH';
    my $R = $op->{responses};

    my $r = $R->{ $status // '' } || $R->{"$status"} || $R->{default};
    if (!$r) {
        my ($lowest) = sort { $a <=> $b } grep { /^2\d\d$/ } keys %$R;
        $r = $R->{$lowest} if defined $lowest;
    }
    $r = _resolve($spec, $r);
    return undef unless ref $r eq 'HASH' && ref $r->{content} eq 'HASH';
    for my $ct (sort keys %{ $r->{content} }) {
        next unless $ct =~ m{\bjson\b}i;
        my $s = $r->{content}{$ct}{schema};
        return $s if defined $s;
    }
    return undef;
}

# Collect declared property schemas for an object schema, following a single
# level of allOf composition (the common "base + extension" shape). Best
# effort: what it cannot resolve, it omits, so an unknown composition makes
# a field look undeclared at worst - it never invents a declaration.
sub _object_props {
    my ($spec, $schema) = @_;
    my %props;
    my $open = !exists $schema->{additionalProperties}
             || (!ref $schema->{additionalProperties}
                 && $schema->{additionalProperties});   # absent or `true`
    if (ref $schema->{properties} eq 'HASH') {
        $props{$_} = $schema->{properties}{$_} for keys %{ $schema->{properties} };
    }
    for my $part (@{ _aref($schema->{allOf}) }) {
        my $r = _resolve($spec, $part);
        next unless ref $r eq 'HASH' && ref $r->{properties} eq 'HASH';
        $props{$_} //= $r->{properties}{$_} for keys %{ $r->{properties} };
        $open = 0 if exists $r->{additionalProperties}
                  && !(!ref $r->{additionalProperties} && $r->{additionalProperties});
    }
    return (\%props, $open);
}

sub _walk_extras {
    my ($spec, $schema, $value, $ptr, $out, $depth) = @_;
    return if $depth > 12 || @$out >= 100;      # bounded: never a walk bomb
    $schema = _resolve($spec, $schema);
    return unless ref $schema eq 'HASH';

    if (ref $value eq 'HASH') {
        my ($props, $open) = _object_props($spec, $schema);
        for my $k (sort keys %$value) {
            my $ps = $props->{$k};
            if (defined $ps) {
                my $rs = _resolve($spec, $ps);
                push @$out, {
                    keyword => 'deprecated-usage', in => 'response',
                    instanceLocation => "$ptr/" . _esc($k),
                } if ref $rs eq 'HASH' && $rs->{deprecated};
                _walk_extras($spec, $rs, $value->{$k}, "$ptr/" . _esc($k),
                             $out, $depth + 1);
            }
            # A key the schema never named is undeclared - but only when the
            # object is open (additionalProperties absent or true). A typed
            # map (additionalProperties: schema) or a closed object
            # (`false`, already a validation error) is not drift here.
            elsif ($open) {
                push @$out, {
                    keyword => 'undeclared-property', in => 'response',
                    instanceLocation => "$ptr/" . _esc($k),
                };
            }
        }
    }
    elsif (ref $value eq 'ARRAY') {
        my $items = $schema->{items};
        return unless defined $items;
        for my $i (0 .. $#$value) {
            _walk_extras($spec, $items, $value->[$i], "$ptr/$i",
                         $out, $depth + 1);
        }
    }
    return;
}

sub _esc {
    my ($k) = @_;
    $k =~ s/~/~0/g;
    $k =~ s{/}{~1}g;
    return $k;
}

# A bounded, best-effort resolver for local `#/...` references inside the
# same document. Returns the node unchanged for anything it cannot resolve
# - an external ref, a cycle, a miss - because this feeds an observe-only
# report: an unresolved schema costs a missed observation, never a wrong
# one.
sub _resolve {
    my ($spec, $node, $depth) = @_;
    $depth ||= 0;
    return $node if $depth > 8 || ref $node ne 'HASH';
    my $ref = $node->{'$ref'};
    return $node unless defined $ref && !ref $ref && $ref =~ m{^#/};

    (my $path = $ref) =~ s{^#/}{};
    my $t = $spec;
    for my $seg (split m{/}, $path) {
        $seg =~ s/~1/\//g;
        $seg =~ s/~0/~/g;
        if    (ref $t eq 'HASH') { $t = $t->{$seg} }
        elsif (ref $t eq 'ARRAY' && $seg =~ /^\d+\z/) { $t = $t->[$seg] }
        else  { return $node }
        return $node unless defined $t;
    }
    return _resolve($spec, $t, $depth + 1);
}

1;

__END__

=head1 NAME

Maat::Observe - observe-only drift the contract permits

=head1 DESCRIPTION

OpenAPI validation is silent on a whole class of real drift: an undeclared
query parameter, a response field the schema never mentions, a deprecated
field still in use, a path with no operation at all. None of it fails a
request, and all of it is worth seeing. This module records each through
L<Maat::Violation> with C<< observe => 1 >> and a distinct C<keyword>, so
it ships and aggregates through the existing pipeline without being counted
as a validation failure.

=head2 record_undeclared(v => $violation, method => ..., path => ..., keyword => ..., spec_version => ...)

A path with no matching operation (or a known path hit with an undeclared
method). The path is templated - value-like segments collapsed to C<*> -
so it is reported by shape, never by value.

=head2 request_params(v => $violation, api => $api, op => $op_id, env => \%env)

Undeclared query parameters and deprecated declared parameters (query and
header) in use on a matched operation, read from the operation's declared
parameters in the compiled document.

=cut
