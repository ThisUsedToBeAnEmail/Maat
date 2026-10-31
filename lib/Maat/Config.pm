package Maat::Config;

use 5.010;
use strict;
use warnings;
use Carp ();
use File::Spec ();
use File::Basename ();

our $VERSION = '0.06';

# The whole configuration of a gateway process, checked at load.
#
# Two rules, both of which exist because this thing starts inside a
# customer's deployment at 3am:
#
#   1. Every error names the key path and what to do about it. "unknown
#      key 'upstrem' (did you mean 'upstream'?)" beats a stack trace
#      from somewhere inside the request path an hour later.
#   2. Unknown keys are fatal, not ignored. A typo'd option that is
#      silently dropped is a setting the operator believes is on.

# key => [ required?, checker, default ]. Nested tables are their own
# schema; anything not named here is a fatal unknown key.
my %SCHEMA = (
    # `upstream` is required for a real gateway and forbidden for a mock -
    # both are enforced below in from_hash, where the mode is known.
    upstream => [ 0, \&_url ],
    spec     => [ 1, \&_readable_file ],
    mode     => [ 0, _enum(qw(observe enforce mock)), 'observe' ],
    mock     => [ 0, \&_mock, undef ],
    listen   => [ 0, \&_listeners, undef ],
    timeout  => [ 0, \&_positive_number, 30 ],
    preserve_host => [ 0, \&_boolean, 0 ],
    tls_verify    => [ 0, \&_boolean, 1 ],
    pool_size     => [ 0, \&_positive_int, 64 ],
    max_body      => [ 0, \&_bytes, 1024 * 1024 ],
    stream        => [ 0, \&_boolean, 0 ],
    workers       => [ 0, \&_nonneg_int, 0 ],
    access_log    => [ 0, \&_string, undef ],
    report        => [ 0, \&_report, undef ],
    responses     => [ 0, \&_responses, undef ],

    # The docs portal (phase 10). Off by default, and the switch is the
    # gate: with `portal` false there is no /docs route at all - a request
    # to /docs is handled as any other path the document does not declare.
    # On, the gateway renders a per-environment docs site from the SAME
    # compiled spec it is enforcing, served from frozen bytes off the
    # request path. See Maat::Portal.
    portal        => [ 0, \&_boolean, 0 ],
);

# Response validation. Off is a supported answer - somebody is proxying
# an API whose responses they do not control and only wants the request
# half - so `validate` is its own key rather than implied by the rest.
my %RESPONSES_SCHEMA = (
    validate => [ 0, \&_boolean, 1 ],
    sample   => [ 0, \&_sample, 'adaptive' ],
    budget   => [ 0, \&_positive_number, 50 ],
    floor    => [ 0, \&_positive_number, 10 ],
    interval => [ 0, \&_positive_number, 1 ],
    max_body => [ 0, \&_bytes, 1024 * 1024 ],
);

# Mock mode. `max_delay` caps ?__delay= so a pasted spec's URL cannot be
# turned into a worker-pinning lever - ten seconds is enough to exercise
# any client timeout worth having.
my %MOCK_SCHEMA = (
    max_delay => [ 0, \&_positive_number, 10 ],
);

my %LISTEN_SCHEMA = (
    port           => [ 1, \&_port ],
    host           => [ 0, \&_string, '0.0.0.0' ],
    tls_cert       => [ 0, \&_readable_file, undef ],
    tls_key        => [ 0, \&_readable_file, undef ],
    redirect_https => [ 0, \&_port, undef ],
);

my %REPORT_SCHEMA = (
    url   => [ 0, \&_url, undef ],
    token => [ 0, \&_string, undef ],

    # aggregation
    window      => [ 0, \&_nonneg_number, 10 ],     # seconds; 0 = every violation
    max_keys    => [ 0, \&_positive_int,    1000 ], # fingerprints per window
    environment => [ 0, \&_string,          undef ],

    # the spool
    spool       => [ 0, \&_string,   undef ],       # a directory
    spool_files => [ 0, \&_positive_int, 1000 ],
    spool_bytes => [ 0, \&_bytes,    64 * 1024 * 1024 ],

    # shipping
    interval    => [ 0, \&_positive_number, 5 ],
    batch       => [ 0, \&_positive_int,    10 ],
    gzip        => [ 0, \&_boolean,         1 ],
    timeout     => [ 0, \&_positive_number, 10 ],
    # Coverage is a snapshot on a much slower clock than the violations
    # it rides with - shipping it at the drain interval would be the
    # same answer twelve times a minute.
    coverage_interval => [ 0, \&_positive_number, 60 ],

    # redaction. `strict` keeps no example value at all.
    redact      => [ 0, _enum(qw(default strict)), 'default' ],
    redact_names => [ 0, \&_string_list, undef ],

    # Observe-only drift the contract permits: undeclared query params,
    # undeclared endpoints (a path with no operation, forwarded upstream),
    # deprecated fields still in use, response fields not in the schema.
    # On by default; an operator whose surface is intentionally larger than
    # its document turns it off here. Never enforced - it only reports.
    undeclared  => [ 0, \&_boolean, 1 ],

    # the self-report endpoint. Off unless a path is given, because it
    # shadows that path on the proxied API - see Maat::Config's POD.
    metrics     => [ 0, \&_string, undef ],
);

sub load {
    my ($class, $file) = @_;
    Carp::croak("Maat::Config: no configuration file given") unless defined $file;
    -r $file or Carp::croak("Maat::Config: cannot read '$file'");

    require YAML::XS;
    my $raw = eval { YAML::XS::LoadFile($file) };
    Carp::croak("Maat::Config: '$file' is not valid YAML: $@") if $@;
    Carp::croak("Maat::Config: '$file' is empty") unless defined $raw;
    Carp::croak("Maat::Config: '$file' must be a mapping, not a "
              . (ref($raw) || 'scalar')) unless ref $raw eq 'HASH';

    my $self = $class->from_hash($raw, File::Basename::dirname($file));
    $self->{file} = $file;
    return $self;
}

sub from_hash {
    my ($class, $raw, $base) = @_;
    $base = '.' unless defined $base;

    my %c = _apply(\%SCHEMA, $raw, '', $base);

    # The mode decides what `upstream` means: a gateway without one has
    # nothing to forward to, and a mock with one is a contradiction an
    # operator should hear about rather than have silently ignored.
    if (($c{mode} || 'observe') eq 'mock') {
        Carp::croak("Maat::Config: mode 'mock' does not take an 'upstream' - "
            . "a mock serves the document, nothing is forwarded")
            if defined $c{upstream};
        $c{mock} = _default_mock() unless defined $c{mock};
    }
    else {
        Carp::croak("Maat::Config: 'upstream' is required (except in "
            . "mode 'mock')") unless defined $c{upstream};
        Carp::croak("Maat::Config: the 'mock' table only applies to "
            . "mode 'mock'") if defined $c{mock};
    }

    $c{listen}    = _default_listen()  unless defined $c{listen};
    $c{responses} = _default_responses() unless defined $c{responses};
    $c{report}    = _default_report()    unless defined $c{report};
    $c{base}      = $base;

    # A TLS listener needs both halves or neither - half a certificate is
    # a boot failure, never a listener that quietly serves plain HTTP.
    for my $l (@{ $c{listen} }) {
        next unless defined $l->{tls_cert} || defined $l->{tls_key};
        defined $l->{tls_cert} && defined $l->{tls_key}
            or Carp::croak("Maat::Config: listen port $l->{port} has "
                . (defined $l->{tls_cert} ? 'tls_cert' : 'tls_key')
                . ' but not the other - a TLS listener needs both');
    }

    return bless \%c, $class;
}

# A hosted tenant's configuration, built in memory from one bundle row
# rather than read from a apip.yml. The spec is not a file here - it has
# already been compiled off the request path by Maat::Registry and the
# object is handed straight to Maat::Gateway - so this fills in only what
# the gateway reads BESIDES the spec: the mode, the upstream, the caps
# that came from the tenant's plan, and the same-shaped default blocks
# for responses/report/mock so nothing downstream has to ask whether it
# is looking at a hosted tenant or a self-hosted one.
#
# enforce is a plan feature. A bundle row may say `mode: enforce` while
# the plan's limits do not grant it (a control plane and a worker briefly
# disagreeing across a downgrade, say); the safe reading is to record
# rather than reject, so enforcement is downgraded to observe here and
# the tenant's traffic flows unblocked rather than being answered 400 by
# a gateway it did not pay for.
sub tenant {
    my ($class, %o) = @_;
    my $limits = $o{limits} || {};
    my $mode   = $o{mode} || 'observe';
    $mode = 'observe' if $mode eq 'enforce' && !$limits->{enforce};

    # How much of the response traffic this tenant's plan buys.
    #
    # The control plane resolves its own vocabulary ('1%', 'adaptive',
    # 'configurable') into this one and sends the answer as `sampling`.
    # We clamp it against the allowance anyway, for the same reason the
    # enforce line above exists: what a tenant may have is decided here,
    # from the plan, and not by trusting the value that arrived beside
    # it. Only `configurable` is taken at its word.
    my $allow = $limits->{sampling};
    my $sampling = $o{sampling};
    $sampling = 100        if defined $allow && $allow eq '1%';
    $sampling = 'adaptive' if defined $allow && $allow eq 'adaptive';
    if (defined $sampling) {
        # Through the same validator a configured `responses.sample`
        # goes through, so a malformed override croaks here naming the
        # key rather than reaching Maat::Sampler as a divisor of 'yes'.
        my %r = %{ $o{responses} || _default_responses() };
        $r{sample} = _sample($sampling, 'responses.sample');
        $o{responses} = \%r;
    }

    my %c = (
        mode          => $mode,
        upstream      => (defined $o{upstream} && length $o{upstream})
                       ? $o{upstream} : undef,
        spec          => undef,               # compiled elsewhere; api is injected
        timeout       => $o{timeout}       // 30,
        preserve_host => $o{preserve_host} // 0,
        tls_verify    => $o{tls_verify}    // 1,
        pool_size     => $o{pool_size}     // 64,
        max_body      => $o{max_body}      // (1024 * 1024),
        stream        => $o{stream}        // 0,
        workers       => 0,
        access_log    => undef,
        base          => '.',
        mock          => _default_mock(),
        responses     => $o{responses} || _default_responses(),
        report        => $o{report}    || _default_report(),
        limits        => { %$limits },
        plan          => $o{plan},
        version       => $o{version},
        portal        => $o{portal} ? 1 : 0,
    );
    return bless \%c, $class;
}

sub limits    { $_[0]{limits} }
sub plan      { $_[0]{plan} }
sub version   { $_[0]{version} }
sub portal    { $_[0]{portal} }

sub mode      { $_[0]{mode} }
sub mock      { $_[0]{mock} }
sub responses { $_[0]{responses} }
sub report    { $_[0]{report} }
sub workers  { $_[0]{workers} }
sub upstream { $_[0]{upstream} }
sub spec     { $_[0]{spec} }
sub listen   { $_[0]{listen} }
sub file     { $_[0]{file} }
sub enforcing { $_[0]{mode} eq 'enforce' ? 1 : 0 }

# ---- the walker -------------------------------------------------------------

sub _apply {
    my ($schema, $raw, $path, $base) = @_;
    my %out;

    for my $k (sort keys %$raw) {
        my $where = $path ? "$path.$k" : $k;
        my $rule = $schema->{$k}
            or Carp::croak("Maat::Config: unknown key '$where'"
                         . _suggest($k, $schema));
        my $v = _resolve($raw->{$k}, $where, $base);
        $out{$k} = $rule->[1]->($v, $where, $base);
    }
    for my $k (sort keys %$schema) {
        next if exists $out{$k};
        my ($required, undef, $default) = @{ $schema->{$k} };
        my $where = $path ? "$path.$k" : $k;
        Carp::croak("Maat::Config: '$where' is required") if $required;
        $out{$k} = $default;
    }
    return %out;
}

# Did-you-mean by edit distance 1-2, which covers the typos people
# actually make. Cheap: this runs once, at boot.
sub _suggest {
    my ($key, $schema) = @_;
    my ($best, $score);
    for my $c (keys %$schema) {
        my $d = _distance(lc $key, lc $c);
        ($best, $score) = ($c, $d) if !defined $score || $d < $score;
    }
    return '' unless defined $score && $score <= 2;
    return " (did you mean '$best'?)";
}

sub _distance {
    my ($a, $b) = @_;
    my @prev = (0 .. length $b);
    for my $i (1 .. length $a) {
        my @cur = ($i);
        for my $j (1 .. length $b) {
            my $cost = substr($a, $i - 1, 1) eq substr($b, $j - 1, 1) ? 0 : 1;
            my $min = $prev[$j] + 1;
            $min = $cur[$j - 1] + 1      if $cur[$j - 1] + 1 < $min;
            $min = $prev[$j - 1] + $cost if $prev[$j - 1] + $cost < $min;
            push @cur, $min;
        }
        @prev = @cur;
    }
    return $prev[-1];
}

# ---- secret references ------------------------------------------------------
# { $env: NAME } / { $file: path }. A token in a config file that is in
# a git repository is the most common way a customer leaks one, so the
# format that keeps it out is first-class rather than documented.

sub _resolve {
    my ($v, $where, $base) = @_;
    return $v unless ref $v eq 'HASH';
    my @k = keys %$v;
    return $v unless @k == 1 && $k[0] =~ /\A\$(env|file)\z/;
    my ($kind, $arg) = ($1, $v->{ $k[0] });

    if ($kind eq 'env') {
        Carp::croak("Maat::Config: '$where' reads environment variable "
                  . "'$arg', which is not set")
            unless defined $ENV{$arg};
        return $ENV{$arg};
    }
    my $path = File::Spec->file_name_is_absolute($arg)
             ? $arg : File::Spec->catfile($base, $arg);
    open my $fh, '<', $path
        or Carp::croak("Maat::Config: '$where' reads '$path': $!");
    local $/;
    my $body = <$fh>;
    close $fh;
    $body =~ s/\s+\z// if defined $body;
    return $body;
}

# ---- checkers ---------------------------------------------------------------

sub _string {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a string")
        if !defined $v || ref $v;
    return "$v";
}

sub _url {
    my ($v, $where) = @_;
    $v = _string($v, $where);
    $v =~ m{\Ahttps?://[^/\s]+}
        or Carp::croak("Maat::Config: '$where' must be an http(s) URL, "
                     . "not '$v'");
    $v =~ s{/\z}{};
    return $v;
}

sub _readable_file {
    my ($v, $where, $base) = @_;
    $v = _string($v, $where);
    my $path = File::Spec->file_name_is_absolute($v)
             ? $v : File::Spec->catfile($base, $v);
    -r $path or Carp::croak("Maat::Config: '$where' is '$v', which is not "
                          . "a readable file (looked at $path)");
    return $path;
}

sub _enum {
    my @ok = @_;
    return sub {
        my ($v, $where) = @_;
        $v = _string($v, $where);
        return $v if grep { $_ eq $v } @ok;
        Carp::croak("Maat::Config: '$where' must be one of "
                  . join(', ', map { "'$_'" } @ok) . ", not '$v'");
    };
}

sub _boolean {
    my ($v, $where) = @_;
    return 0 if !defined $v;
    return $v ? 1 : 0 unless ref $v;
    Carp::croak("Maat::Config: '$where' must be true or false");
}

sub _positive_number {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a positive number")
        if !defined $v || ref $v || $v !~ /\A[\d.]+\z/ || $v <= 0;
    return $v + 0;
}

# Zero is a real answer for a duration: `report.window: 0` means close a
# window on every violation, which is what a low-traffic gateway that
# wants its drift immediately should say.
sub _nonneg_number {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a number, zero or more")
        if !defined $v || ref $v || $v !~ /\A[\d.]+\z/;
    return $v + 0;
}

sub _nonneg_int {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a non-negative integer")
        if !defined $v || ref $v || $v !~ /\A\d+\z/;
    return int $v;
}

sub _positive_int {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a positive integer")
        if !defined $v || ref $v || $v !~ /\A\d+\z/ || $v < 1;
    return int $v;
}

sub _port {
    my ($v, $where) = @_;
    $v = _positive_int($v, $where);
    Carp::croak("Maat::Config: '$where' must be a port (1-65535), not $v")
        if $v > 65535;
    return $v;
}

# 256k / 2M / plain bytes - people write sizes the way they say them
sub _bytes {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a size") if !defined $v || ref $v;
    my %mult = ('' => 1, k => 1024, m => 1024**2, g => 1024**3);
    $v =~ /\A(\d+(?:\.\d+)?)\s*([kmg]?)b?\z/i
        or Carp::croak("Maat::Config: '$where' must be a size like "
                     . "'256k' or '1048576', not '$v'");
    return int($1 * $mult{ lc $2 });
}

sub _listeners {
    my ($v, $where, $base) = @_;
    $v = [$v] if ref $v eq 'HASH';
    Carp::croak("Maat::Config: '$where' must be a list of listeners")
        unless ref $v eq 'ARRAY' && @$v;
    my $i = 0;
    return [ map {
        my $l = $_;
        Carp::croak("Maat::Config: '$where\[$i]' must be a mapping")
            unless ref $l eq 'HASH';
        my %one = _apply(\%LISTEN_SCHEMA, $l, "$where\[$i]", $base);
        $i++;
        \%one;
    } @$v ];
}

sub _report {
    my ($v, $where, $base) = @_;
    Carp::croak("Maat::Config: '$where' must be a mapping")
        unless ref $v eq 'HASH';
    my %r = _apply(\%REPORT_SCHEMA, $v, $where, $base);
    return \%r;
}

sub _string_list {
    my ($v, $where) = @_;
    $v = [$v] unless ref $v;
    Carp::croak("Maat::Config: '$where' must be a string or a list of them")
        unless ref $v eq 'ARRAY';
    return [ map { _string($_, $where) } @$v ];
}

sub _responses {
    my ($v, $where, $base) = @_;
    Carp::croak("Maat::Config: '$where' must be a mapping")
        unless ref $v eq 'HASH';
    my %r = _apply(\%RESPONSES_SCHEMA, $v, $where, $base);
    return \%r;
}

# 'adaptive' (a budget per operation, retuned from traffic), 'all' (every
# response - the honest ceiling, and what a test environment wants), or
# an integer N meaning one response in N.
sub _sample {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be 'adaptive', 'all' or a "
              . "positive integer") if !defined $v || ref $v;
    return $v if $v eq 'adaptive' || $v eq 'all';
    return int $v if $v =~ /\A\d+\z/ && $v >= 1;
    Carp::croak("Maat::Config: '$where' must be 'adaptive', 'all' or a "
              . "positive integer (one response in N), not '$v'");
}

# Through the same schema as a configured one, so the default listener
# has the same shape: anything reading $l->{tls_cert} sees a key that is
# undef rather than a key that is missing, and behaves the same either
# way round.
sub _default_listen {
    return [ { _apply(\%LISTEN_SCHEMA, { port => 8080 }, 'listen[0]', '.') } ];
}

# Likewise: an unconfigured `responses` block is the same shape as a
# configured one, so nothing has to ask which it is looking at.
sub _mock {
    my ($v, $where, $base) = @_;
    Carp::croak("Maat::Config: '$where' must be a mapping")
        unless ref $v eq 'HASH';
    my %r = _apply(\%MOCK_SCHEMA, $v, $where, $base);
    return \%r;
}

sub _default_mock {
    return { _apply(\%MOCK_SCHEMA, {}, 'mock', '.') };
}

sub _default_responses {
    return { _apply(\%RESPONSES_SCHEMA, {}, 'responses', '.') };
}

sub _default_report {
    return { _apply(\%REPORT_SCHEMA, {}, "report", ".") };
}

1;

__END__

=head1 NAME

Maat::Config - a gateway's configuration, validated at load

=head1 SYNOPSIS

    my $config = Maat::Config->load('apip.yml');
    $config->mode;        # observe | enforce
    $config->upstream;    # https://api.internal:8443
    $config->spec;        # an absolute path, proven readable

=head1 DESCRIPTION

Reads C<apip.yml>, checks every key, resolves secret references and
returns an object - or croaks naming the key path and the fix. Unknown
keys are fatal with a did-you-mean, because a silently ignored option is
a setting an operator believes is switched on.

=head2 Keys

C<upstream> (required, except in mode C<mock> where it is refused - a
mock serves the document and forwards nothing) and C<spec> (required);
C<mode> (C<observe>, the default, C<enforce>, or C<mock>); C<listen> (a
list of C<{ port, host, tls_cert,
tls_key, redirect_https }>, defaulting to one plain listener on 8080);
C<timeout>, C<preserve_host>, C<tls_verify>, C<pool_size> passed through
to L<Reverse::Proxy>; C<max_body>, the cap on a body Maat will buffer to
validate; C<workers> and C<access_log> passed through to L<Hyperman>
(0 workers means one per CPU); C<stream> (see below); and C<report>
(C<url>, C<token>) for the violation pipeline.

=head2 responses

How much of the response traffic to weigh against the document, and how
hard to look. Every key has a default, so the block is optional:

    responses:
      validate: true        # check responses at all
      sample:   adaptive    # adaptive | all | N (one response in N)
      budget:   50          # adaptive: validated responses/second/operation
      floor:    10          # ...but at least one every this many seconds
      interval: 1           # how often the divisor is recomputed
      max_body: 1M          # never look at a body larger than this

C<sample: adaptive> is the default and the one to leave alone: it keeps
the work per operation bounded whatever the traffic does, while still
covering an endpoint that serves two requests a minute. C<all> is the
honest ceiling and what a staging environment wants. See
L<Maat::Sampler>.

C<budget> is per operation rather than per process on purpose. One hot
endpoint must not spend the whole validation budget and leave the other
ninety uncovered: coverage across the contract is the product.

Turning C<validate> off is a supported answer - somebody proxying an API
whose responses they do not control may only want the request half.

=head2 mock

    mode: mock
    mock:
      max_delay: 10         # the ceiling on ?__delay=, in seconds

Mock mode: the gateway serves synthesized responses from the document
itself and has no upstream at all - see L<Maat::Gateway/"Mock mode">.
The C<mock> table only applies (and only validates) when the mode is
C<mock>; C<max_delay> caps the C<?__delay=> query parameter so a public
mock URL cannot be held open indefinitely.

=head2 stream

    stream: true

Forward response bodies chunk by chunk instead of buffering them
(L<Reverse::Proxy/stream>). Memory then does not grow with the size of a
download, which is what an API serving large payloads or Server-Sent
Events needs.

The trade is that a streamed body is never a plain scalar when the
response check sees it, so it is counted C<skip_body> and not validated.
Streaming and response validation are alternatives for one route, not
companions: choose per deployment which of the two that upstream needs.

=head2 report

What happens to a violation once it has been recorded. Every key has a
default, so the block is optional; without a C<url> nothing is shipped
and without a C<spool> nothing is written to disk, but aggregation and
C</metrics> work either way.

    report:
      url:   https://openapi-proxy.com/v1/violations
      token: { $env: APIP_TOKEN }

      window:   10              # aggregate for this many seconds
      max_keys: 1000            # distinct fingerprints held per window
      environment: production   # stamped on every record

      spool:       /var/spool/maat
      spool_files: 1000
      spool_bytes: 64M

      interval: 5               # seconds between shipping attempts
      batch:    10              # spool files per request
      gzip:     true
      timeout:  10
      coverage_interval: 60     # seconds between coverage snapshots

      redact:       default     # default | strict
      redact_names: [ account_ref, customer_id ]
      undeclared:   true        # observe-only drift the contract permits

      metrics: /_maat/metrics   # off unless named - see below

C<window: 0> closes a window on every violation, which is what a
low-traffic gateway that wants its drift immediately should say.

C<redact: strict> keeps no example value at all. C<redact_names> adds to
the built-in list of names assumed to be secrets; it never shortens it.
See L<Maat::Redact>.

C<undeclared: true> (the default) reports observe-only drift that OpenAPI
validation permits: undeclared query parameters, undeclared endpoints (a
path with no operation, forwarded to the upstream), deprecated fields still
in use, and response fields not in the schema. It is B<never> enforced -
even in C<enforce> mode these only report - and it has no effect in
C<mock> mode, where there is no upstream to drift against. An operator
whose live surface is intentionally larger than its document sets it
false. Undeclared endpoints are reported by their templated shape
(C<GET /users/*/orders>), never their values, under the same rule that
keeps a payload value out of every other record. See L<Maat::Observe>.

=head2 metrics

C<report.metrics> names a path on which the gateway reports itself -
counters, response coverage, spool depth, shipping failures - as JSON.

It is off unless you name it, and it B<shadows that path on the proxied
API>: a request for it is answered by Maat and never reaches the
upstream. Silently intercepting a path the upstream serves would be the
rudest thing a transparent proxy could do, so it is opt-in and the
operator chooses a path they know is free.

=head2 portal

    portal: true

The docs portal (phase 10), off by default. The switch is the gate: with
C<portal> false there is no C</docs> route at all, and a request to
C</docs> is handled as any other path the document does not declare
(forwarded, or C<404> undeclared in a mock). Turned on, the gateway
renders a per-environment documentation site from the B<same> compiled
spec it is enforcing - the generated reference, the fetched prose guides,
a trigram search over both, per-operation client snippets, and (per the
tenant's own opt-in) a reality badge from the local drift aggregates -
built once off the request path and served from frozen bytes. See
L<Maat::Portal>.

=head2 Secret references

Any scalar may be written C<< { $env: NAME } >> or C<< { $file: path } >>
and is resolved at load, so a token never has to be written into a file
that lives in a repository.

=head1 METHODS

=head2 load($file) / from_hash(\%raw, $base) / mode / mock / upstream / spec / listen / responses / file / enforcing / portal

=cut
