package Maat::Remote;

use 5.010;
use strict;
use warnings;
use Carp ();

our $VERSION = '0.06';

# The CLI's end of the control plane's management API.
#
# There is a house rule behind this file: a write action that exists only
# in a browser is one you cannot perform at 3am. So every action the
# console offers has a command here, and t/27-cli-parity.t walks the
# published document's operations and fails on one no command can reach -
# the parity is a test, not an intention.
#
# Deliberately thin. The control plane validates every request against
# its own document, so this does not re-implement those rules: it turns
# arguments into a request, and a response into something readable.

my $DEFAULT_BASE = 'https://openapi-proxy.com/v1';

sub new {
    my ($class, %o) = @_;
    my $token = defined $o{token} ? $o{token} : $ENV{APIP_TOKEN};
    Carp::croak("Maat::Remote: no token (set APIP_TOKEN)\n")
        unless defined $token && length $token;
    return bless {
        base  => ($o{base} || $ENV{APIP_API} || $DEFAULT_BASE),
        token => $token,
        ua    => $o{ua},
        timeout => defined $o{timeout} ? $o{timeout} : 30,
    }, $class;
}

sub base { $_[0]{base} }

sub _ua {
    my ($self) = @_;
    return $self->{ua} if $self->{ua};
    require Fetch;
    return $self->{ua} = Fetch->new(timeout => $self->{timeout});
}

# One request. Returns ($status, $decoded_body_or_raw). Never dies on an
# HTTP status - a 404 from the control plane is an answer, and the
# command decides what to print.
sub call {
    my ($self, $method, $path, %o) = @_;
    require File::Raw::JSON;

    my $url = $self->{base} . $path;
    my @args = (
        headers => {
            'Authorization' => "Bearer $self->{token}",
            $o{json} ? ('Content-Type' => 'application/json') : (),
            'Accept' => 'application/json',
        },
        $o{json} ? (body => File::Raw::JSON::file_json_encode($o{json})) : (),
    );

    my $res = eval { $self->_ua->request(uc $method, $url, @args)->get };
    Carp::croak("apip: could not reach $url: " . _short($@) . "\n") unless $res;

    my $status = $res->{status} || eval { $res->status } || 0;
    my $body   = $res->{content};
    $body = eval { $res->content } unless defined $body;
    return ($status, undef) unless defined $body && length $body;

    my $data = eval { File::Raw::JSON::file_json_decode($body) };
    return ($status, defined $data ? $data : $body);
}

sub _short {
    my ($e) = @_;
    $e = "$e";
    $e =~ s/\s+at\s+\S+\s+line\s+\d+.*//s;
    $e =~ s/\s+$//;
    return length $e ? $e : 'the connection failed';
}

# ---- the operation map -------------------------------------------------------
#
# operationId => [ command, one-line usage ]. This is the gate: the
# parity test reads the published document, reads this, and fails on an
# operation nothing here reaches. Adding an operation to the API without
# adding a command breaks the build, which is the only way a promise
# like "everything the UI does, the CLI does" survives contact with a
# year of features.

my %COVERAGE = (
    listProxies       => [ 'proxies',          'apip proxies' ],
    getProxy          => [ 'proxies show',     'apip proxies show PROXY' ],
    createProxy       => [ 'proxies create',   'apip proxies create NAME [--upstream URL] [--spec FILE|--url URL]' ],
    updateProxy       => [ 'proxies set',      'apip proxies set PROXY [--name N] [--upstream URL] [--mode observe|enforce]' ],
    deleteProxy       => [ 'proxies delete',   'apip proxies delete PROXY' ],
    rotateReportToken => [ 'proxies rotate',   'apip proxies rotate PROXY' ],

    listSpecs         => [ 'specs',            'apip specs PROXY' ],
    createSpec        => [ 'specs add',        'apip specs add PROXY FILE|--url URL' ],
    getSpec           => [ 'specs get',        'apip specs get PROXY VERSION' ],
    publishSpec       => [ 'specs publish',    'apip specs publish PROXY VERSION' ],
    getDiff           => [ 'specs diff',       'apip specs diff PROXY [FROM TO]' ],

    listEnvironments  => [ 'env',              'apip env PROXY' ],
    setEnvironment    => [ 'env set',          'apip env set PROXY NAME [VERSION]' ],
    deleteEnvironment => [ 'env rm',           'apip env rm PROXY NAME' ],

    listViolations    => [ 'violations',       'apip violations PROXY [--since 24h|7d|friday] [--operation ID]' ],
    getCoverage       => [ 'coverage',         'apip coverage PROXY' ],

    listExamples      => [ 'examples',         'apip examples PROXY' ],
    setExample        => [ 'examples set',     'apip examples set PROXY FILE|- --operation ID --status N [--media-type T] [--name N]' ],
    deleteExample     => [ 'examples rm',      'apip examples rm PROXY EXAMPLE' ],

    getMcp            => [ 'mcp',              'apip mcp PROXY' ],
    updateMcp         => [ 'mcp on|off',       'apip mcp PROXY on|off [--ops ID,ID]' ],
    listMcpTools      => [ 'mcp tools',        'apip mcp PROXY tools' ],

    listAlerts        => [ 'alert',            'apip alert PROXY' ],
    createAlert       => [ 'alert add',        'apip alert add PROXY NAME --threshold N --window M --channel slack|webhook --target URL [--operation ID]' ],
    updateAlert       => [ 'alert silence',    'apip alert silence|enable PROXY ALERT' ],
    deleteAlert       => [ 'alert rm',         'apip alert rm PROXY ALERT' ],
);

sub coverage { return { %COVERAGE } }

# operationId -> command, one per line, for the parity test and for
# anybody wondering which command reaches which operation.
sub coverage_lines {
    return map { sprintf "%s\t%s\t%s", $_, @{ $COVERAGE{$_} } }
           sort keys %COVERAGE;
}

1;

__END__

=head1 NAME

Maat::Remote - the CLI's end of the control plane's management API

=head1 SYNOPSIS

    my $api = Maat::Remote->new;           # token from APIP_TOKEN
    my ($status, $body) = $api->call(GET => '/proxies');

=head1 DESCRIPTION

Thin on purpose. The control plane validates every request against its
own OpenAPI document, so this does not re-implement those rules - it
turns arguments into a request and a response into something readable.

C<APIP_TOKEN> is the account token; C<APIP_API> overrides the base URL
(default C<https://openapi-proxy.com/v1>), which is what points the CLI
at a staging control plane or at a test server.

=head2 The operation map

C<coverage> returns C<< { operationId => [ command, usage ] } >> and
C<coverage_lines> renders it.

This exists to be tested against. The house rule from L<Punk::Queue> is
that B<a write action that exists only in a browser is one you cannot
perform at 3am>, so every action the console offers has a command - and
F<t/27-cli-parity.t> walks the published document's operations and fails
on one nothing here reaches.

Adding an operation to the API without adding a command breaks the
build. That is the only way a promise like "everything the UI does, the
CLI does" survives a year of features.

=cut
