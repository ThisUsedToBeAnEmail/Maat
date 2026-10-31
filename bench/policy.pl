#!/usr/bin/env perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../t/lib";
use MaatTest ();        # puts the sibling blibs on @INC
use Time::HiRes ();
use Maat::Config;
use Maat::Gateway;

# What the POLICY layer costs - Maat's own Perl, with the forward stubbed
# out. The upstream round trip dominates a real request by orders of
# magnitude and would hide exactly what we are trying to see, so the
# proxy is replaced by a coderef that returns a fixed triplet.
#
# Usage: perl bench/policy.pl [ITERS] [REPS]

my $ITERS = shift || 50_000;
my $REPS  = shift || 7;

my $spec = "$FindBin::Bin/../t/spec/petstore.json";
my $config = Maat::Config->from_hash({
    upstream => 'http://127.0.0.1:1',      # never contacted
    spec     => $spec,
    mode     => 'enforce',
});

# The stub: what Reverse::Proxy would have returned, minus the network.
my $FIXED = [ 200, [ 'Content-Type' => 'application/json',
                     'Content-Length' => 2 ], [ '{}' ] ];

sub gateway_app {
    my $gw = Maat::Gateway->new(config => $config);
    $gw->{proxy} = sub { return [ @$FIXED ] };   # a fresh triplet per call
    return ($gw, $gw->to_app);
}

# One env per shape, rebuilt per iteration the way a server hands one
# over (frameworks cache in it, so reuse would flatter us).
sub env_for {
    my ($path, $query, $body) = @_;
    return sub {
        my $b = defined $body ? $body : '';
        open my $in, '<', \$b or die $!;
        my %env = (
            REQUEST_METHOD => (defined $body ? 'POST' : 'GET'),
            PATH_INFO      => $path,
            QUERY_STRING   => (defined $query ? $query : ''),
            SERVER_NAME    => '127.0.0.1',
            SERVER_PORT    => 80,
            SERVER_PROTOCOL => 'HTTP/1.1',
            HTTP_HOST       => 'api.example.com',
            HTTP_USER_AGENT => 'curl/8.4.0',
            HTTP_ACCEPT     => 'application/json',
            HTTP_ACCEPT_ENCODING => 'gzip, deflate, br',
            HTTP_ACCEPT_LANGUAGE => 'en-GB,en;q=0.9',
            HTTP_AUTHORIZATION   => 'Bearer ' . ('x' x 32),
            HTTP_CACHE_CONTROL   => 'no-cache',
            HTTP_CONNECTION      => 'keep-alive',
            HTTP_REFERER         => 'https://app.example.com/orders',
            HTTP_X_FORWARDED_FOR => '203.0.113.7',
            HTTP_X_REAL_IP       => '203.0.113.7',
            'psgi.input'   => $in,
            'psgi.errors'  => \*STDERR,
            'psgi.version' => [1, 1],
            'psgi.url_scheme' => 'http',
        );
        if (defined $body) {
            $env{CONTENT_LENGTH} = length $body;
            $env{CONTENT_TYPE}   = 'application/json';
        }
        return \%env;
    };
}

my @CASES = (
    [ 'conforming GET      ' => env_for('/pets', 'limit=10') ],
    [ 'conforming GET+path ' => env_for('/pets/42') ],
    [ 'conforming POST body' => env_for('/pets', undef, '{"name":"rex"}') ],
    [ 'undeclared path     ' => env_for('/health/deep') ],
    [ 'violating GET       ' => env_for('/pets', 'limit=9999') ],
);

sub best {
    my ($code) = @_;
    my $best;
    for (1 .. $REPS) {
        my $t0 = Time::HiRes::time();
        $code->() for 1 .. $ITERS;
        my $el = Time::HiRes::time() - $t0;
        $best = $el if !defined $best || $el < $best;
    }
    return 1e6 * $best / $ITERS;      # microseconds per iteration
}

printf "%-22s %10s %10s\n", 'case', 'us/req', 'req/s';
printf "%s\n", '-' x 44;

my ($gw, $app) = gateway_app();
my %total;
for my $case (@CASES) {
    my ($name, $mkenv) = @$case;
    my $us = best(sub { $app->($mkenv->()) });
    $total{$name} = $us;
    printf "%-22s %10.2f %10.0f\n", $name, $us, 1e6 / $us;
}

# ---- the same envs through the pieces, to see where the time is --------------

print "\nbreakdown (conforming GET with a query):\n";
my $mkenv = $CASES[0][1];
my $api   = $gw->api;

my $baseline = best(sub { my $e = $mkenv->() });
printf "  %-30s %8.2f us\n", 'building the env (the harness)', $baseline;

for my $part (
    [ "match (XS)" => sub { my $e = $mkenv->();
        my ($op, $x) = $api->match($e->{REQUEST_METHOD}, $e->{PATH_INFO}) } ],
    [ "match + validate_env (XS)" => sub { my $e = $mkenv->();
        my ($op, $x) = $api->match($e->{REQUEST_METHOD}, $e->{PATH_INFO});
        $api->validate_env($op, $e, $x) } ],
    [ 'the whole app' => sub { $app->($mkenv->()) } ],
) {
    my ($name, $code) = @$part;
    my $us = best($code);
    printf "  %-30s %8.2f us  (%.2f net of the env)\n",
           $name, $us, $us - $baseline;
}

printf "\n%d iterations, best of %d, perl %s\n", $ITERS, $REPS, $];
