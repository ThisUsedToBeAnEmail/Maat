#!/usr/bin/env perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/../t/lib";
use MaatTest ();
use Time::HiRes ();
use Maat::Config;
use Maat::Gateway;

# Where the policy layer's time goes, by turning one thing off at a time.
# The point is to find out what is worth writing in C before writing any,
# because "it is Perl" is not the same as "it is the cost".

my $ITERS = shift || 30_000;
my $REPS  = shift || 7;
my $spec  = "$FindBin::Bin/../t/spec/petstore.json";

my $FIXED_BODY = '{"id":1,"name":"rex"}';
sub stub_proxy {
    return sub {
        return [ 200, [ 'Content-Type' => 'application/json',
                        'Content-Length' => length $FIXED_BODY ],
                 [ $FIXED_BODY ] ];
    };
}

sub gw {
    my (%responses) = @_;
    my $config = Maat::Config->from_hash({
        upstream  => 'http://127.0.0.1:1',
        spec      => $spec,
        mode      => 'enforce',
        (%responses ? (responses => \%responses) : ()),
    });
    my $g = Maat::Gateway->new(config => $config);
    $g->{proxy} = stub_proxy();
    return ($g, $g->to_app);
}

sub mkenv {
    my $b = '';
    open my $in, '<', \$b or die $!;
    return {
        REQUEST_METHOD => 'GET', PATH_INFO => '/pets', QUERY_STRING => 'limit=10',
        SERVER_NAME => '127.0.0.1', SERVER_PORT => 80, SERVER_PROTOCOL => 'HTTP/1.1',
        HTTP_HOST => 'api.example.com', HTTP_USER_AGENT => 'curl/8.4.0',
        HTTP_ACCEPT => 'application/json', HTTP_ACCEPT_ENCODING => 'gzip, deflate',
        HTTP_AUTHORIZATION => 'Bearer ' . ('x' x 32), HTTP_CONNECTION => 'keep-alive',
        HTTP_REFERER => 'https://app.example.com/orders',
        HTTP_X_FORWARDED_FOR => '203.0.113.7',
        'psgi.input' => $in, 'psgi.errors' => \*STDERR,
        'psgi.version' => [1,1], 'psgi.url_scheme' => 'http',
    };
}

sub best {
    my ($code) = @_;
    my $best;
    for (1 .. $REPS) {
        my $t0 = Time::HiRes::time();
        $code->() for 1 .. $ITERS;
        my $el = Time::HiRes::time() - $t0;
        $best = $el if !defined $best || $el < $best;
    }
    return 1e6 * $best / $ITERS;
}

my $env_cost = best(sub { mkenv() });
printf "%-46s %8s %8s\n", 'configuration', 'us/req', 'net';
printf "%s\n", '-' x 64;
printf "%-46s %8.2f %8s\n", 'building the env (the harness)', $env_cost, '-';

my @ROWS;
sub row {
    my ($label, $app) = @_;
    my $us = best(sub { $app->(mkenv()) });
    push @ROWS, [ $label, $us - $env_cost ];
    printf "%-46s %8.2f %8.2f\n", $label, $us, $us - $env_cost;
}

{ my ($g, $app) = gw(validate => 0);            row('responses off (request path only)', $app) }
{ my ($g, $app) = gw(validate => 1, sample => 'all'); row('responses on, sample=all', $app) }
{ my ($g, $app) = gw(validate => 1, sample => 200);     row('responses on, 1-in-200', $app) }
{ my ($g, $app) = gw();                          row('the shipped defaults (adaptive)', $app) }

# The request half, piece by piece, against the same env.
print "\nthe request half, cumulative:\n";
my ($g) = gw(validate => 0);
my $api = $g->api;
my $base = best(sub { mkenv() });
for my $part (
    [ 'env + match'                  => sub { my $e = mkenv();
        my ($op,$x) = $api->match($e->{REQUEST_METHOD}, $e->{PATH_INFO}) } ],
    [ 'env + match + validate_env'   => sub { my $e = mkenv();
        my ($op,$x) = $api->match($e->{REQUEST_METHOD}, $e->{PATH_INFO});
        $api->validate_env($op, $e, $x) } ],
    [ 'the whole request path'       => sub { $g->to_app->(mkenv()) } ],
) {
    my ($name, $code) = @$part;
    my $us = best($code);
    printf "  %-42s %8.2f %8.2f\n", $name, $us, $us - $base;
}

printf "\n%d iterations, best of %d\n", $ITERS, $REPS;
