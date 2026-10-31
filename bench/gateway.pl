#!/usr/bin/env perl
use strict;
use warnings;

# What the gateway costs, in five columns, against one upstream that
# returns a fixed 2KB JSON document:
#
#     direct to upstream                    baseline
#     + Reverse::Proxy                      the proxy's own cost
#     + request validation                  phase 1
#     + response validation @ 1%            the product default
#     + response validation @ 100%          the honest ceiling
#
# Reported as microseconds per request and as a percentage of the bare
# proxy, both. The 1% column is the number the product rests on: if it is
# not within a few percent of the request-validation column, the sampling
# design is wrong.
#
# No sockets and no server: each layer's PSGI coderef is called in a loop
# with a freshly built environment, so what is measured is the layer, not
# the network. The upstream is a coderef standing in for the round trip -
# a real one would dominate everything here, which is the point: this
# measures what Maat adds to it.
#
# Every column runs in its own child from a clean interpreter, and the
# best of REPS rounds is reported: the best round is the one least
# disturbed by the rest of the machine.
#
# Usage: perl bench/gateway.pl [ITERATIONS] [REPS]

use FindBin ();
use lib "$FindBin::Bin/../lib";

# The sibling checkouts, when they are built but not installed - the same
# ones the test suite puts on @INC. A benchmark that silently measured an
# older installed Open::API would be worse than no benchmark.
BEGIN {
    my $sem = "$FindBin::Bin/../..";
    for my $dist (qw(JSON-Schema-Fast Fetch Open-API Reverse-Proxy
                     Horus Hyperman File-Raw-JSON)) {
        unshift @INC, "$sem/$dist/blib/lib", "$sem/$dist/blib/arch"
            if -d "$sem/$dist/blib/arch";
    }
}

use Time::HiRes ();
use File::Raw::JSON ();
use Open::API ();
use Maat::Sampler ();

my $ITERS = $ARGV[0] || 20_000;
my $REPS  = $ARGV[1] || 5;
my $SPEC  = "$FindBin::Bin/../t/spec/petstore.json";

# ---- the upstream ------------------------------------------------------------
# A fixed 2KB JSON document, conforming to the schema, built once. It is
# the same bytes in every column so that nothing measures the encoder.

my $DOC = do {
    my $pet = { id => 1, name => 'rex' . ('.' x 1900) };
    File::Raw::JSON::file_json_encode($pet);
};
my @HEADERS = ( 'Content-Type'   => 'application/json',
                'Content-Length' => length $DOC );

sub upstream { return [ 200, [ @HEADERS ], [ $DOC ] ] }

# ---- the environment ---------------------------------------------------------

my $EMPTY = '';
open my $IN, '<', \$EMPTY or die $!;
sub env_for {
    my $in = $IN;
    seek $in, 0, 0;
    return {
        REQUEST_METHOD  => 'GET',       PATH_INFO       => '/pets/42',
        QUERY_STRING    => '',          SCRIPT_NAME     => '',
        SERVER_NAME     => '127.0.0.1', SERVER_PORT     => 80,
        SERVER_PROTOCOL => 'HTTP/1.1',  HTTP_HOST       => '127.0.0.1',
        REMOTE_ADDR     => '127.0.0.1',
        HTTP_USER_AGENT => 'bench',     HTTP_ACCEPT     => '*/*',
        'psgi.version'  => [1, 1],      'psgi.url_scheme' => 'http',
        'psgi.input'    => $in,         'psgi.errors'   => \*STDERR,
        'psgi.multithread' => 0,        'psgi.multiprocess' => 1,
        'psgi.run_once' => 0,           'psgi.nonblocking'  => 0,
        'psgi.streaming' => 1,
    };
}

# ---- the layers --------------------------------------------------------------
# Each returns a PSGI coderef. They stack: every one calls the one below.

sub layer_direct { return \&upstream }

# The proxy's own cost, without the network: what Reverse::Proxy's PSGI
# shell does around the forward. The forward itself is a socket round
# trip in production and is deliberately not measured here.
sub layer_proxy {
    my $down = layer_direct();
    return sub {
        my ($env) = @_;
        my $res = $down->($env);
        push @{ $res->[1] }, 'X-Request-Id' => '019fe30e-9143-7991-84ee-b6e2';
        return $res;
    };
}

sub layer_request {
    my $api  = Open::API->new(spec => $SPEC);
    my $down = layer_proxy();
    return sub {
        my ($env) = @_;
        my ($op, $caps) = $api->match($env->{REQUEST_METHOD}, $env->{PATH_INFO});
        if (defined $op) {
            my ($ok, $result) = $api->can('validate_env')
                ? $api->validate_env($op, $env, $caps, undef)
                : $api->validate_request($op, { path => $caps || {},
                                                query => $env->{QUERY_STRING},
                                                header => {} });
        }
        return $down->($env);
    };
}

sub layer_response {
    my ($sample) = @_;
    my $api  = Open::API->new(spec => $SPEC);
    my $down = layer_proxy();
    my $sampler = Maat::Sampler->new(mode => 'fixed', fixed => $sample,
                                     max_body => 1024 * 1024);
    my ($opts, $generation) = (undef, -1);   # the gateway caches these per op
    return sub {
        my ($env) = @_;
        my ($op, $caps) = $api->match($env->{REQUEST_METHOD}, $env->{PATH_INFO});
        my $res;
        if (defined $op) {
            my ($ok, $result) = $api->can('validate_env')
                ? $api->validate_env($op, $env, $caps, undef)
                : $api->validate_request($op, { path => $caps || {},
                                                query => $env->{QUERY_STRING},
                                                header => {} });
            $res = $down->($env);
            # the same idiom as Maat::Gateway::_check_response, field for
            # field: the coverage hash is not built unless the clock says
            # the retune will run, and the options hashref is the
            # sampler's, looked up rather than allocated
            my $now = time;
            if ($now >= $sampler->{next_at}) {
                $sampler->retune($api->response_coverage, $now);
            }
            if (!$opts || $generation != $sampler->{generation}) {
                $opts = $sampler->options($op);
                $generation = $sampler->{generation};
            }
            my $errors = $api->check_response($op, $res, $opts);
            # a violation would be recorded here; the fixture conforms,
            # so what is measured is the check, not the reporting
        }
        else { $res = $down->($env) }
        return $res;
    };
}

my @COLUMNS = (
    [ 'direct to upstream'          => \&layer_direct    ],
    [ '+ Reverse::Proxy'            => \&layer_proxy     ],
    [ '+ request validation'        => \&layer_request   ],
    [ '+ response validation @ 1%'  => sub { layer_response(100) } ],
    [ '+ response validation @ 100%'=> sub { layer_response(1)   } ],
);

# ---- running -----------------------------------------------------------------

sub consume {
    my ($res) = @_;
    return 0 unless ref $res eq 'ARRAY' && ref $res->[2] eq 'ARRAY';
    return length join '', @{ $res->[2] };
}

sub run_one {
    my ($build) = @_;
    pipe my $r, my $w or die $!;
    my $pid = fork // die $!;
    if (!$pid) {
        close $r;
        my $app = $build->();
        consume($app->(env_for()));                  # warm the paths
        my $best;
        for (1 .. $REPS) {
            my $start = Time::HiRes::time();
            consume($app->(env_for())) for 1 .. $ITERS;
            my $secs = Time::HiRes::time() - $start;
            $best = $secs if !defined $best || $secs < $best;
        }
        print {$w} "$best\n";
        close $w;
        exit 0;
    }
    close $w;
    my $line = <$r>;
    waitpid $pid, 0;
    chomp($line = defined $line ? $line : 0);
    return $line ? 1e6 * $line / $ITERS : 0;
}

printf "\n  %d iterations, best of %d, %s\n\n", $ITERS, $REPS, $^V;
printf "  %-32s %10s %10s %10s\n", '', 'us/req', 'vs bare', 'added';
printf "  %-32s %10s %10s %10s\n", '-' x 32, '-' x 10, '-' x 10, '-' x 10;

my ($bare, $proxy);
for my $col (@COLUMNS) {
    my ($label, $build) = @$col;
    my $us = run_one($build);
    $bare  = $us if !defined $bare;
    $proxy = $us if $label eq '+ Reverse::Proxy';
    printf "  %-32s %10.2f %9.0f%% %10s\n", $label, $us,
           $bare ? 100 * $us / $bare : 0,
           defined $proxy && $label =~ /validation/
               ? sprintf('%+.2fus', $us - $proxy) : '';
}

print <<'NOTE';

  `added` is against the proxy row: what validation costs on top of
  forwarding. The 1% row is the product default and the number the
  capacity model uses; the 100% row is the honest ceiling for anyone who
  wants every response weighed.

  The upstream here is a coderef, not a socket. A real round trip is
  hundreds of microseconds and would bury all of this - which is the
  point of measuring it this way round.

NOTE
