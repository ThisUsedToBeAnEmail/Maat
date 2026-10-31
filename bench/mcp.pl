#!/usr/bin/env perl
use 5.010;
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../blib/arch";
use lib "$FindBin::Bin/../blib/lib";
use lib "$FindBin::Bin/../t/lib";
use lib "$FindBin::Bin/../lib";
use MaatTest;                 # puts the sibling blibs on @INC
use RegistryStub;
use Maat::Registry;
use Maat::Poller;
use Maat::Router;
use File::Raw::JSON ();
use Time::HiRes ();

# What the agent endpoint costs.
#
# Two questions, and they are not the same question:
#
#   1. Does turning MCP ON slow the API path down? It must not. The API
#      path gains one flag test in the dispatcher and nothing else, and a
#      customer who never points an agent at their proxy should not pay
#      for the feature existing. This is the row that would catch it if
#      they did.
#   2. What does a tool call cost over the same request made directly?
#      JSON-RPC framing, argument validation against the tool's compiled
#      schema, and synthesising an environment - then an ordinary request
#      happens. That difference is the toll, and it is the number to
#      quote when somebody asks what the MCP layer adds.
#
# Mock-mode tenants, for bench/fleet.pl's reason: a mock answers from the
# document in C with no upstream and no future, so what separates the
# rows is the thing being measured rather than a socket.
#
# Run:  perl bench/mcp.pl [iterations] [reps]
# and transcribe the block into bench/RESULTS.md, naming the machine.

my $ITERS = defined $ARGV[0] ? $ARGV[0] + 0 : 50_000;
my $REPS  = defined $ARGV[1] ? $ARGV[1] + 0 : 7;

my $HOST = 'a.openapi-proxy.com';

# ---- a one-tenant fleet, with the endpoint on or off ------------------------

sub fleet {
    my ($mcp_on) = @_;
    my $stub = RegistryStub->new(token => 'bench-token');
    $stub->add_tenant(host => $HOST, proxy => 1, plan => 'team',
                      spec => RegistryStub->tenant_spec(1));
    $stub->{tenants}[0]{mcp} = { enabled => 1, ops => [], oauth => 0 }
        if $mcp_on;

    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    Maat::Poller->new(registry => $reg, url => 'http://bench/registry/bundle',
        token => 'bench-token', fetch => $stub->fetcher)->poll_once eq 'applied'
        or die "bench: the bundle did not apply\n";
    return Maat::Router->new(registry => $reg)->to_app;
}

# ---- the two requests -------------------------------------------------------

sub api_env {
    my $env = MaatTest::psgi_env(path => '/hello');
    $env->{HTTP_HOST} = $HOST;
    return $env;
}

sub tool_env {
    my $body = File::Raw::JSON::file_json_encode({
        jsonrpc => '2.0', id => 1, method => 'tools/call',
        params  => { name => 'hello1', arguments => {} } });
    my $env = MaatTest::psgi_env(method => 'POST', path => '/mcp',
        body => $body, content_type => 'application/json');
    $env->{HTTP_HOST}   = $HOST;
    $env->{HTTP_ACCEPT} = 'application/json';
    return $env;
}

# The body is read through psgi.input, so the handle has to go back to
# the start before each call or every iteration after the first measures
# an empty body. Both rows rewind, so the seek is in both or neither.
sub call {
    my ($app, $env) = @_;
    seek $env->{'psgi.input'}, 0, 0;
    return $app->($env);
}

# ---- the clock, bench/fleet.pl's ---------------------------------------------

sub rate {
    my ($label, $code) = @_;
    my $best;
    for (1 .. $REPS) {
        my $t0 = Time::HiRes::time();
        $code->() for 1 .. $ITERS;
        my $dt = Time::HiRes::time() - $t0;
        $best = $dt if !defined $best || $dt < $best;
    }
    printf "  %-36s %8.0f req/s   %7.3f us/req\n",
        $label, $ITERS / $best, $best / $ITERS * 1e6;
    return $best / $ITERS * 1e6;
}

# ---- prove each row answers before timing it --------------------------------

my $off = fleet(0);
my $on  = fleet(1);

my ($api_env, $tool_env) = (api_env(), tool_env());

for my $case ([ 'MCP off, API path', $off, $api_env, 200 ],
              [ 'MCP on,  API path', $on,  $api_env, 200 ],
              [ 'MCP on,  tool call', $on, $tool_env, 200 ]) {
    my ($what, $app, $env, $want) = @$case;
    my ($s) = MaatTest::run_app($app, do { seek $env->{'psgi.input'}, 0, 0; $env });
    die "bench: $what answered $s, wanted $want\n" unless $s == $want;
}

# And that the tool call really reached the operation, rather than
# answering quickly with an error that would make the toll look small.
{
    seek $tool_env->{'psgi.input'}, 0, 0;
    my (undef, undef, $b) = MaatTest::run_app($on, $tool_env);
    my $r = File::Raw::JSON::file_json_decode($b);
    die "bench: the tool call was an error, not a result\n"
        unless $r->{result} && !$r->{result}{isError};
}

printf "\nthe agent endpoint - 1 tenant, %d iterations, best of %d, %s\n\n",
    $ITERS, $REPS, $^V;

my $cold = rate('API path, MCP off',        sub { call($off, $api_env) });
my $warm = rate('API path, MCP on',         sub { call($on,  $api_env) });
my $tool = rate('the same operation, as a tool', sub { call($on, $tool_env) });

# Judged as a proportion of the path, not as an absolute: run to run this
# measurement moves by a few percent, and a fixed microsecond threshold
# would report that as a regression. A NEGATIVE delta is proof of noise
# rather than of a win - one flag test cannot make the path faster - so
# the band is two-sided and the same width either way.
{
    my $delta = $warm - $cold;
    my $pct   = $cold ? $delta / $cold * 100 : 0;
    printf "\n  the flag test: %+.3f us/req (%+.1f%%) on the API path\n",
        $delta, $pct;
    printf "  %s\n", abs($pct) < 5
        ? 'within noise: turning MCP on does not move the API path.'
        : 'LOOK AT THIS: the API path moved by more than this bench can '
        . 'explain.';
}
printf "\n  the tool toll: %+.2f us/req over the same request made directly\n",
    $tool - $warm;
printf "  (JSON-RPC decode, argument validation, env synthesis, encode)\n";
printf "\n  A real forward is hundreds of microseconds. This is what MCP\n";
printf "  adds on top of a request that then happens exactly as it always\n";
printf "  did, which is the only honest way to quote it.\n\n";
