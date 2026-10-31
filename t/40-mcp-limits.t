use 5.010;
use strict;
use warnings;
use FindBin ();

use lib "$FindBin::Bin/../../Open-API/blib/lib",
        "$FindBin::Bin/../../Open-API/blib/arch";

use lib "$FindBin::Bin/lib";
use MaatTest;
use RegistryStub;
use Test::More;

use Digest::SHA ();
use File::Temp ();
use File::Raw::JSON ();
use Open::API ();
use Maat;
use Maat::Config ();
use Maat::Gateway ();
use Maat::RateLimit ();

plan skip_all => 'needs Open::API 0.13 (operation_schema)'
    unless Open::API->can('operation_schema');

# Phase 05 - what a tool call costs, and what it may not do.
#
# Three properties, each of which has a way of being quietly wrong:
#
#   - A tool call is BILLED AS A REQUEST, and the tool counter is a subset
#     of that rather than a second meter. Get this wrong in the generous
#     direction and a customer is billed twice for one call.
#   - Listing tools is FREE. A client lists on every session it opens, so a
#     meter that moved here would bill a customer for an agent connecting.
#   - A per-key ceiling applies ACROSS tools. The per-operation limit the
#     gateway already has cannot see this: it buckets by (key, operation),
#     so an agent calling many different cheap tools trips none of them
#     while still hammering the upstream.
#
# Mutations run by hand, 2026-09-13:
#   - Removing the mt_mcp_over_limit call from the tools/call branch failed
#     assertions 12 to 16: the sixth call was answered normally, so there
#     was no 429 and no retry_after, and both counters read 6 rather than
#     5 - the refused call had reached the upstream.
#   - Removing the MT_COUNT(g.counters, "mcp") line failed 2, 4, 7 and 15,
#     every tool-counter assertion, while every `request` assertion stayed
#     green. That is exactly the split those pairs exist to hold apart: if
#     one counter could silently stand in for the other, a customer could
#     be billed twice for one call and nothing here would notice.
#   Both restored, the object rebuilt from a clean .o, the file green again.

my $MAIN = $$;

# Two upstreams: the echo, and one that answers with more than a model can
# be given. An orphan holds the TAP pipe open and hangs the harness, so
# both are reaped whatever happens, and only by the parent.
my $up  = start_upstream();
my $big = start_upstream(respond => sub {
    return (200, ['Content-Type' => 'text/plain'], 'x' x 300_000);
});
END {
    if (defined $MAIN && $$ == $MAIN) {
        stop_upstream($_) for grep { $_ } ($up, $big);
    }
}

sub decode { File::Raw::JSON::file_json_decode($_[0]) }
sub encode { File::Raw::JSON::file_json_encode($_[0], sort_keys => 1) }

sub endpoint {
    my (%o) = @_;
    my $api = Open::API->new(spec => RegistryStub->secured_spec(1));
    my $gw  = Maat::Gateway->new(
        config => Maat::Config->tenant(
            mode     => 'observe',
            upstream => "http://127.0.0.1:" . ($o{port} || $up->{port})),
        api => $api,
        ($o{ratelimit} ? (ratelimit => $o{ratelimit}) : ()),
    );
    my $mcp = Maat::MCP->new(
        api => $api, gw => $gw, host => 'a.example', version => '1');
    return ($mcp, $gw);
}

sub rpc {
    my (%o) = @_;
    my $env = MaatTest::psgi_env(
        method       => 'POST',
        path         => '/mcp',
        body         => encode($o{message}),
        content_type => 'application/json');
    $env->{HTTP_ACCEPT} = 'application/json';
    $env->{HTTP_AUTHORIZATION} = $o{auth} if defined $o{auth};
    $env->{'maat.keys'}        = $o{keys} if defined $o{keys};
    my ($s, $h, $b) =
        MaatTest::run_app(sub { Maat::MCP::_serve($o{mcp}, $_[0]) }, $env);
    return ($s, decode($b));
}

sub tool_call {
    my (%o) = @_;
    return rpc(%o, message => {
        jsonrpc => '2.0', id => $o{id} || 1, method => 'tools/call',
        params  => { name => $o{name}, arguments => $o{arguments} || {} } });
}

# ---- a tool call is a request, and listing tools is free --------------------

{
    my ($mcp, $gw) = endpoint();

    tool_call(mcp => $mcp, name => 'public1', id => $_) for 1 .. 100;

    is $gw->counters->{request}, 100,
        '100 tool calls are 100 requests: the meter a customer is billed on';
    is $gw->counters->{mcp}, 100,
        '...and 100 tool calls, which is the SUBSET of them an agent made';

    rpc(mcp => $mcp, message => {
        jsonrpc => '2.0', id => 200 + $_, method => 'tools/list' })
        for 1 .. 100;

    is $gw->counters->{request}, 100,
        '100 tools/list add nothing to the bill';
    is $gw->counters->{mcp}, 100,
        '...and nothing to the tool count either';

    # Both totals ride in ONE entry. usage_hours is UNIQUE (proxy, hour,
    # gateway) and the control plane REPLACES the row, so an entry
    # carrying one column without the other would zero the other for that
    # hour - a partial payload is a wrong bill, not a missing field.
    my $usage = $gw->usage;
    ok $usage && @$usage, 'the hour is offered for shipping';
    is $usage->[0]{requests}, 100, '...carrying the request total';
    is $usage->[0]{mcp}, 100, '...and the tool total, in the same entry';
}

# ---- what goes back to the model is bounded --------------------------------

{
    my ($mcp) = endpoint(port => $big->{port});

    my (undef, $r) = tool_call(mcp => $mcp, name => 'public1');
    my $text = $r->{result}{content}[0]{text};

    is length($text), 262144 + length("\n... truncated"),
        'a 300KB body reaches the model as 256KB plus the marker';
    like $text, qr/\n\.\.\. truncated\z/,
        '...and the text ENDS with the marker, so a model reading to the '
      . 'end learns it was cut rather than trusting a clean stop';
    ok $r->{result}{_meta}{truncated},
        '...with _meta.truncated, so a client knows without parsing text';
}

# ---- one bucket across every tool ------------------------------------------

{
    # rate_per_min 0 turns the PER-OPERATION limit off entirely, which is
    # the point: with it off, anything that refuses the sixth call can
    # only be the MCP-only ceiling. The key carries its own small ceiling
    # so the test does not have to make 300 calls to reach the default.
    my $secret = 'k_' . ('a' x 30);
    my $key = { id => 7, hash => Digest::SHA::sha256_hex($secret),
                prefix => substr($secret, 0, 8),
                rate_per_min => 0, mcp_calls_per_min => 5 };

    my $dir = File::Temp::tempdir('maat-mcp-rl-XXXXXX', TMPDIR => 1,
                                  CLEANUP => 1);
    my ($mcp, $gw) = endpoint(ratelimit => Maat::RateLimit->new(dir => $dir));

    # Alternating tools, so a per-operation bucket would see three of each
    # and refuse nothing. One bucket for the key sees six.
    my @names = qw(public1 secure1 public1 secure1 public1 secure1);
    my @errors;
    my $last;
    for my $i (0 .. 5) {
        my (undef, $r) = tool_call(
            mcp => $mcp, name => $names[$i], id => 300 + $i,
            auth => "Bearer $secret", keys => [$key]);
        push @errors, ($r->{result}{isError} ? 1 : 0);
        $last = $r;
    }

    is_deeply [ @errors[0 .. 4] ], [ 0, 0, 0, 0, 0 ],
        'five tool calls across two different tools are answered';
    ok $errors[5],
        'the sixth is refused, though no single tool was called six times';
    is $last->{result}{_meta}{status}, 429,
        '...as a rate limit';
    ok defined $last->{result}{_meta}{retry_after},
        '...telling the model how long to wait, so it does not spin';

    is $gw->counters->{mcp}, 5,
        'a refused call is not billed as a tool call';
    is $gw->counters->{request}, 5,
        '...and never became a request, so it cost the upstream nothing';
}

# ---- tools/list is paged ---------------------------------------------------

{
    # 120 operations. A document this size is a real customer, and one
    # response carrying 120 schemas is the thing paging exists to avoid.
    # Single-quoted: the JSON is full of braces, and a qq{} would have to
    # balance every one of them.
    my $tmpl = '"/op%d": { "get": { "operationId": "op%d", "responses": '
             . '{ "200": { "description": "ok", "content": '
             . '{ "application/json": { "schema": { "type": "object" } } '
             . '} } } } }';
    my @paths = map { sprintf $tmpl, $_, $_ } 1 .. 120;

    my $api = Open::API->new(spec =>
        '{ "openapi": "3.1.0", "info": { "title": "Wide", "version": "1" },'
      . ' "paths": { ' . join(',', @paths) . ' } }');
    my $gw  = Maat::Gateway->new(
        config => Maat::Config->tenant(
            mode => 'observe', upstream => "http://127.0.0.1:$up->{port}"),
        api => $api);
    my $mcp = Maat::MCP->new(
        api => $api, gw => $gw, host => 'wide.example', version => '1');

    my $list = sub {
        my ($id, $cursor) = @_;
        my (undef, $r) = rpc(mcp => $mcp, message => {
            jsonrpc => '2.0', id => $id, method => 'tools/list',
            (defined $cursor ? (params => { cursor => $cursor }) : ()) });
        return $r;
    };

    my $p0 = $list->(1);
    is scalar @{ $p0->{result}{tools} }, 50,
        'the first page carries 50 tools, not all 120';
    is $p0->{result}{nextCursor}, '1', '...and a cursor to the next';

    my $p1 = $list->(2, $p0->{result}{nextCursor});
    is scalar @{ $p1->{result}{tools} }, 50, 'the second page carries 50';

    my $p2 = $list->(3, $p1->{result}{nextCursor});
    is scalar @{ $p2->{result}{tools} }, 20, 'the last carries the remainder';
    ok !exists $p2->{result}{nextCursor},
        '...and no cursor at all, which is how a client knows it has them all';

    my %seen;
    $seen{ $_->{name} }++ for map { @{ $_->{result}{tools} } } $p0, $p1, $p2;
    is scalar keys %seen, 120, 'every tool is somewhere in the pages';
    is scalar(grep { $_ != 1 } values %seen), 0,
        '...exactly once, so paging neither drops a tool nor repeats one';

    # A cursor is this server's own token. One it never issued is a client
    # inventing state, and guessing a page for it would quietly answer
    # with the wrong tools.
    is $list->(4, '99')->{error}{code}, -32602,
        'a cursor this server never issued is refused';
    is $list->(5, 'not-a-page')->{error}{code}, -32602,
        '...and so is one that is not a page number at all';
}

done_testing;
