use 5.010;
use strict;
use warnings;
use FindBin ();

# operation_schema / operation_doc arrived in Open::API 0.13; prefer a sibling
# checkout the way the other cross-dist tests do. Inert with 0.13 installed.
use lib "$FindBin::Bin/../../Open-API/blib/lib",
        "$FindBin::Bin/../../Open-API/blib/arch";

use lib "$FindBin::Bin/lib";
use MaatTest;
use RegistryStub;
use Test::More;

use File::Raw::JSON ();
use Open::API ();
use Maat;
use Maat::Config ();
use Maat::Gateway ();

plan skip_all => 'needs Open::API 0.13 (operation_schema)'
    unless Open::API->can('operation_schema');

# The MCP endpoint (include/mt_mcp.h), driven as a client drives it.
#
# The property worth more than any single assertion here: a tools/call is a
# REQUEST THROUGH THE GATEWAY. It is matched, validated, metered and forwarded
# by mt_serve, the same C entry a customer's own client reaches - so the
# upstream sees a request it cannot tell from one, and the counters move. The
# echo upstream is what lets that be asserted rather than asserted about.
#
# Mutations run by hand (phase 02's two lines), 2026-09-12:
#   - Disabling the argument validation in mt_mcp_dispatch failed exactly four
#     assertions: the three -32602 ones and the one saying a refused call never
#     reached the gateway. A bad call reached the upstream instead.
#   - Dropping the array-repeat branch in mt_mcp_call failed exactly one, "an
#     array argument repeats the key"; the arrayref went out stringified.
# Both restored, the header verified byte-identical, the file green again.

my $MAIN = $$;
my $up   = start_upstream();

# If anything below dies, the upstream must still be reaped. An orphaned
# child holds the TAP pipe open, so the harness hangs for ever instead of
# reporting the failure. Guarded on the pid so the child never runs it.
END { stop_upstream($up) if $up && $$ == $MAIN }

my $api = Open::API->new(spec => RegistryStub->portal_spec(1));
my $gw  = Maat::Gateway->new(
    config => Maat::Config->tenant(
        mode     => 'observe',
        upstream => "http://127.0.0.1:$up->{port}",
    ),
    api => $api,
);
my $mcp = Maat::MCP->new(
    api => $api, gw => $gw, host => 'acme.example', version => '3.2.1');
my $app = sub { Maat::MCP::_serve($mcp, $_[0]) };

sub decode { File::Raw::JSON::file_json_decode($_[0]) }
sub encode { File::Raw::JSON::file_json_encode($_[0], sort_keys => 1) }

# A JSON-RPC call, through the endpoint.
sub rpc {
    my (%o) = @_;
    my $env = MaatTest::psgi_env(
        method => $o{method} || 'POST',
        path   => defined $o{path} ? $o{path} : '/mcp',
        (defined $o{body} ? (body => $o{body}) : ()),
    );
    $env->{HTTP_ACCEPT} = defined $o{accept} ? $o{accept} : 'application/json';
    $env->{HTTP_ORIGIN} = $o{origin} if defined $o{origin};
    $env->{HTTP_MCP_PROTOCOL_VERSION} = $o{proto} if defined $o{proto};
    delete $env->{HTTP_ACCEPT} if exists $o{accept} && !defined $o{accept};
    return MaatTest::run_app($app, $env);
}

sub call {
    my ($method, $params, $id) = @_;
    my %m = (jsonrpc => '2.0', method => $method);
    $m{id}     = $id     if defined $id;
    $m{params} = $params if defined $params;
    my ($s, $h, $b) = rpc(body => encode(\%m));
    return ($s, $b ? decode($b) : undef);
}

# ---- the transport's refusals ----------------------------------------------

{
    my ($s, $h) = rpc(method => 'GET');
    is $s, 405, 'GET is refused: this endpoint opens no stream';
    is MaatTest::header_get($h, 'Allow'), 'POST', '...and says what it takes';

    ($s) = rpc(method => 'DELETE');
    is $s, 405, 'DELETE is refused: there is no session to end';

    ($s) = rpc(origin => 'https://evil.example', body => '{}');
    is $s, 403, 'a cross-origin request is refused before anything is read';

    ($s) = rpc(accept => 'text/html', body => '{}');
    is $s, 406, 'a client that will not take JSON is refused';

    ($s) = rpc(proto => '1999-01-01', body => '{}');
    is $s, 400, 'an unsupported protocol version is refused';

    # RFC 9728 discovery. Public on purpose: it is what tells a client how to
    # authenticate, so putting it behind authentication would be a loop.
    my ($ms, $mh, $mb) = rpc(method => 'GET',
        path => '/.well-known/oauth-protected-resource');
    is $ms, 200, 'the protected-resource metadata is served';

    my $meta = decode($mb);
    is $meta->{resource}, 'https://acme.example/mcp',
       '...naming this endpoint as the canonical resource, not the host';
    is_deeply $meta->{scopes_supported}, ['mcp'], '...with the scope it wants';
    is_deeply $meta->{bearer_methods_supported}, ['header'],
       '...presented in a header';
    ok !exists $meta->{authorization_servers},
       'a keys-only tenant advertises no authorization server to try';

    ($ms) = rpc(method => 'POST', body => '{}',
                path => '/.well-known/oauth-protected-resource');
    is $ms, 405, 'and the document is read-only';
}

# ---- JSON-RPC framing -------------------------------------------------------

{
    my ($s, $h, $b) = rpc(body => 'not json at all');
    is $s, 400, 'a body that is not JSON is a 400';
    my $r = decode($b);
    is $r->{error}{code}, -32700, '...carrying a parse error';
    ok !defined $r->{id}, '...with a null id, because there was none to echo';

    ($s, $h, $b) = rpc(body => '[{"jsonrpc":"2.0","method":"ping","id":1}]');
    is $s, 400, 'a batch is refused';
    is decode($b)->{error}{code}, -32600, '...as an invalid request';

    ($s, $h, $b) = rpc(body => '{"method":"ping","id":1}');
    is $s, 400, 'a message without jsonrpc 2.0 is refused';
    is decode($b)->{error}{code}, -32600, '...as an invalid request';

    ($s) = rpc(body => encode({ jsonrpc => '2.0', method => 'notifications/initialized' }));
    is $s, 202, 'a notification is accepted and owed nothing';
}

# ---- the methods ------------------------------------------------------------

{
    my ($s, $r) = call('initialize',
        { protocolVersion => '2025-06-18', capabilities => {} }, 1);
    is $s, 200, 'initialize answers';
    is $r->{result}{protocolVersion}, '2025-06-18', 'at the version asked for';
    ok exists $r->{result}{capabilities}{tools}, 'declaring tools';
    is $r->{result}{serverInfo}{name}, 'apip', 'and naming itself';
    is $r->{result}{serverInfo}{title}, 'Pets 1', '...with the document title';

    ($s, $r) = call('initialize', { protocolVersion => '2025-03-26' }, 2);
    is $r->{result}{protocolVersion}, '2025-03-26',
        'a client on the prior version is met there';

    ($s, $r) = call('ping', undef, 3);
    is $s, 200, 'ping answers';
    is_deeply $r->{result}, {}, 'with nothing to say';

    ($s, $r) = call('no/such/method', undef, 4);
    is $r->{error}{code}, -32601, 'an unknown method is method-not-found';
}

# ---- tools/list -------------------------------------------------------------

{
    my ($s, $r) = call('tools/list', undef, 'a-string-id');
    is $s, 200, 'tools/list answers';
    is $r->{id}, 'a-string-id', 'echoing a string id as a string';
    is scalar @{ $r->{result}{tools} }, 2, 'with both operations as tools';
    my %by = map { $_->{name} => $_ } @{ $r->{result}{tools} };
    ok $by{getpet1}, 'the tool is there under its derived name';
    ok $by{getpet1}{inputSchema}{properties}{petId}, 'carrying its input schema';
    is $by{getpet1}{annotations}{readOnlyHint}, 1, 'and its annotations';
}

# ---- tools/call, which is a request through the gateway ---------------------

{
    my $before = $gw->violation->counters->{request} || 0;

    my ($s, $r) = call('tools/call',
        { name => 'getpet1', arguments => { petId => 7 } }, 10);
    is $s, 200, 'a tool call answers';
    ok !$r->{result}{isError}, 'and did not error';
    is $r->{result}{_meta}{status}, 200, 'reporting the upstream status';

    # THE ASSERTION THIS FILE EXISTS FOR: the upstream saw a real request,
    # built from the tool's arguments at the path the document declares.
    my $text = $r->{result}{content}[0]{text};
    like $text, qr{^method=GET$}m, 'the upstream saw the right method';
    like $text, qr{^target=/pets/7$}m,
        'and the path parameter reached it in the right place';

    my $after = $gw->violation->counters->{request} || 0;
    is $after - $before, 1, 'and the call moved the request counter exactly once';

    # Which is what the control plane bills from: a tool call has to reach
    # the usage buckets the shipper drains, not just a counter in memory.
    my $usage = $gw->usage;
    ok $usage && @$usage, 'the call appears in usage()';
    ok((grep { $_->{requests} >= 1 } @$usage), '...as a request in its hour');
}

# A call that fails validation must never reach the upstream, and must cost
# nothing: a model gets a protocol error it can correct instead of a 400 from
# an API whose document it cannot read.
{
    my $before = $gw->violation->counters->{request} || 0;

    my ($s, $r) = call('tools/call',
        { name => 'getpet1', arguments => { petId => 'not-an-integer' } }, 11);
    is $r->{error}{code}, -32602, 'a wrong argument type is invalid params';
    ok $r->{error}{data}{errors}, '...saying which';

    ($s, $r) = call('tools/call', { name => 'getpet1', arguments => {} }, 12);
    is $r->{error}{code}, -32602, 'a missing required argument likewise';

    is(($gw->violation->counters->{request} || 0) - $before, 0,
       'and neither reached the gateway at all');
}

# ---- a query argument that is an array --------------------------------------
#
# Repeating the key (tag=a&tag=b) is what the client half of this stack emits
# for the same value. No shipped fixture has a query parameter at all, so this
# document exists to exercise the encoding rather than leave it asserted about.
{
    my $qapi = Open::API->new(spec => {
        openapi => '3.1.0',
        info    => { title => 'Q', version => '1.0.0' },
        paths   => { '/pets' => { get => {
            operationId => 'searchPets',
            parameters  => [
                { name => 'tag', in => 'query',
                  schema => { type => 'array', items => { type => 'string' } } },
                { name => 'limit', in => 'query',
                  schema => { type => 'integer' } },
            ],
            responses => { 200 => { description => 'ok' } },
        } } },
    });
    my $qgw = Maat::Gateway->new(
        config => Maat::Config->tenant(
            mode => 'observe', upstream => "http://127.0.0.1:$up->{port}"),
        api => $qapi);
    my $qmcp = Maat::MCP->new(api => $qapi, gw => $qgw,
                              host => 'acme.example', version => '1');

    my $env = MaatTest::psgi_env(method => 'POST', path => '/mcp',
        body => encode({
            jsonrpc => '2.0', id => 20, method => 'tools/call',
            params  => { name      => 'searchpets',
                         arguments => { tag => ['a', 'b'], limit => 5 } } }));
    $env->{HTTP_ACCEPT} = 'application/json';
    my ($s, $h, $b) =
        MaatTest::run_app(sub { Maat::MCP::_serve($qmcp, $_[0]) }, $env);

    is $s, 200, 'a call with an array query argument answers';
    my $text = decode($b)->{result}{content}[0]{text};
    like $text, qr{^target=/pets\?}m, 'the upstream saw a query string';
    like $text, qr{tag=a&tag=b}, 'an array argument repeats the key';
    like $text, qr{limit=5}, 'and a scalar argument appears once';
}

{
    my ($s, $r) = call('tools/call', { name => 'nosuchtool' }, 13);
    is $r->{error}{code}, -32602, 'an unknown tool is invalid params';

    ($s, $r) = call('tools/call', {}, 14);
    is $r->{error}{code}, -32602, 'so is a call naming no tool';
}

# ---- the refusal bytes, written down ----------------------------------------
#
# t/30-edge.t's convention, applied here: a refusal body is a public interface,
# a client parses it, and the only way to notice a word changing is to have
# written the word down. They live in this file rather than in t/30 because the
# MCP endpoint is not the edge, and t/30 must not grow a dependency on
# Open::API 0.13 to reach them.
{
    my (undef, undef, $b) = rpc(body => 'not json at all');
    is $b, '{"error":{"code":-32700,"message":"parse error"},"id":null,'
         . '"jsonrpc":"2.0"}',
       'the parse error, byte for byte';

    (undef, undef, $b) = rpc(body => '[{"jsonrpc":"2.0","method":"ping","id":1}]');
    is $b, '{"error":{"code":-32600,"message":"batches are not supported"},'
         . '"id":null,"jsonrpc":"2.0"}',
       'the batch refusal, byte for byte';

    (undef, undef, $b) = rpc(body => '{"method":"ping","id":1}');
    is $b, '{"error":{"code":-32600,"message":"invalid request"},"id":1,'
         . '"jsonrpc":"2.0"}',
       'the invalid request, byte for byte, echoing the id it was handed';

    (undef, undef, $b) = rpc(body =>
        encode({ jsonrpc => '2.0', method => 'nope', id => 4 }));
    is $b, '{"error":{"code":-32601,"message":"method not found"},"id":4,'
         . '"jsonrpc":"2.0"}',
       'the unknown method, byte for byte';
}

# ---- the body ceiling -------------------------------------------------------

{
    my ($s) = rpc(body => '{"jsonrpc":"2.0","method":"ping","id":1,"pad":"'
                        . ('x' x (1024 * 1024 + 16)) . '"}');
    is $s, 413, 'an envelope past the ceiling is refused before it is decoded';
}

done_testing;
