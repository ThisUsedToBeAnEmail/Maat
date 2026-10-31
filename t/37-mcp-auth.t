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
use File::Raw::JSON ();
use Open::API ();
use Maat;
use Maat::Config ();
use Maat::Gateway ();

plan skip_all => 'needs Open::API 0.13 (operation_schema)'
    unless Open::API->can('operation_schema');
plan skip_all => 'needs Crypt::JWS with its C ABI'
    unless eval { require Crypt::JWS; Crypt::JWS->can('_abi_ptr') };

# Phase 03A - who may call an agent endpoint.
#
# The tenant's own API keys are the credential. The point of doing it this way
# rather than inventing an MCP-shaped auth: a tool call ends up carrying the
# SAME resolved key an ordinary request carries, so the rate limit, the
# metering and the per-key attribution a customer already pays for apply to
# agents without a second code path to keep honest.
#
# The assertion that earns this file: a tools/call on an operation the
# document GUARDS succeeds without the document's own credential, because the
# endpoint already authenticated the caller and says so. If that skip were
# wrong in either direction the test below fails - too strict and the guarded
# call is refused, too loose and an unauthenticated caller reaches it.

my $MAIN = $$;
my $up   = start_upstream();
END { stop_upstream($up) if $up && $$ == $MAIN }

sub decode { File::Raw::JSON::file_json_decode($_[0]) }
sub encode { File::Raw::JSON::file_json_encode($_[0], sort_keys => 1) }

sub key_for {
    my ($secret, %o) = @_;
    return { id           => $o{id} || 7,
             hash         => Digest::SHA::sha256_hex($secret),
             prefix       => substr($secret, 0, 8),
             rate_per_min => 0,
             (exists $o{scopes} ? (scopes => $o{scopes}) : ()) };
}

# An endpoint over the secured document: /secure is guarded by an ApiKey
# scheme, /public is not.
sub endpoint {
    my (%o) = @_;
    my $api = Open::API->new(spec => RegistryStub->secured_spec(1));
    my $gw  = Maat::Gateway->new(
        config => Maat::Config->tenant(
            mode => 'observe', upstream => "http://127.0.0.1:$up->{port}"),
        api => $api);
    my $mcp = Maat::MCP->new(
        api  => $api, gw => $gw,
        host => $o{host} || 'a.example', version => '1',
        ($o{mcp} ? (mcp => $o{mcp}) : ()));
    return ($mcp, $gw);
}

sub call {
    my (%o) = @_;
    my $env = MaatTest::psgi_env(
        method => $o{method} || 'POST',
        path   => defined $o{path} ? $o{path} : '/mcp',
        (defined $o{body} ? (body => $o{body}) : ()),
    );
    $env->{HTTP_ACCEPT} = 'application/json';
    $env->{HTTP_AUTHORIZATION} = $o{auth}  if defined $o{auth};
    $env->{'maat.keys'}        = $o{keys}  if defined $o{keys};
    return MaatTest::run_app(sub { Maat::MCP::_serve($o{mcp}, $_[0]) }, $env);
}

sub rpc_body {
    my ($method, $params, $id) = @_;
    return encode({ jsonrpc => '2.0', method => $method,
                    id => defined $id ? $id : 1,
                    ($params ? (params => $params) : ()) });
}

my $SECRET = 'apip_live_alpha_secret';
my $LIST   = rpc_body('tools/list');

# ---- a tenant that publishes keys demands one ------------------------------

{
    my ($mcp) = endpoint();
    my $keys = [ key_for($SECRET) ];

    my ($s, $h) = call(mcp => $mcp, keys => $keys, body => $LIST);
    is $s, 401, 'no credential, and the tenant has keys: 401';

    # Byte-exact: this header is how a client discovers where to authenticate,
    # so a word changing in it is a client that stops working.
    is scalar MaatTest::header_get($h, 'WWW-Authenticate'),
       'Bearer realm="apip", resource_metadata='
     . '"https://a.example/.well-known/oauth-protected-resource"',
       '...challenging with the realm and the metadata URL, word for word';

    ($s) = call(mcp => $mcp, keys => $keys, body => $LIST,
                auth => 'Bearer apip_not_the_right_secret');
    is $s, 401, 'a credential that matches nothing: 401';

    ($s) = call(mcp => $mcp, keys => $keys, body => $LIST, auth => $SECRET);
    is $s, 401, 'a bare secret with no scheme is not a bearer token';

    my $b;
    ($s, $h, $b) = call(mcp => $mcp, keys => $keys, body => $LIST,
                        auth => "Bearer $SECRET");
    is $s, 200, 'the tenant"s own key is admitted';
    is scalar @{ decode($b)->{result}{tools} }, 2, '...and served its tools';

    ($s) = call(mcp => $mcp, keys => $keys, body => $LIST,
                auth => "bearer $SECRET");
    is $s, 200, 'the scheme is case-insensitive, as RFC 9110 says it is';
}

# ---- scopes ----------------------------------------------------------------

{
    my ($mcp) = endpoint();

    my ($s) = call(mcp => $mcp, body => $LIST, auth => "Bearer $SECRET",
                   keys => [ key_for($SECRET, scopes => ['read']) ]);
    is $s, 403, 'a key without the mcp scope is authenticated but refused';

    ($s) = call(mcp => $mcp, body => $LIST, auth => "Bearer $SECRET",
                keys => [ key_for($SECRET, scopes => ['read', 'mcp']) ]);
    is $s, 200, 'a key carrying mcp among its scopes is admitted';

    ($s) = call(mcp => $mcp, body => $LIST, auth => "Bearer $SECRET",
                keys => [ key_for($SECRET, scopes => []) ]);
    is $s, 200, 'a key with no scopes at all keeps the existing "no scopes '
              . 'means every scope" rule, so keys issued before mcp existed '
              . 'still work';
}

# ---- one tenant's key is not another's -------------------------------------

{
    my ($a) = endpoint(host => 'a.example');
    my ($b) = endpoint(host => 'b.example');

    my $akeys = [ key_for($SECRET, id => 1) ];
    my $bkeys = [ key_for('apip_live_beta_secret', id => 2) ];

    is scalar((call(mcp => $a, keys => $akeys, body => $LIST,
                    auth => "Bearer $SECRET"))[0]), 200,
       'the key works at its own tenant';

    is scalar((call(mcp => $b, keys => $bkeys, body => $LIST,
                    auth => "Bearer $SECRET"))[0]), 401,
       'and the same key is nobody at the neighbour, because the neighbour '
     . 'publishes different hashes';
}

# ---- a tenant with no keys is not locked out -------------------------------

{
    my ($mcp) = endpoint();
    my ($s) = call(mcp => $mcp, body => $LIST);
    is $s, 200, 'a tenant that publishes no keys is open, the same stance the '
              . 'API path takes, so a republish that drops the last key is '
              . 'not an outage';
}

# ---- THE POINT: an authenticated call reaches a GUARDED operation ----------

{
    my ($mcp, $gw) = endpoint();
    my $keys = [ key_for($SECRET) ];
    my $before = $gw->violation->counters->{request} || 0;

    # /secure carries `security: [{ApiKey: []}]`, and the synthetic request
    # carries no X-API-Key - it cannot, because the gateway stores key hashes
    # and never the secret. It succeeds because the endpoint already resolved
    # the caller and _authorize trusts that rather than re-checking.
    my ($s, $h, $b) = call(mcp => $mcp, keys => $keys,
        auth => "Bearer $SECRET",
        body => rpc_body('tools/call', { name => 'secure1', arguments => {} }, 9));

    is $s, 200, 'a tool call on a guarded operation answers';
    my $r = decode($b);
    ok !$r->{error}, '...and was not refused as unauthorized';
    is $r->{result}{_meta}{status}, 200, '...reporting the upstream status';
    like $r->{result}{content}[0]{text}, qr{^target=/secure$}m,
       '...having actually reached the upstream';

    is(($gw->violation->counters->{request} || 0) - $before, 1,
       'and it was metered as one request, like any other');
}

# ---- the metadata document names an authorization server only if there is one

{
    my ($plain) = endpoint();
    my (undef, undef, $pb) = call(mcp => $plain, method => 'GET',
        path => '/.well-known/oauth-protected-resource');
    ok !exists decode($pb)->{authorization_servers},
       'a keys-only tenant names no authorization server';

    my ($oauth) = endpoint(mcp => { enabled => 1, oauth => 1 });
    my (undef, undef, $ob) = call(mcp => $oauth, method => 'GET',
        path => '/.well-known/oauth-protected-resource');
    is_deeply decode($ob)->{authorization_servers},
       ['https://openapi-proxy.com/oauth'],
       'a tenant with OAuth on names the default authorization server';

    my ($custom) = endpoint(mcp => { enabled => 1, oauth => 1,
                                     issuer => 'https://id.example/oauth' });
    my (undef, undef, $cb) = call(mcp => $custom, method => 'GET',
        path => '/.well-known/oauth-protected-resource');
    is_deeply decode($cb)->{authorization_servers}, ['https://id.example/oauth'],
       '...or the issuer it was configured with';
}

done_testing;
