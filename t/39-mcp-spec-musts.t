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

# The MUSTs, named.
#
# Phase 03's acceptance asks that every MUST in the authorization spec which
# applies to a resource server has a test NAMING it. The behaviours are
# largely covered across t/36 to t/38, but covered is not the same as named:
# a requirement nobody can point at is one nobody notices losing. So this
# file restates each one in the words of the specification and asserts it
# directly, and it is deliberately the only place that does.
#
# From the 2025-06-18 authorization specification, for an MCP server acting
# as an OAuth 2.1 resource server:
#
#   1. MUST serve RFC 9728 protected resource metadata.
#   2. MUST point at that metadata from WWW-Authenticate on a 401.
#   3. MUST validate that the token's audience is this server.
#   4. MUST NOT pass the client's token upstream.
#
# And from the transport section, which applies whether or not authorization
# is in use:
#
#   5. Origin MUST be validated.
#   6. An unsupported MCP-Protocol-Version is a 400.

my $MAIN = $$;
my $up   = start_upstream();
END { stop_upstream($up) if $up && $$ == $MAIN }

my $ISS      = 'https://idp.test/oauth';
my $RESOURCE = 'https://a.example/mcp';
my $KEY_ID   = 'key-1';
my $SECRET   = 'apip_live_secret';

my $have_jws = eval { require Crypt::JWS; require Crypt::JWS::Key;
                      Crypt::JWS::Key->can('generate') } ? 1 : 0;
my ($signing, $jwk);
if ($have_jws) {
    $signing = Crypt::JWS::Key->generate('ES256');
    $jwk     = $signing->to_jwk(kid => 'k1', alg => 'ES256');
}

sub jenc { File::Raw::JSON::file_json_encode($_[0], sort_keys => 1) }
sub jdec { File::Raw::JSON::file_json_decode($_[0]) }

my @KEYS = ({ id => $KEY_ID, hash => Digest::SHA::sha256_hex($SECRET),
              scopes => [], rate_per_min => 0, prefix => 'apip_liv' });

sub endpoint {
    my (%o) = @_;
    my $port = $o{port} || $up->{port};
    my $api = Open::API->new(spec => RegistryStub->secured_spec(1));
    my $gw  = Maat::Gateway->new(
        config => Maat::Config->tenant(
            mode => 'observe', upstream => "http://127.0.0.1:$port"),
        api => $api);
    my $mcp = Maat::MCP->new(
        api => $api, gw => $gw, host => $o{host} || 'a.example',
        version => '1', proxy => defined $o{proxy} ? $o{proxy} : 7,
        mcp => { enabled => 1, oauth => 1, issuer => $ISS });
    return ($mcp, $gw);
}

sub call {
    my (%o) = @_;
    my $env = MaatTest::psgi_env(
        method => $o{method} || 'POST',
        path   => defined $o{path} ? $o{path} : '/mcp',
        (defined $o{body} ? (body => $o{body}) : ()));
    $env->{HTTP_ACCEPT} = 'application/json';
    $env->{HTTP_AUTHORIZATION} = "Bearer $o{token}" if defined $o{token};
    $env->{HTTP_ORIGIN} = $o{origin} if defined $o{origin};
    $env->{HTTP_MCP_PROTOCOL_VERSION} = $o{proto} if defined $o{proto};
    $env->{'maat.keys'} = exists $o{keys} ? $o{keys} : [@KEYS];
    $env->{'maat.jwks'} = exists $o{jwks} ? $o{jwks} : ($jwk ? [$jwk] : undef);
    return MaatTest::run_app(sub { Maat::MCP::_serve($o{mcp}, $_[0]) }, $env);
}

my $LIST = jenc({ jsonrpc => '2.0', id => 1, method => 'tools/list' });

# ---- 1. MUST serve RFC 9728 protected resource metadata --------------------

{
    my ($mcp) = endpoint();
    my ($s, undef, $b) = call(mcp => $mcp, method => 'GET',
        path => '/.well-known/oauth-protected-resource');
    is $s, 200,
       'MUST serve RFC 9728 protected resource metadata';
    my $doc = jdec($b);
    is $doc->{resource}, $RESOURCE,
       '...identifying this endpoint as the resource';
    is_deeply $doc->{authorization_servers}, [$ISS],
       '...and naming the authorization server to use';
}

# ---- 2. MUST point at it from WWW-Authenticate on a 401 --------------------

{
    my ($mcp) = endpoint();
    my ($s, $h) = call(mcp => $mcp, body => $LIST);
    is $s, 401, 'an unauthenticated call is refused';
    is scalar MaatTest::header_get($h, 'WWW-Authenticate'),
       'Bearer realm="apip", resource_metadata='
     . '"https://a.example/.well-known/oauth-protected-resource"',
       'MUST point at the metadata from WWW-Authenticate on a 401';
}

# ---- 3. MUST validate the token audience is this server --------------------

SKIP: {
    skip 'needs Crypt::JWS for a real token', 2 unless $have_jws;

    # A coderef, not a lexical sub: `my sub` needs 5.18 and this dist's
    # floor is 5.010.
    my $mint = sub {
        my (%over) = @_;
        my %claims = (iss => $ISS, aud => $RESOURCE, sub => 'user-9',
                      scope => 'mcp', apip_proxy => 7, apip_key => $KEY_ID,
                      iat => time, exp => time + 300, %over);
        return Crypt::JWS::sign($signing, jenc(\%claims),
                                alg => 'ES256', kid => 'k1');
    };

    my ($mcp) = endpoint();
    is scalar((call(mcp => $mcp, body => $LIST, token => $mint->()))[0]), 200,
       'a token audienced for this server is accepted';

    # Same issuer, same signature, same key: only the audience differs.
    is scalar((call(mcp => $mcp, body => $LIST,
                    token => $mint->(aud => 'https://b.example/mcp')))[0]), 401,
       'MUST validate the token audience is this server';
}

# ---- 4. MUST NOT pass the client's token upstream --------------------------
#
# The one requirement nothing else in the suite checks. The gateway holds only
# key hashes, so it could not replay a client credential even if it tried -
# but "could not" is an argument, and the upstream's own view is evidence.

SKIP: {
    skip 'needs Crypt::JWS for a real token', 3 unless $have_jws;

    my %claims = (iss => $ISS, aud => $RESOURCE, sub => 'user-9',
                  scope => 'mcp', apip_proxy => 7, apip_key => $KEY_ID,
                  iat => time, exp => time + 300);
    my $token = Crypt::JWS::sign($signing, jenc(\%claims),
                                 alg => 'ES256', kid => 'k1');

    # An upstream that reports the HEAD it received. The default echo reports
    # method, target and body only, so asserting against it would be asserting
    # against something that could never contain a header in the first place.
    my $spy = start_upstream(respond => sub {
        my ($method, $target, $body, $head) = @_;
        return (200, ['Content-Type' => 'text/plain'], $head);
    });

    my ($mcp) = endpoint(port => $spy->{port});
    my (undef, undef, $b) = call(mcp => $mcp, token => $token,
        body => jenc({ jsonrpc => '2.0', id => 5, method => 'tools/call',
                       params => { name => 'secure1', arguments => {} } }));

    my $head = jdec($b)->{result}{content}[0]{text} // '';
    like $head, qr{^GET /secure}m,
       'the tool call reached the upstream (so the check below is real)';
    unlike $head, qr/\Q$token\E/,
       'MUST NOT pass the client token upstream';
    unlike $head, qr/(?im)^authorization:/,
       '...nor any Authorization header at all';

    stop_upstream($spy);
}

# ---- 5. Origin MUST be validated -------------------------------------------

{
    my ($mcp) = endpoint();
    my ($s) = call(mcp => $mcp, body => $LIST, token => undef,
                   origin => 'https://evil.example');
    is $s, 403, 'Origin MUST be validated, and a foreign one is refused';
}

# ---- 6. An unsupported protocol version is a 400 ---------------------------

{
    my ($mcp) = endpoint();
    is scalar((call(mcp => $mcp, body => $LIST, proto => '1999-01-01'))[0]),
       400, 'an unsupported MCP-Protocol-Version is a 400';
    is scalar((call(mcp => $mcp, body => $LIST, proto => '2025-06-18',
                    token => undef))[0]), 401,
       '...while a supported one proceeds to authentication';
}

done_testing;
