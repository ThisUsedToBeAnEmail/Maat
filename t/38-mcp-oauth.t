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
plan skip_all => 'needs Crypt::JWS with key generation'
    unless eval { require Crypt::JWS; require Crypt::JWS::Key;
                  Crypt::JWS::Key->can('generate') && Crypt::JWS->can('sign') };

# Phase 03B - an OAuth access token instead of an API key.
#
# The token is verified statelessly against the JWKS the registry bundle
# carried, because the data plane must never call the control plane per
# request. Everything below uses REAL keys and REAL signatures: the token is
# minted here with Crypt::JWS and verified by the endpoint's own code, so a
# test passing means the signature path works rather than that a fixture was
# typed correctly.
#
# The assertion this file exists for is the cross-tenant one. One
# authorization server issues for every tenant on the platform, so the only
# thing stopping a token minted for proxy A being spent at proxy B is that
# `aud` is the endpoint's own canonical resource and is checked. That is why
# RFC 8707 went into the authorization server at all.

my $MAIN = $$;
my $up   = start_upstream();
END { stop_upstream($up) if $up && $$ == $MAIN }

my $ISS      = 'https://idp.test/oauth';
my $RESOURCE = 'https://a.example/mcp';
my $KEY_ID   = 'key-1';

my $signing = Crypt::JWS::Key->generate('ES256');
my $jwk     = $signing->to_jwk(kid => 'k1', alg => 'ES256');
my $other   = Crypt::JWS::Key->generate('ES256');

sub jenc { File::Raw::JSON::file_json_encode($_[0], sort_keys => 1) }
sub jdec { File::Raw::JSON::file_json_decode($_[0]) }

sub mint {
    my (%over) = @_;
    my $key = delete $over{_key} || $signing;
    my %claims = (
        iss        => $ISS,
        aud        => $RESOURCE,
        sub        => 'user-9',
        scope      => 'mcp',
        apip_proxy => 7,
        apip_key   => $KEY_ID,
        iat        => time,
        exp        => time + 300,
        %over,
    );
    delete $claims{$_} for grep { !defined $claims{$_} } keys %claims;
    return Crypt::JWS::sign($key, jenc(\%claims), alg => 'ES256', kid => 'k1');
}

my @KEYS = ({ id => $KEY_ID, hash => Digest::SHA::sha256_hex('never-presented'),
              scopes => [], rate_per_min => 0, prefix => 'apip_xxx' });

sub endpoint {
    my (%o) = @_;
    my $api = Open::API->new(spec => RegistryStub->secured_spec(1));
    my $gw  = Maat::Gateway->new(
        config => Maat::Config->tenant(
            mode => 'observe', upstream => "http://127.0.0.1:$up->{port}"),
        api => $api);
    my $mcp = Maat::MCP->new(
        api  => $api, gw => $gw,
        host => $o{host} || 'a.example',
        version => '1',
        proxy   => defined $o{proxy} ? $o{proxy} : 7,
        mcp     => { enabled => 1,
                     ($o{oauth} // 1) ? (oauth => 1, issuer => $ISS) : () });
    return ($mcp, $gw);
}

sub call {
    my (%o) = @_;
    my $env = MaatTest::psgi_env(method => 'POST', path => '/mcp',
        body => $o{body} || jenc({ jsonrpc => '2.0', id => 1,
                                   method => 'tools/list' }));
    $env->{HTTP_ACCEPT} = 'application/json';
    $env->{HTTP_AUTHORIZATION} = "Bearer $o{token}" if defined $o{token};
    $env->{'maat.keys'} = exists $o{keys} ? $o{keys} : [@KEYS];
    $env->{'maat.jwks'} = exists $o{jwks} ? $o{jwks} : [$jwk];
    return MaatTest::run_app(sub { Maat::MCP::_serve($o{mcp}, $_[0]) }, $env);
}

# ---- a good token is admitted ----------------------------------------------

{
    my ($mcp) = endpoint();
    my ($s, $h, $b) = call(mcp => $mcp, token => mint());
    is $s, 200, 'a token signed by the authorization server is admitted';
    is scalar @{ jdec($b)->{result}{tools} }, 2, '...and served the tools';
}

# ---- THE CROSS-TENANT CASE -------------------------------------------------

{
    my ($a) = endpoint(host => 'a.example', proxy => 7);
    my ($b) = endpoint(host => 'b.example', proxy => 8);

    my $for_a = mint();
    is scalar((call(mcp => $a, token => $for_a))[0]), 200,
       'the token works at the tenant it was minted for';

    # Same account, same authorization server, same signature. Only the
    # audience differs, and that is the whole defence.
    is scalar((call(mcp => $b, token => $for_a))[0]), 401,
       'and is refused at the neighbour, because aud is not its resource';

    my $for_b = mint(aud => 'https://b.example/mcp', apip_proxy => 8);
    is scalar((call(mcp => $a, token => $for_b))[0]), 401,
       'and the reverse is refused too';

    # A token whose aud is right but which names another tenant's proxy.
    is scalar((call(mcp => $a, token => mint(apip_proxy => 8)))[0]), 401,
       'a mismatched apip_proxy is refused even with the right audience';

    # ONLY the audience is wrong: same proxy, same issuer, same key, same
    # scope. Without this the two cross-tenant assertions above pass on the
    # apip_proxy check alone and the audience comparison is never exercised -
    # which is exactly what a mutation of it proved.
    is scalar((call(mcp => $a,
                    token => mint(aud => 'https://b.example/mcp')))[0]), 401,
       'a token whose ONLY fault is its audience is refused';

    # RFC 7519 allows aud to be a list. Both branches of that, because the
    # list branch is a separate path through the comparison.
    is scalar((call(mcp => $a,
                    token => mint(aud => ['https://b.example/mcp',
                                          $RESOURCE])))[0]), 200,
       'an audience list containing this resource is admitted';

    is scalar((call(mcp => $a,
                    token => mint(aud => ['https://b.example/mcp',
                                          'https://c.example/mcp'])))[0]), 401,
       'an audience list without it is refused';
}

# ---- what else a token must satisfy ----------------------------------------

{
    my ($mcp) = endpoint();

    is scalar((call(mcp => $mcp, token => mint(iss => 'https://evil/oauth')))[0]),
       401, 'another issuer is refused';

    is scalar((call(mcp => $mcp, token => mint(exp => time - 3600)))[0]),
       401, 'an expired token is refused';

    is scalar((call(mcp => $mcp, token => mint(nbf => time + 3600)))[0]),
       401, 'a token not yet valid is refused';

    is scalar((call(mcp => $mcp, token => mint(scope => 'read')))[0]),
       403, 'a token without the mcp scope is authenticated but refused';

    # Signed with a key the JWKS does not carry: the signature is real and
    # verifies against ITS key, which is exactly the attack.
    is scalar((call(mcp => $mcp, token => mint(_key => $other)))[0]),
       401, 'a token signed by a key outside the JWKS is refused';

    is scalar((call(mcp => $mcp, token => 'not.a.token'))[0]),
       401, 'a credential shaped like a JWT but not one is refused';

    is scalar((call(mcp => $mcp, token => mint(), jwks => []))[0]),
       401, 'with no JWKS published there is nothing to verify against';
}

# ---- revocation ------------------------------------------------------------

{
    my ($mcp) = endpoint();

    is scalar((call(mcp => $mcp, token => mint(apip_key => 'no-such-key')))[0]),
       401, 'a token naming a key this tenant does not publish is refused';

    # The revocation path: the bundle drops the key, the live token dies with
    # it, without the control plane being asked anything.
    is scalar((call(mcp => $mcp, token => mint(), keys => []))[0]),
       401, 'and a token outlives nothing when its key is revoked';
}

# ---- a keys-only tenant refuses tokens outright ----------------------------

{
    my ($mcp) = endpoint(oauth => 0);
    is scalar((call(mcp => $mcp, token => mint()))[0]), 401,
       'a tenant not configured for OAuth refuses a token rather than '
     . 'half-validating it';
}

# ---- the resolved key is what the call is metered as -----------------------

{
    my ($mcp, $gw) = endpoint();
    my $before = $gw->violation->counters->{request} || 0;

    my ($s, $h, $b) = call(mcp => $mcp, token => mint(),
        body => jenc({ jsonrpc => '2.0', id => 5, method => 'tools/call',
                       params => { name => 'secure1', arguments => {} } }));
    is $s, 200, 'a tool call authorised by a token answers';
    my $r = jdec($b);
    ok !$r->{error}, '...and was not refused';
    like $r->{result}{content}[0]{text}, qr{^target=/secure$}m,
       '...reaching the guarded operation through the resolved key';
    is(($gw->violation->counters->{request} || 0) - $before, 1,
       '...metered as exactly one request, like any other');
}

done_testing;
