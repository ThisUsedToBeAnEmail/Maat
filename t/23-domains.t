use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Maat::Registry;
use Maat::Poller;
use Maat::Router;

# Phase 7, the edge half - everything testable without a live TLS socket:
#
#   * an ISSUED domain in the bundle serves its proxy over the routed
#     host, and its PEM cert/key land in the tls_sni map Hyperman loads
#     from (files, key mode 0600);
#   * an http-01 CHALLENGE in the bundle is answered at the well-known
#     path for the domain being validated;
#   * a domain that LEAVES the bundle stops being served, and its SNI
#     material is gone, within ONE poll.
#
# The whole thing is driven through Maat::Poller->poll_once against the
# RegistryStub, so "within one poll" is literal, not a figure of speech.

my $CRT = "-----BEGIN CERTIFICATE-----\nMAAT-TEST-CERT\n-----END CERTIFICATE-----\n";
my $KEY = "-----BEGIN PRIVATE KEY-----\nMAAT-TEST-KEY\n-----END PRIVATE KEY-----\n";

my $stub = RegistryStub->new(token => 'reg-token');
$stub->add_tenant(host => 'acme.openapi-proxy.com', proxy => 42, version => 4,
    plan => 'team', spec => RegistryStub->tenant_spec(42));

my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
my $poller = Maat::Poller->new(registry => $reg,
    url => 'http://control/registry/bundle', token => 'reg-token',
    fetch => $stub->fetcher);
my $app = Maat::Router->new(registry => $reg)->to_app;

sub call {
    my ($host, $path) = @_;
    my $env = MaatTest::psgi_env(path => $path // '/hello');
    $env->{HTTP_HOST} = $host;
    return MaatTest::run_app($app, $env);
}

# ---- before issuance: the domain is pending, only the challenge exists ----

$stub->add_challenge('probe-token', 'probe-token.key-authorization');
is $poller->poll_once, 'applied', 'the pending-domain bundle applies';

{
    my ($s, $h, $b) = call('api.customer.com',
        '/.well-known/acme-challenge/probe-token');
    is $s, 200, 'http-01: the challenge is answered for the domain being validated';
    is $b, 'probe-token.key-authorization', 'with its exact key authorization';
}
{
    my ($s) = call('api.customer.com', '/hello');
    is $s, 404, 'the domain does not yet route to a proxy (unissued)';
}

# ---- issuance: the domain appears with cert + key -------------------------

$stub->clear_challenges;                       # order completed
$stub->add_domain(host => 'api.customer.com', proxy => 42,
    tls_crt => $CRT, tls_key => $KEY, expires => time + 90 * 86400);
is $poller->poll_once, 'applied', 'the issued-domain bundle applies';

{
    my ($s, $h, $b) = call('api.customer.com', '/hello');
    is $s, 200, 'the issued domain now serves its proxy over the routed host';
    like $b, qr/"tenant":42/, 'and serves that proxy\'s spec';
    is MaatTest::header_get($h, 'X-Maat-Proxy'), 42, 'attributed to the right proxy';
}

{
    my $sni = $reg->tls_sni;
    ok $sni->{'api.customer.com'}, 'the domain is in the tls_sni map Hyperman loads from';
    my $cert = $sni->{'api.customer.com'}{cert};
    my $key  = $sni->{'api.customer.com'}{key};
    ok -e $cert && -e $key, 'the PEM cert and key were materialized to disk';
    is do { open my $fh, '<', $cert; local $/; <$fh> }, $CRT,
        'the cert file holds the bundle cert bytes';
    my $mode = (stat $key)[2] & 07777;
    is $mode, 0600, 'the private key file is readable only by us (0600)';
}

# The challenge for the now-issued domain is gone.
{
    my ($s) = call('api.customer.com', '/.well-known/acme-challenge/probe-token');
    is $s, 404, 'the completed challenge is no longer answered';
}

# ---- removal: the domain leaves the bundle --------------------------------

my $cert_path = $reg->tls_sni->{'api.customer.com'}{cert};
my $key_path  = $reg->tls_sni->{'api.customer.com'}{key};

$stub->clear_domains;
is $poller->poll_once, 'applied', 'the removal bundle applies (one poll)';

{
    my ($s) = call('api.customer.com', '/hello');
    is $s, 404, 'a domain that left the bundle stops being served within one poll';
    is_deeply { %{ $reg->tls_sni } }, {}, 'its SNI entry is dropped within the same poll';
    ok !-e $cert_path && !-e $key_path,
        'and its cert/key files are removed from disk';
}

# The underlying tenant (its openapi-proxy.com host) is untouched.
{
    my ($s) = call('acme.openapi-proxy.com', '/hello');
    is $s, 200, 'the tenant\'s own slug host keeps serving throughout';
}

done_testing;
