#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use Time::HiRes ();
use File::Raw::JSON ();

use Maat::Config;
use Maat::Gateway;

# Mock mode: a gateway with no upstream serves the document. The request
# half is the phase-1 path unchanged - a non-conforming request is
# answered 400 with its pointers - and the response half is Open::API's
# synthesis, deterministic and validating against its own schema.

sub mock_gateway {
    my (%o) = @_;
    my $config = Maat::Config->from_hash({
        spec => spec_path('petstore.json'),
        mode => 'mock',
        (exists $o{mock} ? (mock => delete $o{mock}) : ()),
    });
    my $g = Maat::Gateway->new(config => $config, %o);
    return ($g, $g->to_app);
}

# ---- configuration ----------------------------------------------------------

{
    ok(!eval { Maat::Config->from_hash({ spec => spec_path('petstore.json'),
                                         mode => 'mock',
                                         upstream => 'http://up:1' }) },
       'mock plus upstream is refused');
    like($@, qr/does not take an 'upstream'/, 'and says why');

    ok(!eval { Maat::Config->from_hash({ spec => spec_path('petstore.json') }) },
       'no upstream outside mock is still fatal');
    like($@, qr/'upstream' is required/, 'with the phase-1 message');

    ok(!eval { Maat::Config->from_hash({ spec => spec_path('petstore.json'),
                                         upstream => 'http://up:1',
                                         mock => {} }) },
       'a mock table outside mock mode is refused');
}

# ---- a declared operation answers from the document -------------------------

{
    my ($g, $app) = mock_gateway();
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets/42',
    ));
    is($status, 200, 'declared operation answers');
    is(header_get($headers, 'Content-Type'), 'application/json',
       'with the declared content type');
    my $data = File::Raw::JSON::file_json_decode($body);
    ok(defined $data->{id} && defined $data->{name},
       'and a body carrying the schema\'s required members');
    ok(header_get($headers, 'X-Request-Id'), 'the request id is stamped');
    is($g->counters->{conforming}, 1, 'counted conforming, as the proxy would');

    # byte-identical with what Open::API synthesizes directly, and with
    # itself, every time. The gateway hands the path captures through, so
    # the direct call gets the same ones - GET /pets/42 answers id 42.
    my $direct = $g->api->synthesize('getPet',
        { path => { petId => 42 } })->[2][0];
    is($body, $direct, 'the body is Open::API\'s synthesis, byte for byte');
    for (1 .. 99) {
        my (undef, undef, $again) = run_app($app, psgi_env(
            method => 'GET', path => '/pets/42',
        ));
        $body eq $again or fail('mock responses drifted'), last;
    }
    pass('100 requests, byte-identical bodies');

    # the mock cannot generate what its own validator rejects
    is($g->api->check_response('getPet',
           [ 200, [ 'Content-Type' => 'application/json',
                    'Content-Length' => length $body ], [ $body ] ], {}),
       undef, 'the served body validates against the document');
}

# ---- Prefer: status selection and named examples ----------------------------

{
    my ($g, $app) = mock_gateway();
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method  => 'GET', path => '/pets/42',
        headers => [ 'Prefer' => 'code=404' ],
    ));
    is($status, 404, 'Prefer: code=404 selects the declared 404');
    is($body, '', 'which declares no content, so no body is invented');
}

# ---- a bad request is a conformance report, not a forward -------------------

{
    my ($g, $app) = mock_gateway();
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=500',
    ));
    is($status, 400, 'a non-conforming request is rejected');
    is(header_get($headers, 'Content-Type'), 'application/problem+json',
       'as problem+json');
    my $prob = File::Raw::JSON::file_json_decode($body);
    is($prob->{errors}[0]{name}, 'limit', 'naming the parameter');
    is($prob->{errors}[0]{keyword}, 'maximum', 'and the failing keyword');
    is($g->counters->{rejected}, 1, 'counted rejected');
}

# ---- wrong method and undeclared path ---------------------------------------

{
    my ($g, $app) = mock_gateway();
    my ($status, $headers) = run_app($app, psgi_env(
        method => 'PATCH', path => '/pets',
    ));
    is($status, 405, 'declared path, undeclared method: 405');
    like(header_get($headers, 'Allow'), qr/GET/, 'with the Allow header');

    my ($s2, $h2, $b2) = run_app($app, psgi_env(
        method => 'GET', path => '/not/in/the/document',
    ));
    is($s2, 404, 'undeclared path: 404 - nothing to forward to');
    is(header_get($h2, 'Content-Type'), 'application/problem+json',
       'as problem+json');
    my $prob = File::Raw::JSON::file_json_decode($b2);
    like($prob->{detail}, qr/does not declare/, 'saying the document does not declare it');
    is($g->counters->{undeclared}, 1, 'counted undeclared, same as the proxy');
}

# ---- __delay: present, and bounded ------------------------------------------

{
    my ($g, $app) = mock_gateway();
    my $t0 = Time::HiRes::time();
    my ($status) = run_app($app, psgi_env(
        method => 'GET', path => '/pets/42', query => '__delay=200ms',
    ));
    my $took = Time::HiRes::time() - $t0;
    is($status, 200, 'delayed request still answers');
    cmp_ok($took, '>=', 0.15, "__delay=200ms held the response (${\ sprintf '%.0f', $took*1000}ms)");
}

{
    my ($g, $app) = mock_gateway(mock => { max_delay => 0.3 });
    my $t0 = Time::HiRes::time();
    my ($status) = run_app($app, psgi_env(
        method => 'GET', path => '/pets/42', query => '__delay=60s',
    ));
    my $took = Time::HiRes::time() - $t0;
    is($status, 200, 'an absurd delay still answers');
    cmp_ok($took, '<', 2, "and is capped at mock.max_delay (${\ sprintf '%.2f', $took}s)");
}

# ---- chaos: a synthesis failure is a 500, never a hang ----------------------

{
    my ($g, $app) = mock_gateway(chaos => 'mock');
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets/42',
    ));
    is($status, 500, 'APIP_CHAOS=mock: synthesis failure answers 500');
    is(header_get($headers, 'Content-Type'), 'application/problem+json',
       'as problem+json');
    is($g->counters->{failed}, 1, 'and the failure is counted');
}

# a dying validator still fails open onto the mock: the request cannot be
# judged, so it is answered rather than dropped - same rule as the proxy
{
    my ($g, $app) = mock_gateway(chaos => 'validate');
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets/42',
    ));
    is($status, 200, 'APIP_CHAOS=validate: the mock still answers');
    ok(length $body, 'with a synthesized body');
    is($g->counters->{failed}, 1, 'and the failure is counted');
}

done_testing;
