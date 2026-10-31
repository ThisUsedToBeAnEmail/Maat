use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;

use File::Raw::JSON ();
use Maat::Config;
use Maat::Gateway;

my $up = start_upstream();

sub enforcing {
    my $config = Maat::Config->from_hash({
        upstream => "http://127.0.0.1:$up->{port}",
        spec     => spec_path('petstore.json'),
        mode     => 'enforce',
    });
    return Maat::Gateway->new(config => $config);
}

sub problem {
    my ($body) = @_;
    return File::Raw::JSON::file_json_decode($body);
}

# ---- a malformed body answers problem+json and never reaches upstream -------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my $before = () = upstream_log($up);

    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => '{oops, not json',
    ));
    is($status, 400, 'malformed body rejected with 400');
    is(header_get($headers, 'Content-Type'), 'application/problem+json',
       'content type is problem+json');

    my $p = problem($body);
    is($p->{status}, 400, 'problem.status');
    is($p->{title}, 'Bad Request', 'problem.title');
    like($p->{type}, qr/openapi-proxy\.com/, 'problem.type');
    ok(@{ $p->{errors} }, 'the pointer list is present');
    is($p->{errors}[0]{in}, 'body', 'error names where');
    is($p->{errors}[0]{keyword}, 'json', 'error names the keyword');
    is($p->{request_id}, header_get($headers, 'X-Request-Id'),
       'the problem carries the request id the response echoes');

    my $after = () = upstream_log($up);
    is($after, $before, 'the upstream access log shows it never arrived');

    is($g->counters->{rejected}, 1, 'rejected counted');
    is($g->counters->{violation}, 1, 'violation recorded');
}

# ---- a schema violation carries the failing pointer -------------------------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my $before = () = upstream_log($up);

    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => '{"tag":"cat"}',
    ));
    is($status, 400, 'missing required property rejected');
    my $p = problem($body);
    my ($err) = grep { $_->{keyword} eq 'required' } @{ $p->{errors} };
    ok($err, 'a required-keyword error is in the list');
    is($err->{in}, 'body', 'it points at the body');

    is(scalar(() = upstream_log($up)), $before, 'upstream never saw it');
}

# ---- a query violation ------------------------------------------------------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/pets', query => 'limit=500',
    ));
    is($status, 400, 'out-of-range query rejected');
    my $p = problem($body);
    my ($err) = grep { ($_->{name} || '') eq 'limit' } @{ $p->{errors} };
    ok($err, 'the error names the parameter');
    is($err->{in}, 'query', 'and where it lives');
    is($err->{keyword}, 'maximum', 'and the failed keyword');
}

# ---- a missing required cookie ----------------------------------------------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'DELETE', path => '/pets/42',
    ));
    is($status, 400, 'missing required cookie rejected');
    my $p = problem($body);
    my ($err) = grep { ($_->{name} || '') eq 'session' } @{ $p->{errors} };
    ok($err, 'the error names the cookie parameter');
    is($err->{in}, 'cookie', 'in=cookie');
}

# ---- wrong method: 405 with Allow -------------------------------------------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my $before = () = upstream_log($up);

    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'DELETE', path => '/pets',
    ));
    is($status, 405, 'undeclared method on a declared path is 405');
    is(header_get($headers, 'Allow'), 'GET, POST', 'Allow lists the methods');
    my $p = problem($body);
    is($p->{title}, 'Method Not Allowed', 'problem.title');
    is(scalar(() = upstream_log($up)), $before, 'upstream never saw it');
    is($g->counters->{wrong_method}, 1, 'wrong_method counted');
}

# ---- gate 4: an unmatched path is forwarded in enforce too ------------------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my ($status, $headers, $body) = run_app($app, psgi_env(
        method => 'GET', path => '/metrics/internal',
    ));
    is($status, 200, 'enforce forwards the undeclared path');
    is($body, "method=GET\ntarget=/metrics/internal\nbody=",
       'straight through to the upstream');
    is($g->counters->{undeclared}, 1, 'counted undeclared');
    is($g->counters->{rejected}, 0, 'not rejected');
}

# ---- and a conforming request still flows -----------------------------------

{
    my $g   = enforcing();
    my $app = $g->to_app;
    my ($status) = run_app($app, psgi_env(
        method => 'POST', path => '/pets', body => '{"name":"rex"}',
    ));
    is($status, 200, 'conforming request forwarded in enforce');
    is($g->counters->{conforming}, 1, 'conforming counted');
}

stop_upstream($up);
done_testing;
