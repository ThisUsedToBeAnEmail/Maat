use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;

use Maat::Config;
use Maat::Gateway;

# Gate 1, approximated locally: a corpus of requests is sent once
# straight to the upstream and once through the gateway, and every
# conforming (and undeclared) response must be identical - status, body
# bytes, and every header outside the hop-by-hop set and X-Request-Id.

my $up = start_upstream();

my $config = Maat::Config->from_hash({
    upstream => "http://127.0.0.1:$up->{port}",
    spec     => spec_path('petstore.json'),
    mode     => 'observe',
});
my $g   = Maat::Gateway->new(config => $config);
my $app = $g->to_app;

# The corpus: conforming, undeclared, queries, bodies, odd headers.
my @corpus = (
    { name => 'plain GET',
      method => 'GET', path => '/pets/42' },
    { name => 'GET with query',
      method => 'GET', path => '/pets', query => 'limit=10' },
    { name => 'GET with repeated query params',
      method => 'GET', path => '/pets', query => 'limit=10&tags=a&tags=b' },
    { name => 'conforming POST with a JSON body',
      method => 'POST', path => '/pets', body => '{"name":"rex","tag":"dog"}' },
    { name => 'undeclared path',
      method => 'GET', path => '/health/deep' },
    { name => 'undeclared path with query and body',
      method => 'PUT', path => '/v2/whatever', query => 'x=1&y=2',
      body => 'opaque bytes: not json at all', content_type => 'text/plain' },
    { name => 'undeclared deep path with odd characters',
      method => 'GET', path => '/a/b%20c/d', query => 'q=%2Fslash' },
    { name => 'custom request headers ride along',
      method => 'GET', path => '/pets/42',
      headers => [ 'X-Custom-One' => 'alpha', 'Accept' => 'application/json' ] },
    { name => 'a declared operation with a required cookie',
      method => 'DELETE', path => '/pets/42',
      headers => [ Cookie => 'session=abc' ] },
    { name => 'undeclared path that looks like a file',
      method => 'GET', path => '/pets/42/photo.png' },
    # Encoded, not raw. A client may put raw UTF-8 bytes in a request
    # line, but no proxy can forward them unchanged: anything above
    # 0x7f has to be re-encoded to stay inside a request target, so the
    # two sides could never be byte-identical and the comparison would
    # be testing the wrong thing. Encoded on the wire, both sides
    # describe the same path.
    { name => 'percent-encoded UTF-8 in the path',
      method => 'GET', path => '/unicode/caf%C3%A9' },
);

for my $c (@corpus) {
    # Direct to the upstream.
    my $target = $c->{path} . (defined $c->{query} ? "?$c->{query}" : '');
    my @extra  = @{ $c->{headers} || [] };
    push @extra, 'Content-Type' => ($c->{content_type} || 'application/json')
        if defined $c->{body};
    my ($d_status, $d_headers, $d_body) =
        http_request($up->{port}, $c->{method}, $target, \@extra, $c->{body});

    # Through the gateway.
    my ($p_status, $p_headers, $p_body) = run_app($app, psgi_env(
        method => $c->{method}, path => $c->{path},
        (defined $c->{query} ? (query => $c->{query}) : ()),
        (defined $c->{body}  ? (body => $c->{body},
                                content_type => $c->{content_type}
                                             || 'application/json') : ()),
        ($c->{headers} ? (headers => $c->{headers}) : ()),
    ));

    subtest $c->{name} => sub {
        is($p_status, $d_status, 'status identical');
        is($p_body, $d_body, 'body byte-identical');
        is_deeply(normalise_headers($p_headers), normalise_headers($d_headers),
                  'headers identical minus hop-by-hop and X-Request-Id');
        ok(defined header_get($p_headers, 'X-Request-Id'),
           'the gateway adds X-Request-Id');
        my @cookies = header_get($p_headers, 'Set-Cookie');
        is_deeply(\@cookies, [ 'a=1; Path=/', 'b=2; Path=/' ],
                  'multi-valued Set-Cookie preserved in order');
    };
}

is($g->counters->{rejected}, 0, 'nothing in the corpus was rejected');
is($g->counters->{failed},   0, 'no internal failures during the replay');

stop_upstream($up);
done_testing;
