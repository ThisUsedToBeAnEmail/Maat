use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use Test::More;
use File::Temp ();
use File::Raw::JSON ();

use Maat::Config;
use Maat::Gateway;

# Observe-only drift the contract permits (Maat::Observe): undeclared query
# params, undeclared endpoints, wrong-method, deprecated fields still in use,
# and response fields not in the schema. None of it fails a request; all of
# it is recorded through the same pipeline as a validation failure, with
# distinct keywords and observe => 1 (so counted `observed`, not `violation`).

# A spec with a deprecated query param and a deprecated response property,
# plus an open object so an extra response key reads as undeclared.
my %DEP_SPEC = (
    openapi => '3.1.0',
    info    => { title => 'dep', version => '3' },
    paths   => {
        '/items' => {
            get => {
                operationId => 'listItems',
                parameters  => [
                    { name => 'q',   in => 'query', schema => { type => 'string' } },
                    { name => 'old', in => 'query', deprecated => \1,
                      schema => { type => 'string' } },
                ],
                responses => { 200 => { description => 'ok', content => {
                    'application/json' => { schema => {
                        type => 'object',
                        properties => {
                            id     => { type => 'integer' },
                            legacy => { type => 'string', deprecated => \1 },
                        },
                    } },
                } } },
            },
        },
    },
);

sub spec_file {
    my ($hash) = @_;
    my $fh = File::Temp->new(SUFFIX => '.json', UNLINK => 1);
    print {$fh} File::Raw::JSON::file_json_encode($hash);
    close $fh;
    return $fh;   # keep the object alive so UNLINK does not fire early
}

# Build a gateway over an in-process upstream that answers a fixed triplet,
# serve one request, and return the flushed records.
sub serve {
    my (%o) = @_;
    my %rh = (upstream => 'http://127.0.0.1:9',
              spec     => $o{spec},
              mode     => $o{mode} || 'observe',
              responses=> { sample => 'all', %{ $o{responses} || {} } });
    delete $rh{upstream} if ($o{mode} || '') eq 'mock';
    $rh{report} = $o{report} if $o{report};
    my $cfg = Maat::Config->from_hash(\%rh);

    my @rec;
    my $g = Maat::Gateway->new(config => $cfg, sink => sub { push @rec, @{ $_[0] } });
    if ($o{mode} && $o{mode} eq 'mock') {
        # leave the mock app in place
    }
    else {
        my $resp = $o{response}
            || [ 200, [ 'Content-Type' => 'application/json',
                        'Content-Length' => 2 ], [ '{}' ] ];
        $g->{proxy} = sub { ref $resp eq 'CODE' ? $resp->(@_) : $resp };
    }
    my $app = $g->to_app;
    $app->($o{env});
    $g->violation->flush;
    return ($g, \@rec);
}

sub by_keyword {
    my ($rec, $kw) = @_;
    return grep { ($_->{keyword} // '') eq $kw } @$rec;
}

my $PET = MaatTest::spec_path('petstore.json');

# ---- undeclared query parameter --------------------------------------------
{
    my ($g, $rec) = serve(spec => $PET,
        response => [ 200, [ 'Content-Type' => 'application/json',
                             'Content-Length' => 2 ], [ '[]' ] ],   # conforming
        env => psgi_env(method => 'GET', path => '/pets',
                        query => 'limit=5&mystery=1'));
    my @u = by_keyword($rec, 'undeclared-parameter');
    is scalar @u, 1, 'one undeclared query parameter is reported';
    is $u[0]{pointer}, 'query/mystery', '...named, by where it lives';
    is $u[0]{kind}, 'request', '...as request drift';
    is_deeply [ by_keyword($rec, 'undeclared-parameter') ],
        [ grep { $_->{pointer} ne 'query/limit' } @u ],
        'a declared parameter (limit) is not reported';
    ok $g->counters->{observed} >= 1, 'counted as an observation';
    is $g->counters->{violation}, 0, 'and never as a violation';
}

# ---- deprecated query parameter still in use -------------------------------
{
    my $sf = spec_file(\%DEP_SPEC);
    my ($g, $rec) = serve(spec => "$sf",
        env => psgi_env(method => 'GET', path => '/items', query => 'old=1'));
    my @d = by_keyword($rec, 'deprecated-usage');
    is scalar @d, 1, 'a deprecated query parameter in use is reported';
    is $d[0]{pointer}, 'query/old', '...named';
}

# ---- undeclared endpoint, reported by templated shape ----------------------
{
    my ($g, $rec) = serve(spec => $PET,
        env => psgi_env(method => 'GET', path => '/widgets/42/reviews'));
    my @e = by_keyword($rec, 'undeclared-endpoint');
    is scalar @e, 1, 'an unmapped path is reported as an undeclared endpoint';
    is $e[0]{pointer}, 'GET /widgets/*/reviews',
        '...by method and templated path - the id is a *, never a value';
    is $e[0]{kind}, 'undeclared', '...of the undeclared kind';
}

# two ids on the same shape are ONE fingerprint - the whole point of the *
{
    my $seen = {};
    for my $id (42, 99, 7) {
        my ($g, $rec) = serve(spec => $PET,
            env => psgi_env(method => 'GET', path => "/widgets/$id/reviews"));
        $seen->{ $_->{fingerprint} } = $_->{pointer}
            for by_keyword($rec, 'undeclared-endpoint');
    }
    is scalar(keys %$seen), 1,
        'different ids under the same undocumented shape share one fingerprint';
}

# ---- a known path with an undeclared method --------------------------------
{
    my ($g, $rec) = serve(spec => $PET,
        env => psgi_env(method => 'DELETE', path => '/pets'));
    my @w = by_keyword($rec, 'wrong-method');
    is scalar @w, 1, 'a known path hit with an undeclared method is reported';
    is $w[0]{method}, 'DELETE', '...carrying the method that was used';
}

# ---- an undeclared field in a CONFORMING response --------------------------
{
    my $body = '{"id":1,"name":"Rex","surprise":true}';
    my ($g, $rec) = serve(spec => $PET,
        response => [ 200, [ 'Content-Type' => 'application/json',
                             'Content-Length' => length $body ], [ $body ] ],
        env => psgi_env(method => 'GET', path => '/pets/42'));
    my @p = by_keyword($rec, 'undeclared-property');
    is scalar @p, 1, 'a response field not in the schema is reported';
    is $p[0]{pointer}, '/surprise', '...by its pointer';
    is $p[0]{kind}, 'response', '...as response drift';
    is $g->counters->{violation}, 0, 'a conforming response is not a violation';
}

# ---- a deprecated field in use in a CONFORMING response --------------------
{
    my $sf = spec_file(\%DEP_SPEC);
    my $body = '{"id":1,"legacy":"still-here"}';
    my ($g, $rec) = serve(spec => "$sf",
        response => [ 200, [ 'Content-Type' => 'application/json',
                             'Content-Length' => length $body ], [ $body ] ],
        env => psgi_env(method => 'GET', path => '/items'));
    my @d = by_keyword($rec, 'deprecated-usage');
    is scalar @d, 1, 'a deprecated response field in use is reported';
    is $d[0]{pointer}, '/legacy', '...by its pointer';
}

# ---- mock mode never observes (no upstream to drift against) ---------------
{
    my ($g, $rec) = serve(spec => $PET, mode => 'mock',
        env => psgi_env(method => 'GET', path => '/widgets/42'));
    is scalar @$rec, 0, 'mock mode records no observations';
    is $g->{observe}, 0, '...because observe is off in mock mode';
}

# ---- the toggle turns it all off -------------------------------------------
{
    my ($g, $rec) = serve(spec => $PET, report => { undeclared => 0 },
        env => psgi_env(method => 'GET', path => '/widgets/42',
                        query => 'mystery=1'));
    is scalar @$rec, 0, 'report.undeclared:false reports nothing';
    is $g->{observe}, 0, '...the gateway is not observing';
}

done_testing();
