#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Temp ();
use Maat::Config;

# The configuration is read once, at boot, by someone who is not here.
# Every error has to name the key and the fix.

my $dir  = File::Temp->newdir('maat-config-XXXXXX', TMPDIR => 1);
my $spec = spec_path('petstore.json');

sub load_yaml {
    my ($body) = @_;
    my $file = write_file("$dir/apip.yml", $body);
    return eval { Maat::Config->load($file) };
}
sub load_hash { return eval { Maat::Config->from_hash($_[0]) } }

# ---- the defaults ---------------------------------------------------------------
{
    my $c = load_hash({ upstream => 'http://up:8080', spec => $spec });
    ok($c, 'a minimal configuration loads') or diag $@;
    is($c->mode, 'observe', 'mode defaults to observe - never enforce by accident');
    is($c->enforcing, 0, 'and enforcing is false');
    is($c->upstream, 'http://up:8080', 'upstream kept');
    is($c->spec, $spec, 'spec resolved to a real path');
    is($c->{timeout}, 30, 'timeout default');
    is($c->{pool_size}, 64, 'pool_size default');
    is($c->{max_body}, 1024 * 1024, 'max_body default');
    is($c->{tls_verify}, 1, 'tls_verify defaults ON');
    is_deeply($c->listen, [ { port => 8080, host => '0.0.0.0',
                              tls_cert => undef, tls_key => undef,
                              redirect_https => undef } ],
              'one plain listener by default');
}

# ---- what is required -----------------------------------------------------------
{
    ok(!load_hash({ spec => $spec }), 'upstream is required');
    like($@, qr/'upstream' is required/, 'and says which key');

    ok(!load_hash({ upstream => 'http://up' }), 'spec is required');
    like($@, qr/'spec' is required/, 'and says which key');
}

# ---- unknown keys are fatal, with a guess ----------------------------------------
# A silently ignored option is a setting the operator believes is on.
{
    ok(!load_hash({ upstream => 'http://up', spec => $spec, upstrem => 'x' }),
       'an unknown key is fatal');
    like($@, qr/unknown key 'upstrem'/, 'naming it');
    like($@, qr/did you mean 'upstream'/, 'and guessing the intent');

    ok(!load_hash({ upstream => 'http://up', spec => $spec, mode => 'enfroce' }),
       'a bad enum value is fatal');
    like($@, qr/'mode' must be one of 'observe', 'enforce', 'mock', not 'enfroce'/,
         'listing what is allowed');
}

# ---- values are checked, not merely present ---------------------------------------
{
    ok(!load_hash({ upstream => 'ftp://nope', spec => $spec }), 'upstream must be http(s)');
    like($@, qr/must be an http\(s\) URL/, 'and says so');

    ok(!load_hash({ upstream => 'http://up', spec => "$dir/no-such-spec.json" }),
       'the spec must exist');
    like($@, qr/not a readable file/, 'and says where it looked');

    ok(!load_hash({ upstream => 'http://up', spec => $spec, timeout => -1 }),
       'timeout must be positive');
    ok(!load_hash({ upstream => 'http://up', spec => $spec, max_body => 'huge' }),
       'max_body must be a size');
    like($@, qr/like '256k'/, 'with an example of one');
}

# ---- sizes the way people write them ----------------------------------------------
{
    for my $case ([ '256k' => 256 * 1024 ], [ '2M' => 2 * 1024 * 1024 ],
                  [ '1048576' => 1048576 ], [ '512kb' => 512 * 1024 ]) {
        my $c = load_hash({ upstream => 'http://up', spec => $spec,
                            max_body => $case->[0] });
        is($c && $c->{max_body}, $case->[1], "max_body '$case->[0]'");
    }
}

# ---- listeners ---------------------------------------------------------------------
{
    my $c = load_hash({ upstream => 'http://up', spec => $spec,
        listen => [ { port => 80, redirect_https => 443 },
                    { port => 443, tls_cert => $spec, tls_key => $spec } ] });
    ok($c, 'two listeners load') or diag $@;
    is(scalar @{ $c->listen }, 2, 'both kept');
    is($c->listen->[0]{redirect_https}, 443, 'the redirect target survives');
    is($c->listen->[1]{host}, '0.0.0.0', 'host defaults per listener');

    # Half a certificate is a boot failure, never a listener that quietly
    # serves plain HTTP on the port everyone believes is TLS.
    ok(!load_hash({ upstream => 'http://up', spec => $spec,
                    listen => [ { port => 443, tls_cert => $spec } ] }),
       'tls_cert without tls_key is refused');
    like($@, qr/needs both/, 'saying why');

    ok(!load_hash({ upstream => 'http://up', spec => $spec,
                    listen => [ { port => 99999 } ] }), 'a port must be a port');
    like($@, qr/listen\[0\]\.port/, 'and the error names the index');
}

# ---- secret references ---------------------------------------------------------------
{
    local $ENV{MAAT_TEST_TOKEN} = 's3kr3t';
    my $c = load_hash({ upstream => 'http://up', spec => $spec,
        report => { url => 'https://control.test/v1', token => { '$env' => 'MAAT_TEST_TOKEN' } } });
    ok($c, 'an $env reference loads') or diag $@;
    is($c->{report}{token}, 's3kr3t', 'and resolves from the environment');

    ok(!load_hash({ upstream => 'http://up', spec => $spec,
        report => { token => { '$env' => 'MAAT_DEFINITELY_NOT_SET' } } }),
       'an unset environment variable is fatal at boot, not at first use');
    like($@, qr/which is not set/, 'and says so');

    my $secret = write_file("$dir/token.txt", "from-a-file\n");
    my $c2 = load_hash({ upstream => 'http://up', spec => $spec,
        report => { token => { '$file' => $secret } } });
    is($c2 && $c2->{report}{token}, 'from-a-file',
       'a $file reference resolves and loses the trailing newline');
}

# ---- from a real file ------------------------------------------------------------------
{
    my $c = load_yaml(<<"YML");
upstream: http://127.0.0.1:9999
spec:     $spec
mode:     enforce
max_body: 256k
YML
    ok($c, 'a YAML file loads') or diag $@;
    is($c->mode, 'enforce', 'mode read');
    is($c->enforcing, 1, 'and enforcing follows it');
    is($c->{max_body}, 256 * 1024, 'sizes parsed from YAML');
    like($c->file, qr/apip\.yml\z/, 'the file is remembered');

    ok(!eval { Maat::Config->load("$dir/nope.yml") }, 'a missing file croaks');
    like($@, qr/cannot read/, 'saying which');

    write_file("$dir/bad.yml", "upstream: [this is\n  not: valid");
    ok(!eval { Maat::Config->load("$dir/bad.yml") }, 'invalid YAML croaks');

    write_file("$dir/empty.yml", "");
    ok(!eval { Maat::Config->load("$dir/empty.yml") }, 'an empty file croaks');
    like($@, qr/is empty/, 'saying so');
}

done_testing;
