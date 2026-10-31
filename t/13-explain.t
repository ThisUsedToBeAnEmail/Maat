#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Temp ();

# `apip explain` answers the question a customer asks before turning any
# of this on in front of real traffic: what will you actually check, and
# what will you do about it. The answer has to come from the same
# compiled spec the gateway serves from, or the tool and the thing it
# describes can disagree.

my $root = dist_root();
my $dir  = File::Temp::tempdir(CLEANUP => 1);

sub run_explain {
    my ($yaml, @args) = @_;
    my $cfg = write_file("$dir/explain.yml", $yaml);
    local $ENV{PERL5LIB} = join ':', "$root/lib", "$root/blib/lib",
        "$root/blib/arch", sibling_inc(),
        (defined $ENV{PERL5LIB} ? $ENV{PERL5LIB} : ());
    my $out = `$^X $root/bin/apip explain $cfg @args 2>&1`;
    return ($out, $? >> 8);
}

my $BASE = <<"YML";
upstream: http://127.0.0.1:9
spec: @{[ spec_path('petstore.json') ]}
mode: observe
YML

# ---- by method and path ------------------------------------------------------
{
    my ($out, $exit) = run_explain($BASE, 'GET', '/pets/42');
    is($exit, 0, 'explain exits 0 for an operation it found');
    like($out, qr{GET\s+/pets/\{petId\}}, 'the templated path, not the one asked for');
    like($out, qr/operationId\s+getPet/, 'the operationId');
    like($out, qr/path\s+petId\s+required/, 'the path parameter and that it must be there');
    like($out, qr/200\s+application\/json\s+checked against its schema/,
        'the status that will be checked');
    like($out, qr/mode\s+observe/, 'what it will do with a violation');
    like($out, qr/a response is never altered/,
        'and the promise that matters most');
}

# ---- by operationId ----------------------------------------------------------
{
    my ($out, $exit) = run_explain($BASE, 'deletePet');
    is($exit, 0, 'an operationId works too');
    like($out, qr{DELETE\s+/pets/\{petId\}}, 'resolved to the same operation');
    like($out, qr/cookie\s+session\s+required/, 'its cookie parameter');
    like($out, qr/no response schema declared/,
        'a status with no schema says so rather than implying coverage');
    like($out, qr/skip_schema/, 'and names the counter it will move');
}

# ---- what it says about sampling ---------------------------------------------
{
    my ($out) = run_explain($BASE . "responses:\n  sample: all\n", 'getPet');
    like($out, qr/every one is checked/, 'sample: all');

    ($out) = run_explain($BASE . "responses:\n  sample: 25\n", 'getPet');
    like($out, qr/one in 25 is checked/, 'a fixed divisor');

    ($out) = run_explain($BASE . "responses:\n  validate: false\n", 'getPet');
    like($out, qr/not checked/, 'and off says off');

    ($out) = run_explain($BASE . "responses:\n  budget: 5\n  floor: 30\n", 'getPet');
    like($out, qr/at most 5 a second/, 'the adaptive budget');
    like($out, qr/at least one every 30 seconds/, 'and the floor');
}

# ---- enforce ------------------------------------------------------------------
{
    my $yaml = $BASE;
    $yaml =~ s/mode: observe/mode: enforce/;
    my ($out) = run_explain($yaml, 'getPet');
    like($out, qr/answered here, not forwarded/,
        'enforce says the request will be answered by us');
}

# ---- what it does when it cannot answer --------------------------------------
{
    my ($out, $exit) = run_explain($BASE, 'GET', '/not-in-the-document');
    is($exit, 1, 'an unmatched path exits non-zero');
    like($out, qr/nothing in .* matches GET \/not-in-the-document/,
        'and says so');
    like($out, qr/counts it `undeclared`/,
        'naming what will happen instead - forwarded, not rejected');

    ($out, $exit) = run_explain($BASE, 'noSuchOperation');
    is($exit, 1, 'an unknown operationId exits non-zero');
    like($out, qr/no operation 'noSuchOperation'/, 'named');

    ($out, $exit) = run_explain($BASE);
    is($exit, 2, 'no arguments is a usage error');
    like($out, qr/usage: apip explain/, 'with the usage');
}

done_testing();
