use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use Test::More;
use File::Spec ();

use Maat::Remote;

# Phase 8, gate 1: every UI action has a CLI equivalent, enumerated in a
# test that walks the mounted spec's operations and fails on one the CLI
# cannot reach.
#
# The house rule this defends, from Punk::Queue: a write action that
# exists only in a browser is one you cannot perform at 3am. An
# intention decays; a failing build does not.

# The control plane's published document. It lives in the site
# repository - the CLI is a client of that contract, not its owner - so
# this test finds it where a developer checkout puts it and skips
# politely when only one of the two is present.
my $SPEC = $ENV{MAAT_SITE_SPEC};
unless (defined $SPEC && -r $SPEC) {
    for my $guess (
        File::Spec->catfile('..', 'Web', 'Maat-Site', 'share', 'openapi.json'),
        File::Spec->catfile('..', '..', 'Web', 'Maat-Site', 'share', 'openapi.json'),
    ) {
        next unless -r $guess;
        $SPEC = $guess;
        last;
    }
}

plan skip_all => 'the control plane document is not in this checkout '
               . '(set MAAT_SITE_SPEC to point at share/openapi.json)'
    unless defined $SPEC && -r $SPEC;

require Open::API;
my $api = eval { Open::API->new(spec => $SPEC) };
plan skip_all => "the control plane document does not compile here: $@"
    unless $api;

my @ops = sort map { $_->{operationId} }
          grep { defined $_->{operationId} } @{ $api->operations };
ok scalar @ops, 'the control plane document declares operations';

my $covered = Maat::Remote->coverage;

# ---- the gate ---------------------------------------------------------------

{
    my @unreachable = grep { !$covered->{$_} } @ops;
    is_deeply \@unreachable, [],
        'every published operation has a CLI command'
        or diag "no command reaches: @unreachable\n"
              . "add one to bin/apip and name it in Maat::Remote::%COVERAGE";
}

# The other direction, which matters just as much: a command claiming to
# reach an operation the API no longer has is a command that will fail
# in a customer's pipeline with a 404 and no explanation.
{
    my %published = map { $_ => 1 } @ops;
    my @phantom = sort grep { !$published{$_} } keys %$covered;
    is_deeply \@phantom, [],
        'and no command claims an operation the API does not publish';
}

# ---- the map is usable, not just present ------------------------------------

{
    my $bad = 0;
    for my $op (sort keys %$covered) {
        my ($command, $usage) = @{ $covered->{$op} };
        $bad++, diag "$op has no command" unless defined $command && length $command;
        $bad++, diag "$op has no usage line" unless defined $usage && length $usage;
        $bad++, diag "$op usage does not start with 'apip'"
            unless ($usage // '') =~ /^apip /;
    }
    is $bad, 0, 'each entry names a command and shows how to invoke it';
}

# Every command named in the map is a command bin/apip actually
# dispatches - the first word, since subcommands are arguments.
{
    my $cli = File::Spec->catfile('bin', 'apip');
    plan skip_all => 'bin/apip is not in this checkout' unless -r $cli;

    open my $fh, '<', $cli or die "cannot read $cli: $!";
    my $src = do { local $/; <$fh> };
    close $fh;

    my ($table) = $src =~ /my \%COMMANDS = \((.*?)\n\);/s;
    ok $table, 'bin/apip has a command table';
    my %dispatch = map { $_ => 1 } $table =~ /^\s*(\w+)\s*=>/gm;

    my @missing;
    for my $op (sort keys %$covered) {
        my ($first) = split ' ', $covered->{$op}[0];
        push @missing, "$op -> $first" unless $dispatch{$first};
    }
    is_deeply \@missing, [],
        'and every command in the map is one bin/apip dispatches';
}

# `apip operations` is how an operator asks the same question this test
# asks. If it stopped printing the map, the answer would be silence.
{
    my @lines = Maat::Remote->coverage_lines;
    is scalar @lines, scalar keys %$covered,
        'coverage_lines renders every entry';
    like $lines[0], qr/^\w+\t\S.*\tapip /,
        '...as operationId, command, usage';
}

done_testing;
