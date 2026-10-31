use 5.010;
use strict;
use warnings;
use ExtUtils::MakeMaker;

# Maat - the openapi-proxy.com data plane.
#
# The request path is XS (Maat.xs, include/mt_*.h). Not because any one
# line of the Perl was slow - measured, the counters were 0.09us each and
# the three eval blocks 0.04us together - but because the shape was: a
# dozen Perl ops and four Perl/XS crossings per request for two calls'
# worth of work. One C function removes all of them at once.
#
# Everything expensive it calls is already C elsewhere: Open::API
# compiles and validates in C, Reverse::Proxy forwards in C through
# Fetch's ABI. This distribution is the policy between them.

my %WriteMakefileArgs = (
    NAME             => 'Maat',
    AUTHOR           => ['LNATION <email@lnation.org>'],
    VERSION_FROM     => 'lib/Maat.pm',
    ABSTRACT_FROM    => 'lib/Maat.pm',
    LICENSE          => 'artistic_2',
    MIN_PERL_VERSION => '5.010000',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },
    TEST_REQUIRES => {
        'Test::More' => '0',
    },
    PREREQ_PM => {
        'Open::API'       => '0.13',   # + operation_schema/_doc, component $refs
        'JSON::Schema::Fast' => '0.10',# tool argument validators, compiled once
        # The forwarding half, C via Fetch. 0.04 and not 0.03: 0.04 is the
        # release that re-encodes the forwarded request target. PATH_INFO
        # reaches a PSGI app percent-DECODED, so before it a client URL
        # holding %0d%0a arrived as a real CRLF and was spliced into the
        # upstream request line, which is request smuggling straight past
        # whatever this gateway enforces. 0.06 is what is tested here.
        'Reverse::Proxy'  => '0.06',
        'File::Raw::JSON' => '0.05',   # problem+json, spec reads
        'Horus'           => '0.09',   # uuid_v7 request ids
        'Legba'           => '0.08',   # the rate limiter's Legba-anchored counter
        'Digest::SHA'     => '0',      # key hashing, constant-time compare (core)
        'Crypt::JWS'      => '0.07',   # C ABI: sha256 + constant-time compare on /mcp
        'YAML::XS'        => '0',      # apip.yml
        'IO::Compress::Gzip' => '0',   # shipping batches (core)
        'Fetch'           => '0',      # shipping them
    },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        prereqs => {
            runtime => {
                recommends => {
                    # `apip run` hosts on Hyperman for the event loop and
                    # TLS; any PSGI server serves the same app, blocking.
                    'Hyperman' => '0.45',
                },
            },
        },
    },
    # `apip` is the gateway a customer runs and the control plane from a
    # terminal; `apip-fleet` is the hosted data plane, which is one
    # process holding every tenant the control plane publishes. Two
    # programs because they are configured by different things - a
    # document and an upstream, against a control plane and a pool - and
    # a single binary that meant both would need a mode flag to tell an
    # operator which one they had started. `fleet_server` is the process
    # manager for the second of those on a box with no service manager -
    # start/stop/restart/status, the shape openapi-proxy.com's own
    # bin/prod_server has, so the two boxes take the same commands.
    EXE_FILES => ['bin/apip', 'bin/apip-fleet', 'bin/fleet_server'],
    INC   => '-Iinclude',
    # MakeMaker maps Maat.xs -> Maat.c and does not rescan the headers it
    # includes, so a change to include/*.h would silently do nothing.
    depend => {
        'Maat$(OBJ_EXT)' => join(' ', glob('include/*.h')),
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Maat-*' },
);

unless (eval { ExtUtils::MakeMaker->VERSION('6.64'); 1 }) {
    my $test_requires = delete $WriteMakefileArgs{TEST_REQUIRES} || {};
    @{$WriteMakefileArgs{PREREQ_PM}}{keys %$test_requires} = values %$test_requires;
}
delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
    unless eval { ExtUtils::MakeMaker->VERSION('6.52'); 1 };
delete $WriteMakefileArgs{MIN_PERL_VERSION}
    unless eval { ExtUtils::MakeMaker->VERSION('6.48'); 1 };
delete $WriteMakefileArgs{LICENSE}
    unless eval { ExtUtils::MakeMaker->VERSION('6.31'); 1 };

WriteMakefile(%WriteMakefileArgs);
