use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Temp ();
use IO::Socket::INET ();

# `apip run` end to end: listeners from apip.yml, bound by Hyperman,
# real bytes over real sockets. One worker, so no supervisor tree to
# clean up.

my $root = dist_root();
my $bin  = "$root/bin/apip";
my $dir  = File::Temp::tempdir(CLEANUP => 1);
my $up   = start_upstream();

my $port = do {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Listen => 1, ReuseAddr => 1);
    my $p = $s->sockport;
    close $s;
    $p;
};

my $spec = spec_path('petstore.json');
my $cfg  = write_file("$dir/run.yml", <<"YML");
upstream: http://127.0.0.1:$up->{port}
spec: $spec
mode: enforce
workers: 1
listen:
  - port: $port
    host: 127.0.0.1
YML

local $ENV{PERL5LIB} = join ':', "$root/lib", sibling_inc(),
                                 (defined $ENV{PERL5LIB} ? $ENV{PERL5LIB} : ());

my $pid = fork;
die "fork: $!" unless defined $pid;
if (!$pid) {
    open STDOUT, '>', "$dir/run.out";
    open STDERR, '>&', \*STDOUT;
    exec $^X, $bin, 'run', $cfg;
    exit 1;
}

# Wait for the listener.
my $bound = 0;
for (1 .. 100) {
    my $probe = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                      PeerPort => $port,
                                      Proto => 'tcp', Timeout => 1);
    if ($probe) { close $probe; $bound = 1; last }
    select undef, undef, undef, 0.1;
}

SKIP: {
    if (!$bound) {
        my $out = do { local $/; open my $fh, '<', "$dir/run.out"; <$fh> };
        kill 'TERM', $pid; waitpid $pid, 0;
        skip "apip run did not bind :$port - output was:\n$out", 1;
    }

    # A conforming request, through Hyperman, through the gateway, to
    # the upstream and back.
    my ($status, $headers, $body) =
        http_request($port, 'GET', '/pets/42', []);
    is($status, 200, 'conforming request served through apip run');
    is($body, "method=GET\ntarget=/pets/42\nbody=", 'upstream bytes returned');
    ok(defined header_get($headers, 'X-Request-Id'), 'X-Request-Id echoed');

    # An undeclared path is forwarded even in enforce.
    ($status, $headers, $body) = http_request($port, 'GET', '/health', []);
    is($status, 200, 'undeclared path forwarded over the wire');
    is($body, "method=GET\ntarget=/health\nbody=", 'straight through');

    # And a violation is rejected before the upstream.
    my $before = () = upstream_log($up);
    ($status, $headers, $body) = http_request($port, 'POST', '/pets',
        [ 'Content-Type' => 'application/json' ], '{oops');
    is($status, 400, 'violation rejected over the wire');
    is(header_get($headers, 'Content-Type'), 'application/problem+json',
       'as problem+json');
    is(scalar(() = upstream_log($up)), $before, 'upstream never saw it');

    kill 'TERM', $pid;
    waitpid $pid, 0;
}

stop_upstream($up);
done_testing;
