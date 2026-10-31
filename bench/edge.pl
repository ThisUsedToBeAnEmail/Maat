#!/usr/bin/env perl
use 5.010;
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/../blib/arch";
use lib "$FindBin::Bin/../blib/lib";
use lib "$FindBin::Bin/../t/lib";
use lib "$FindBin::Bin/../lib";
use MaatTest;                 # puts the sibling blibs on @INC
use RegistryStub;
use Maat::Registry;
use Maat::Poller;
use Maat::Router;
use IO::Socket::INET ();
use Time::HiRes ();
use POSIX ();

# END TO END, over a real socket.
#
# Every other number in bench/ is in-process: the client is a function
# call, the upstream is a coderef, and the point of measuring it that way
# is to isolate what Maat ADDS to a request. This one measures what a
# customer's client actually gets - accept, HTTP parse, the fleet
# dispatch, the compiled request path, the response written back down a
# socket - because "requests per second" asked without qualification
# means this, and the capacity model should not be the only place a
# throughput figure appears.
#
# Mock-mode tenants, so there is no upstream round trip in the middle: a
# real proxied request is dominated by the upstream, which would bury the
# thing being measured. This is the ceiling the gateway itself imposes.
#
# Run:  perl bench/edge.pl [workers] [clients] [requests-per-client]

my $WORKERS = defined $ARGV[0] ? $ARGV[0] + 0 : 1;
my $CLIENTS = defined $ARGV[1] ? $ARGV[1] + 0 : 4;
my $PER     = defined $ARGV[2] ? $ARGV[2] + 0 : 5_000;
my $TENANTS = 50;

eval { require Hyperman; 1 }
    or die "bench/edge.pl needs Hyperman - it is the server under test\n";

# ---- a port nothing is on ---------------------------------------------------

my $probe = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Listen => 1, ReuseAddr => 1)
    or die "bench: cannot find a port: $!\n";
my $PORT = $probe->sockport;
close $probe;

# ---- the fleet under test ---------------------------------------------------

sub build_app {
    my $stub = RegistryStub->new(token => 'bench');
    $stub->add_tenant(host => "t$_.openapi-proxy.com", proxy => $_,
        plan => 'team', spec => RegistryStub->tenant_spec($_))
        for 1 .. $TENANTS;

    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
                                  max_specs => $TENANTS + 1);
    Maat::Poller->new(registry => $reg, url => 'http://bench/registry/bundle',
        token => 'bench', fetch => $stub->fetcher)->poll_once eq 'applied'
        or die "bench: the bundle did not apply\n";

    my $app = Maat::Router->new(registry => $reg)->to_app;

    # Compile every tenant before the clock starts: a lazy compile is a
    # first-request cost (capacity.pl measures it) and would otherwise
    # land inside the measurement.
    for my $i (1 .. $TENANTS) {
        my $env = MaatTest::psgi_env(path => '/hello');
        $env->{HTTP_HOST} = "t$i.openapi-proxy.com";
        MaatTest::run_app($app, $env);
    }
    return $app;
}

# ---- the server -------------------------------------------------------------

my $server = fork;
defined $server or die "bench: cannot fork the server: $!\n";
if (!$server) {
    POSIX::setsid();
    my $app = build_app();
    open STDERR, '>', '/dev/null';        # Hyperman's boot chatter
    Hyperman->run(app => $app, host => '127.0.0.1',
                  listen  => [ { port => $PORT } ],
                  workers => $WORKERS);
    POSIX::_exit(0);
}

# Wait for the listener rather than sleeping a guess.
my $up = 0;
for (1 .. 100) {
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $PORT,
                                  Proto => 'tcp', Timeout => 1);
    if ($s) { close $s; $up = 1; last }
    Time::HiRes::sleep(0.1);
}
$up or do { kill 'TERM', $server; die "bench: the server never came up\n" };

# ---- the load ---------------------------------------------------------------
#
# One keep-alive connection per client process, requests written and read
# serially on it. Not a pipelining flood: this measures what a normal
# client gets, and a pipelined number would flatter the server by
# amortising away the per-request read the real path pays.

sub client {
    my ($n) = @_;
    my $host = 't' . (($n % $TENANTS) + 1) . '.openapi-proxy.com';
    my $sock = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
        PeerPort => $PORT, Proto => 'tcp', Timeout => 5) or return 0;
    $sock->autoflush(1);

    my $req = "GET /hello HTTP/1.1\r\nHost: $host\r\n"
            . "User-Agent: bench\r\nConnection: keep-alive\r\n\r\n";
    my $ok = 0;
    for (1 .. $PER) {
        print {$sock} $req or last;
        # Read one whole response: headers, then Content-Length bytes.
        my $head = '';
        while ($head !~ /\r\n\r\n/) {
            my $chunk;
            defined sysread($sock, $chunk, 4096) && length $chunk or last;
            $head .= $chunk;
        }
        last unless $head =~ /\r\n\r\n/;
        my ($len) = $head =~ /Content-Length:\s*(\d+)/i;
        my ($hdr, $body) = split /\r\n\r\n/, $head, 2;
        $body = '' unless defined $body;
        while (defined $len && length($body) < $len) {
            my $chunk;
            defined sysread($sock, $chunk, 4096) && length $chunk or last;
            $body .= $chunk;
        }
        $ok++ if $head =~ m{\AHTTP/1\.[01] 200};
    }
    close $sock;
    return $ok;
}

my @kids;
my $t0 = Time::HiRes::time();
for my $n (1 .. $CLIENTS) {
    my $pid = fork;
    defined $pid or die "bench: cannot fork a client: $!\n";
    if (!$pid) { my $ok = client($n); POSIX::_exit($ok > 255 ? 255 : $ok) }
    push @kids, $pid;
}
waitpid $_, 0 for @kids;
my $dt = Time::HiRes::time() - $t0;

kill 'TERM', $server;
waitpid $server, 0;

# ---- the reading ------------------------------------------------------------

my $total = $CLIENTS * $PER;
printf "\nend to end, over loopback HTTP\n\n";
printf "  server            Hyperman, %d worker%s, plain (no TLS)\n",
    $WORKERS, $WORKERS == 1 ? '' : 's';
printf "  app               Maat::Router -> Maat::Gateway, %d mock tenants\n",
    $TENANTS;
printf "  load              %d client%s, keep-alive, %d requests each\n",
    $CLIENTS, $CLIENTS == 1 ? '' : 's', $PER;
printf "  wall              %.2f s\n", $dt;
printf "\n  %.0f req/s end to end   (%.1f us/req)\n\n",
    $total / $dt, $dt / $total * 1e6;
printf "  For comparison, bench/fleet.pl measures the same app in-process\n";
printf "  (no socket, no HTTP parse) - the difference between the two is\n";
printf "  what the server and the kernel cost, and it is most of it.\n";
