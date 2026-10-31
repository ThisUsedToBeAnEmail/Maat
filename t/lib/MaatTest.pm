package MaatTest;

use 5.010;
use strict;
use warnings;

# The shared machinery for Maat's tests:
#
#   - puts the sibling checkouts' blib directories on @INC, so the tests
#     run against the dependency versions phase 1 targets even when the
#     installed ones are older;
#   - a tiny forked HTTP upstream with an access log, so "the upstream
#     never saw it" is an assertion rather than a hope;
#   - a raw HTTP client, so the direct-to-upstream bytes can be compared
#     with the through-the-gateway bytes;
#   - PSGI plumbing: build an env, run an app whatever shape it answers
#     in, and normalise headers for the byte-identical comparison.

use Cwd ();
use File::Basename ();
use File::Temp ();
use IO::Socket::INET ();

my $ROOT;      # the Maat checkout
my $SEM;       # its parent, where the sibling checkouts live
my @SIBLING;   # the blib directories we put on @INC

BEGIN {
    $ROOT = Cwd::abs_path(File::Basename::dirname(__FILE__) . '/../..');
    $SEM  = File::Basename::dirname($ROOT);
    for my $dist (qw(
        JSON-Schema-Fast Fetch Open-API Reverse-Proxy
        Horus Hyperman File-Raw-JSON Legba
    )) {
        my $blib = "$SEM/$dist/blib";
        if (-d "$blib/arch") {
            unshift @INC, "$blib/lib", "$blib/arch";
            push @SIBLING, "$blib/lib", "$blib/arch";
        }
        else {
            # An unbuilt sibling is not "use the installed one instead" -
            # it is a silent version downgrade, and it wasted an evening:
            # Reverse-Proxy had no blib, the installed copy was 0.01
            # against a 0.03 prerequisite, and every test that proxies to
            # a real upstream failed in a way that looked like a bug in
            # whatever had just been changed. Say so once, loudly, rather
            # than let a stale @INC pose as a regression.
            warn "MaatTest: $dist has no blib - falling back to whatever "
               . "is installed, which may not be the version this "
               . "distribution requires. Build it: "
               . "(cd $SEM/$dist && perl Makefile.PL && make)\n";
        }
    }
}

use Exporter 'import';
our @EXPORT = qw(
    dist_root spec_path sibling_inc
    start_upstream stop_upstream upstream_log
    http_request
    psgi_env run_app header_get headers_hash
    normalise_headers
    write_file
);

sub dist_root   { $ROOT }
sub spec_path   { "$ROOT/t/spec/" . $_[0] }
sub sibling_inc { @SIBLING }

# ---- the upstream -----------------------------------------------------------
# One connection per request (it answers Connection: close), an access
# log line per request, and a deterministic echo body so the same
# request always produces the same bytes - which is what lets the
# byte-identical test compare direct against proxied.

sub start_upstream {
    my (%o) = @_;
    my $srv = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Listen    => 16,
        ReuseAddr => 1,
    ) or die "MaatTest: cannot listen: $!";
    my $port = $srv->sockport;
    my ($fh, $log) = File::Temp::tempfile(
        'maat-upstream-XXXXXX', TMPDIR => 1, UNLINK => 0);
    close $fh;

    my $pid = fork;
    die "MaatTest: fork: $!" unless defined $pid;
    if (!$pid) {
        local $SIG{TERM} = sub { exit 0 };
        while (my $c = $srv->accept) {
            _serve_one($c, $log, $o{respond});
            close $c;
        }
        exit 0;
    }
    close $srv;

    # Wait for it to answer before handing it to a test.
    for (1 .. 50) {
        my $probe = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => $port,
            Proto => 'tcp', Timeout => 1);
        if ($probe) { close $probe; last }
        select undef, undef, undef, 0.05;
    }
    return { port => $port, pid => $pid, log => $log };
}

sub _serve_one {
    my ($c, $log, $respond) = @_;
    my $head = '';
    while (defined(my $line = <$c>)) {
        $head .= $line;
        last if $line =~ /\A\r?\n\z/;
    }
    return unless length $head;
    my ($method, $target) = $head =~ /\A(\S+)\s+(\S+)/;
    my ($len) = $head =~ /^Content-Length:\s*(\d+)/im;
    my $body = '';
    if ($len) {
        my $got = 0;
        while ($got < $len) {
            my $n = read($c, my $chunk, $len - $got);
            last unless $n;
            $body .= $chunk;
            $got += $n;
        }
    }
    my ($rid) = $head =~ /^X-Request-Id:\s*(\S+)/im;

    if (open my $lf, '>>', $log) {
        print $lf join("\t", $method, $target, length($body),
                             defined $rid ? $rid : '-'), "\n";
        close $lf;
    }

    # A test that cares what the upstream says supplies a responder:
    #   respond => sub { my ($method, $target, $body, $head) = @_;
    #                    return ($status, \@headers, $body) }
    # Everything else gets the fixed text/plain answer, which is what
    # makes the byte-identical comparison possible.
    #
    # $head is the raw request head, headers included. It is the only way to
    # assert what did NOT reach the upstream - that a client's bearer token
    # was not forwarded, say - because the fixed echo below deliberately
    # reports method, target and body alone.
    if ($respond) {
        my ($status, $headers, $out) = $respond->($method, $target, $body, $head);
        $out = '' unless defined $out;
        my $h = join '', map { "$headers->[$_*2]: $headers->[$_*2+1]\r\n" }
                             0 .. (@$headers / 2 - 1);
        print $c "HTTP/1.1 $status OK\r\n"
               . $h
               . "Content-Length: " . length($out) . "\r\n"
               . "Connection: close\r\n"
               . "\r\n"
               . $out;
        return;
    }

    my $out = join("\n", "method=$method", "target=$target", "body=$body");
    print $c "HTTP/1.1 200 OK\r\n"
           . "Content-Type: text/plain\r\n"
           . "Content-Length: " . length($out) . "\r\n"
           . "X-Upstream: maat-test\r\n"
           . "ETag: \"maat-fixed\"\r\n"
           . "Set-Cookie: a=1; Path=/\r\n"
           . "Set-Cookie: b=2; Path=/\r\n"
           . "Connection: close\r\n"
           . "\r\n"
           . $out;
    return;
}

sub stop_upstream {
    my ($u) = @_;
    return unless $u && $u->{pid};
    kill 'TERM', $u->{pid};
    waitpid $u->{pid}, 0;
    unlink $u->{log} if $u->{log};
    delete $u->{pid};
    return;
}

sub upstream_log {
    my ($u) = @_;
    open my $fh, '<', $u->{log} or return ();
    my @lines = <$fh>;
    close $fh;
    chomp @lines;
    return map { my @f = split /\t/; {
        method => $f[0], target => $f[1], body_len => $f[2], rid => $f[3],
    } } @lines;
}

# ---- a raw client -----------------------------------------------------------
# Speak the request straight down a socket and hand back exactly what
# came up it, parsed but not interpreted.

sub http_request {
    my ($port, $method, $target, $headers, $body) = @_;
    $headers = [] unless $headers;
    $body    = '' unless defined $body;

    my $c = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port,
        Proto => 'tcp', Timeout => 5,
    ) or die "MaatTest: connect to :$port failed: $!";

    my $req = "$method $target HTTP/1.1\r\n"
            . "Host: 127.0.0.1:$port\r\n";
    for (my $i = 0; $i < @$headers; $i += 2) {
        $req .= "$headers->[$i]: $headers->[$i+1]\r\n";
    }
    $req .= "Content-Length: " . length($body) . "\r\n" if length $body;
    $req .= "Connection: close\r\n\r\n$body";
    print $c $req;

    # Read to the end of the message, not to the end of the socket.
    #
    # Reading until EOF makes the client's termination the SERVER's
    # decision: a server that keeps the connection open - which it is
    # entitled to do whatever we asked for - hangs the test forever, and
    # it does so intermittently, which is worse. So: headers first, then
    # exactly Content-Length bytes, with EOF only as the fall-back for a
    # response that declares no length. A read timeout underneath, so a
    # genuinely wedged server fails the test instead of stopping it.
    my $raw = '';
    my $deadline = time + 10;
    my $read_more = sub {
        vec(my $rin = '', fileno($c), 1) = 1;
        my $left = $deadline - time;
        return 0 if $left <= 0;
        return 0 unless select($rin, undef, undef, $left) > 0;
        my $n = sysread($c, my $chunk, 65536);
        return 0 if !defined $n || $n == 0;
        $raw .= $chunk;
        return 1;
    };

    $read_more->() while index($raw, "\r\n\r\n") < 0 && time < $deadline;
    my $sep = index($raw, "\r\n\r\n");
    die "MaatTest: no response headers from :$port after 10s\n" if $sep < 0;

    my $head_only = substr($raw, 0, $sep);
    if (my ($len) = $head_only =~ /^Content-Length:\s*(\d+)/im) {
        my $want = $sep + 4 + $len;
        $read_more->() while length($raw) < $want && time < $deadline;
    }
    elsif ($head_only !~ /^Transfer-Encoding:/im) {
        1 while $read_more->();          # no length declared: read to EOF
    }
    else {
        1 while $read_more->();          # chunked: the tests do not use it
    }
    close $c;

    my ($head, $rest) = split /\r\n\r\n/, $raw, 2;
    $rest = '' unless defined $rest;
    my @lines = split /\r\n/, $head;
    my $status_line = shift @lines;
    my ($status) = $status_line =~ m{\AHTTP/\d\.\d\s+(\d+)};
    my @h;
    for my $line (@lines) {
        my ($k, $v) = split /:\s*/, $line, 2;
        push @h, $k, $v;
    }
    return ($status, \@h, $rest);
}

# ---- PSGI plumbing ----------------------------------------------------------

sub psgi_env {
    my (%o) = @_;
    my $body = defined $o{body} ? $o{body} : '';
    open my $in, '<', \$body or die "MaatTest: psgi.input: $!";

    # PATH_INFO reaches a PSGI app percent-DECODED; REQUEST_URI does not.
    # That is RFC 3875, and it is what Maat actually runs behind:
    # Hyperman decodes the path exactly once on both the HTTP/1 and
    # HTTP/2 paths.
    #
    # Handing an app the raw form instead would describe a client who
    # typed its escapes twice - '%20' as PATH_INFO means the client
    # asked for '%2520' - and since Reverse::Proxy re-encodes the
    # forwarded target, the same request sent straight to the upstream
    # would then disagree byte for byte.
    my $raw  = defined $o{path} ? $o{path} : '/';
    my $path = $raw;
    $path =~ s/%([0-9A-Fa-f]{2})/pack 'C', hex $1/ge;    # %XX only, no '+'

    my %env = (
        REQUEST_METHOD    => $o{method} || 'GET',
        SCRIPT_NAME       => '',
        PATH_INFO         => $path,
        REQUEST_URI       => $raw
                           . (defined $o{query} && length $o{query}
                                ? "?$o{query}" : ''),
        QUERY_STRING      => defined $o{query} ? $o{query} : '',
        SERVER_NAME       => '127.0.0.1',
        SERVER_PORT       => 80,
        SERVER_PROTOCOL   => 'HTTP/1.1',
        HTTP_HOST         => '127.0.0.1',
        'psgi.version'    => [1, 1],
        'psgi.url_scheme' => 'http',
        'psgi.input'      => $in,
        'psgi.errors'     => \*STDERR,
        'psgi.multithread'  => 0,
        'psgi.multiprocess' => 0,
        'psgi.run_once'     => 0,
        'psgi.nonblocking'  => 0,
        'psgi.streaming'    => 1,
    );
    if (length $body) {
        $env{CONTENT_LENGTH} = length $body;
        $env{CONTENT_TYPE}   = $o{content_type} || 'application/json';
    }
    elsif (defined $o{content_type}) {
        $env{CONTENT_TYPE} = $o{content_type};
    }
    if ($o{headers}) {
        for (my $i = 0; $i < @{ $o{headers} }; $i += 2) {
            my $k = uc $o{headers}[$i];
            $k =~ tr/-/_/;
            $env{"HTTP_$k"} = $o{headers}[$i + 1];
        }
    }
    return \%env;
}

# Run a PSGI app and always come back with ($status, \@headers, $body),
# whatever shape the app answered in.
sub run_app {
    my ($app, $env) = @_;
    my $res = $app->($env);

    if (ref $res eq 'CODE') {
        my $triplet;
        my @written;
        $res->(sub {
            my ($r) = @_;
            $triplet = $r;
            if (@$r == 2) {
                return MaatTest::Writer->new(\@written);
            }
            return;
        });
        die "MaatTest: delayed app never called the responder" unless $triplet;
        my $body = @$triplet == 3 ? _body_string($triplet->[2])
                                  : join('', @written);
        return ($triplet->[0], $triplet->[1], $body);
    }
    die "MaatTest: unexpected app response: " . (ref($res) || 'scalar')
        unless ref $res eq 'ARRAY';
    return ($res->[0], $res->[1], _body_string($res->[2]));
}

sub _body_string {
    my ($b) = @_;
    return join '', @$b if ref $b eq 'ARRAY';
    if (ref $b) {                       # a handle
        local $/;
        my $s = <$b>;
        return defined $s ? $s : '';
    }
    return defined $b ? $b : '';
}

sub header_get {
    my ($headers, $name) = @_;
    $name = lc $name;
    my @got;
    for (my $i = 0; $i < @$headers; $i += 2) {
        push @got, $headers->[$i + 1] if lc $headers->[$i] eq $name;
    }
    return wantarray ? @got : $got[0];
}

sub headers_hash {
    my ($headers) = @_;
    my %h;
    for (my $i = 0; $i < @$headers; $i += 2) {
        push @{ $h{ lc $headers->[$i] } }, $headers->[$i + 1];
    }
    return \%h;
}

# The gate-1 comparison set: everything except the hop-by-hop headers
# (which a proxy owns by definition) and X-Request-Id (which Maat adds).
my %HOP = map { $_ => 1 } qw(
    connection keep-alive te trailer transfer-encoding upgrade
    proxy-authenticate proxy-authorization
);

sub normalise_headers {
    my ($headers) = @_;
    my @kept;
    for (my $i = 0; $i < @$headers; $i += 2) {
        my $k = lc $headers->[$i];
        next if $HOP{$k} || $k eq 'x-request-id';
        push @kept, [ $k, $headers->[$i + 1] ];
    }
    return [ sort { $a->[0] cmp $b->[0] || $a->[1] cmp $b->[1] } @kept ];
}

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or die "MaatTest: write $path: $!";
    print $fh $content;
    close $fh;
    return $path;
}

package MaatTest::Writer;

sub new { my ($c, $sink) = @_; return bless { sink => $sink }, $c }
sub write { my ($self, $chunk) = @_; push @{ $self->{sink} }, $chunk; return }
sub close { return }

1;
