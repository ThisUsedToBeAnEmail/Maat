use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;
use File::Temp ();
use IO::Socket::INET ();

# `apip check` is the pre-deploy gate: exit 1 on a bad config, a bad
# spec or a dead upstream, each with a message naming the fix. It runs
# here as a real child process, the way CI runs it.

my $root = dist_root();
my $bin  = "$root/bin/apip";
my $dir  = File::Temp::tempdir(CLEANUP => 1);
my $up   = start_upstream();

my $cfg_n = 0;
sub cfg_file {
    my ($yaml) = @_;
    return write_file("$dir/check-" . $cfg_n++ . ".yml", $yaml);
}

sub run_maat {
    my (@args) = @_;
    local $ENV{PERL5LIB} = join ':', "$root/lib", "$root/t/lib", sibling_inc(),
                                     (defined $ENV{PERL5LIB} ? $ENV{PERL5LIB} : ());
    my $cmd = join ' ', map { quotemeta } $^X, "-I$root/t/lib", "-MMaatTest", $bin, @args;
    my $out = `$cmd 2>&1`;
    return ($? >> 8, $out);
}

# A free port with nothing behind it, for the unreachable-upstream case.
my $dead_port = do {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Listen => 1, ReuseAddr => 1);
    my $p = $s->sockport;
    close $s;
    $p;
};

my $mini = spec_path('mini.json');

# ---- everything is right ----------------------------------------------------

{
    my $file = cfg_file(<<"YML");
upstream: http://127.0.0.1:$up->{port}
spec: $mini
YML
    my ($exit, $out) = run_maat('check', $file);
    is($exit, 0, 'check exits 0 when everything is right') or diag $out;
    like($out, qr/config/,   'reports the config loaded');
    like($out, qr/compiles; 1 operation\b/, 'reports the compiled operations');
    like($out, qr/upstream\s+127\.0\.0\.1:$up->{port} answers/, 'reports the probe');
    like($out, qr/`apip run/, 'says run will start');
}

# ---- an unknown config key --------------------------------------------------

{
    my $file = cfg_file(<<"YML");
upstrem: http://127.0.0.1:$up->{port}
spec: $mini
YML
    my ($exit, $out) = run_maat('check', $file);
    is($exit, 1, 'unknown key exits 1');
    like($out, qr/unknown key 'upstrem'/, 'names the offending key');
    like($out, qr/did you mean 'upstream'\?/, 'suggests the fix');
    like($out, qr/Fix that key/, 'tells the operator what to do');
}

# ---- a spec that does not compile -------------------------------------------

{
    my $broken = spec_path('broken.json');
    my $file = cfg_file(<<"YML");
upstream: http://127.0.0.1:$up->{port}
spec: $broken
YML
    my ($exit, $out) = run_maat('check', $file);
    is($exit, 1, 'bad spec exits 1');
    like($out, qr/did not compile/, 'says the spec did not compile');
    like($out, qr/broken\.json/, 'names the file');
    like($out, qr/refuse to start/, 'explains the consequence');
}

# ---- an upstream that does not answer ---------------------------------------

{
    my $file = cfg_file(<<"YML");
upstream: http://127.0.0.1:$dead_port
spec: $mini
YML
    my ($exit, $out) = run_maat('check', $file);
    is($exit, 1, 'dead upstream exits 1');
    like($out, qr/nothing is answering at 127\.0\.0\.1:$dead_port/,
         'names the address probed');
    like($out, qr/Start the upstream/, 'names the fix');
}

# ---- a config file that does not exist --------------------------------------

{
    my ($exit, $out) = run_maat('check', "$dir/absent.yml");
    is($exit, 1, 'missing config exits 1');
    like($out, qr/cannot read/, 'says why');
}

# ---- the command surface ----------------------------------------------------

{
    my ($exit, $out) = run_maat();
    is($exit, 1, 'no command exits 1');
    like($out, qr/usage: apip/, 'and prints usage');

    ($exit, $out) = run_maat('help');
    is($exit, 0, 'help exits 0');
    like($out, qr/APIP_CHAOS/, 'usage documents the chaos switch');

    ($exit, $out) = run_maat('frobnicate');
    is($exit, 1, 'unknown command exits 1');
    like($out, qr/unknown command 'frobnicate'/, 'and names it');
}

stop_upstream($up);
done_testing;
