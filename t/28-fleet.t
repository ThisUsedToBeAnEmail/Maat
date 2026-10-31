use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;
use File::Temp ();

use Maat::Fleet;

# The composition: the process an operator actually starts.
#
# Phase 6 and 7 left Registry, Poller, Router and Shard as four tested
# libraries with nothing owning them in a process, so a hosted deployment
# was four correct pieces and no data plane. This is the wiring, and what
# is worth testing about wiring is the order and the refusals - that a
# worker comes up holding tenants rather than filling in later, that a
# pool nobody hashes to is refused at boot rather than serving 404 to
# everybody, and that the bundle's per-domain certificates reach the
# listener.

my $CRT = "-----BEGIN CERTIFICATE-----\nMAAT-TEST-CERT\n-----END CERTIFICATE-----\n";
my $KEY = "-----BEGIN PRIVATE KEY-----\nMAAT-TEST-KEY\n-----END PRIVATE KEY-----\n";

sub stub_with_tenants {
    my ($n) = @_;
    my $stub = RegistryStub->new(token => 'reg-token');
    for my $i (1 .. $n) {
        $stub->add_tenant(host => "t$i.openapi-proxy.com", proxy => $i,
            plan => 'team', spec => RegistryStub->tenant_spec($i));
    }
    return $stub;
}

sub config {
    my (%o) = @_;
    return Maat::Fleet->from_hash({
        control_plane  => 'http://control.invalid',
        registry_token => 'reg-token',
        listen         => [ { port => 8080 } ],
        %o,
    }, '.');
}

sub fleet {
    my ($stub, %o) = @_;
    return Maat::Fleet->new(
        config     => $o{config} || config(%{ $o{config_args} || {} }),
        fetch      => $stub->fetcher,
        fetch_spec => $stub->spec_fetcher,
    );
}

# ---- the configuration -------------------------------------------------------

subtest 'the configuration is checked, and a typo is fatal' => sub {
    my $c = config();
    is $c->{control_plane}, 'http://control.invalid', 'the control plane is kept';
    is $c->{interval}, 15, 'the poll interval defaults';
    is $c->{max_bytes}, 256 * 1024 * 1024, 'and the memory cap, in bytes';

    eval { config(max_byte => '10M') };
    like $@, qr/unknown key 'max_byte'.*did you mean 'max_bytes'/,
        'a near-miss key is refused and named - a memory cap the operator '
      . 'believes is set is the one that matters';

    eval { Maat::Fleet->from_hash({ listen => [ { port => 80 } ],
        registry_token => 'x' }, '.') };
    like $@, qr/'control_plane' is required/, 'and a missing required key';

    eval { config(registry_token => { '$env' => 'NOT_SET_ANYWHERE_XYZ' }) };
    like $@, qr/NOT_SET_ANYWHERE_XYZ.*not set/,
        'a { $env: NAME } that is not set says which variable, not "must '
      . 'be a string"';

    local $ENV{APIP_TEST_TOKEN} = 'from-the-environment';
    is config(registry_token => { '$env' => 'APIP_TEST_TOKEN' })->{registry_token},
        'from-the-environment', 'and one that is set resolves';
};

subtest 'a pool nothing hashes to is refused at boot' => sub {
    my $stub = stub_with_tenants(2);

    eval { fleet($stub, config_args => { pools => { paid => 2 } }) };
    like $@, qr/'pools' needs 'pool'/,
        'a fleet shape with no slice named is refused';

    eval { fleet($stub, config_args => { pool => 'paid-0' }) };
    like $@, qr/'pool' needs 'pools'/, 'and a slice with no shape';

    eval { fleet($stub, config_args =>
        { pools => { paid => 2 }, pool => 'paid-7' }) };
    like $@, qr/pool 'paid-7' is not one of/,
        'a pool outside the fleet is refused here rather than starting, '
      . 'polling, filtering every tenant out and serving 404 to all of them';
    like $@, qr/paid-0, paid-1/, '...and the message lists the real ones';

    ok fleet($stub, config_args => { pools => { paid => 2 }, pool => 'paid-1' }),
        'a real pool builds';
};

# ---- the boot poll -----------------------------------------------------------

subtest 'a worker comes up holding tenants, not filling in later' => sub {
    my $stub  = stub_with_tenants(3);
    my $fleet = fleet($stub);

    is scalar @{ $fleet->registry->hosts }, 0, 'nothing before the poll';
    is $fleet->boot_poll, 'applied', 'the boot poll applies the bundle';
    is scalar @{ $fleet->registry->hosts }, 3,
        'so the first request finds a full tenant table - a worker that '
      . 'filled in fifteen seconds would 404 real traffic looking healthy';

    is $fleet->boot_poll, 'not_modified',
        'an unchanged bundle is a 304, not a re-apply';
};

subtest 'a failed boot poll is reported, not swallowed' => sub {
    my $stub  = stub_with_tenants(1);
    my $fleet = Maat::Fleet->new(
        config     => config(),
        fetch_spec => $stub->spec_fetcher,
        fetch      => sub { return { status => 503, headers => {}, body => '' } },
    );
    is $fleet->boot_poll, 'error',
        'the status word comes back so the caller can refuse to start';
    is scalar @{ $fleet->registry->hosts }, 0, 'and nothing is served';

    my $wrong = Maat::Fleet->new(
        config     => config(registry_token => 'not-the-shared-secret'),
        fetch_spec => $stub->spec_fetcher,
        fetch      => $stub->fetcher,
    );
    is $wrong->boot_poll, 'bad_signature',
        'a token that is not the control plane\'s is a signature failure, '
      . 'never a quietly empty fleet';
};

# ---- the app -----------------------------------------------------------------

subtest 'the app routes by host, and answers the edge cases itself' => sub {
    my $stub = stub_with_tenants(2);
    $stub->add_challenge('probe-token', 'probe-token.key-authorization');
    my $fleet = fleet($stub);
    $fleet->boot_poll;

    my $app = $fleet->app;
    my $call = sub {
        my ($host, $path) = @_;
        my $env = MaatTest::psgi_env(path => $path // '/hello');
        $env->{HTTP_HOST} = $host;
        return MaatTest::run_app($app, $env);
    };

    my ($status, $headers, $body) = $call->('t1.openapi-proxy.com');
    is $status, 200, 'a tenant hostname is served';
    is MaatTest::header_get($headers, 'X-Maat-Proxy'), 1,
        'attributed to its proxy';
    like $body, qr/"tenant":\s*1/,
        'answered from its own compiled spec, not a neighbour\'s';

    is +($call->('t2.openapi-proxy.com'))[0], 200, 'and so is the next one';
    is +($call->('nobody.openapi-proxy.com'))[0], 404,
        'a host the bundle does not carry is a 404 at the edge';

    my ($s, undef, $b) =
        $call->('anything.example', '/.well-known/acme-challenge/probe-token');
    is $s, 200, 'the ACME probe is answered for any host';
    is $b, 'probe-token.key-authorization', '...with its key authorization';
};

# ---- TLS ---------------------------------------------------------------------

subtest 'the bundle\'s domain certificates reach the listener' => sub {
    my $dir  = File::Temp->newdir;
    my $stub = stub_with_tenants(1);
    $stub->add_domain(host => 'api.customer.com', proxy => 1,
        tls_crt => $CRT, tls_key => $KEY);

    # A TLS listener needs real files to name, and Maat::Config checks
    # they are readable at load - so the wildcard is a temp file here.
    my $crt = "$dir/wild.crt";
    my $key = "$dir/wild.key";
    for my $pair ([ $crt, $CRT ], [ $key, $KEY ]) {
        open my $fh, '>', $pair->[0] or die $!;
        print $fh $pair->[1];
        close $fh;
    }

    # Nested and absent on purpose: /var/lib/maat/tls on a fresh box is
    # two levels of nothing.
    my $fleet = fleet($stub, config_args => {
        tls_dir => "$dir/made/up/tls",
        listen  => [ { port => 80 },
                     { port => 443, tls_cert => $crt, tls_key => $key } ],
    });
    $fleet->boot_poll;

    my $sni = $fleet->tls_sni;
    ok $sni->{'api.customer.com'}, 'the custom domain is in the SNI map';

    ok -d "$dir/made/up/tls", 'a tls_dir that does not exist yet is created';
    is +((stat "$dir/made/up/tls")[2] & 07777), 0700,
        '...0700, because the bundle unseals customers\' private keys into '
      . 'it - and Maat::Registry would otherwise not notice it was missing '
      . 'until the first domain arrived, weeks later';

    my $listen = $fleet->listeners;
    is scalar @$listen, 2, 'both listeners are passed through';
    ok !exists $listen->[0]{tls_sni},
        'the plain listener gets no SNI map - it is where http-01 is '
      . 'answered, and it terminates nothing';
    is_deeply $listen->[1]{tls_sni}, $sni,
        'and the TLS listener carries every domain certificate the bundle '
      . 'brought';
    is $listen->[1]{tls_cert}, $crt,
        'beside the wildcard, which is what every tenant hostname uses';
};

done_testing();
