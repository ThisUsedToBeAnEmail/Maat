use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;
use File::Temp ();

use Maat::Fleet;
use Maat::Registry;

# Before anything localises Hyperman::tls_reload below. Maat::Fleet
# requires Hyperman lazily, inside new, so a load that happens after the
# local would run XSLoader and install the real XS sub straight over it -
# the override would vanish and the test would quietly assert nothing.
use Hyperman ();

# Serving a certificate that arrives after the process started.
#
# The registry writes it to tls_dir within one poll and routes the host
# immediately, but a listener's SSL context was built before the first
# fork - so without a reload the customer's domain is verified, issued,
# routed, and still fails the handshake until somebody restarts. This is
# the signal that closes that gap: when the materialised certificate set
# moves, and only then, the fleet asks Hyperman to rebuild.

my $CRT = "-----BEGIN CERTIFICATE-----\nMAAT-TEST-CERT\n-----END CERTIFICATE-----\n";
my $KEY = "-----BEGIN PRIVATE KEY-----\nMAAT-TEST-KEY\n-----END PRIVATE KEY-----\n";
my $CRT2 = "-----BEGIN CERTIFICATE-----\nMAAT-RENEWED\n-----END CERTIFICATE-----\n";

sub stub {
    my $s = RegistryStub->new(token => 'reg-token');
    $s->add_tenant(host => 't1.openapi-proxy.com', proxy => 1,
        plan => 'team', spec => RegistryStub->tenant_spec(1));
    return $s;
}

sub registry_with {
    my ($dir, $stub) = @_;
    my @seen;
    my $reg = Maat::Registry->new(
        fetch_spec    => $stub->spec_fetcher,
        tls_dir       => $dir,
        on_tls_change => sub { push @seen, $_[0] },
    );
    return ($reg, \@seen);
}

sub apply {
    my ($reg, $stub) = @_;
    $reg->apply_bundle({ tenants    => $stub->{tenants},
                         domains    => $stub->{domains},
                         challenges => [] });
    return;
}

# ---- the generation only moves when the certificates do ---------------------
{
    my $dir  = File::Temp->newdir;
    my $stub = stub();
    my ($reg, $seen) = registry_with("$dir", $stub);

    apply($reg, $stub);
    is $reg->tls_generation, 0, 'a bundle with no domains moves nothing';
    is scalar @$seen, 0, '...and the callback is not called';

    $stub->add_domain(host => 'api.customer.com', proxy => 1,
        tls_crt => $CRT, tls_key => $KEY);
    apply($reg, $stub);
    is $reg->tls_generation, 1, 'a domain arriving moves the generation';
    is scalar @$seen, 1, '...and calls the callback once';
    ok $seen->[-1]{'api.customer.com'}, '...with the new SNI map';
    is_deeply [ sort keys %{ $seen->[-1]{'api.customer.com'} } ], [qw(cert key)],
        '...carrying cert and key only, not this file\'s bookkeeping';

    # The case a stable fleet is in on almost every poll. If this moved,
    # every worker would rebuild an SSL context every fifteen seconds
    # for nothing.
    apply($reg, $stub);
    is $reg->tls_generation, 1, 'the same bundle again moves nothing';
    is scalar @$seen, 1, '...and does not call the callback';
}

# ---- a renewal is the same host at the same path, different bytes -----------
{
    my $dir  = File::Temp->newdir;
    my $stub = stub();
    my ($reg, $seen) = registry_with("$dir", $stub);
    $stub->add_domain(host => 'api.customer.com', proxy => 1,
        tls_crt => $CRT, tls_key => $KEY);
    apply($reg, $stub);
    is $reg->tls_generation, 1, 'issued';

    # The path is derived from the hostname and never moves, so only the
    # bytes say a renewal happened - which is the case a listener most
    # needs telling about, and the one a path comparison would miss.
    $stub->{domains}[0]{tls_crt} = $CRT2;
    apply($reg, $stub);
    is $reg->tls_generation, 2, 'a renewal at the same path moves it';
    is scalar @$seen, 2, '...and calls the callback again';
}

# ---- a domain leaving ------------------------------------------------------
{
    my $dir  = File::Temp->newdir;
    my $stub = stub();
    my ($reg, $seen) = registry_with("$dir", $stub);
    $stub->add_domain(host => 'api.customer.com', proxy => 1,
        tls_crt => $CRT, tls_key => $KEY);
    apply($reg, $stub);

    $stub->{domains} = [];
    apply($reg, $stub);
    is $reg->tls_generation, 2, 'a domain removed moves it too';
    is_deeply $seen->[-1], {}, '...and the map it hands over is empty';
}

# ---- the fleet asks Hyperman, and only when it should ----------------------
{
    my $dir  = File::Temp->newdir;
    my $crt  = "$dir/w.crt";
    my $key  = "$dir/w.key";
    for my $p ([ $crt, $CRT ], [ $key, $KEY ]) {
        open my $fh, '>', $p->[0] or die $!;
        print $fh $p->[1];
        close $fh;
    }

    my $stub = stub();
    my @reloads;
    my $fleet;
    {
        no warnings 'redefine', 'once';
        local *Hyperman::tls_reload = sub { push @reloads, $_[1]; 1 };

        $fleet = Maat::Fleet->new(
            config => Maat::Fleet->from_hash({
                control_plane  => 'http://control.invalid',
                registry_token => 'reg-token',
                tls_dir        => "$dir/tls",
                listen => [ { port => 80 },
                            { port => 443, tls_cert => $crt, tls_key => $key } ],
            }, '.'),
            fetch      => $stub->fetcher,
            fetch_spec => $stub->spec_fetcher,
        );

        apply($fleet->registry, $stub);
        is scalar @reloads, 0, 'no domains, no reload';

        $stub->add_domain(host => 'api.customer.com', proxy => 1,
            tls_crt => $CRT, tls_key => $KEY);
        apply($fleet->registry, $stub);
        is scalar @reloads, 1, 'a domain arriving asks Hyperman to rebuild';
        ok $reloads[-1]{'api.customer.com'}, '...with the domain in the map';

        apply($fleet->registry, $stub);
        is scalar @reloads, 1, 'an unchanged bundle asks for nothing';
    }
}

# ---- the guards ------------------------------------------------------------
{
    my $dir  = File::Temp->newdir;
    my $stub = stub();

    my $plain = Maat::Fleet->new(
        config => Maat::Fleet->from_hash({
            control_plane  => 'http://control.invalid',
            registry_token => 'reg-token',
            listen         => [ { port => 80 } ],
        }, '.'),
        fetch      => $stub->fetcher,
        fetch_spec => $stub->spec_fetcher,
    );
    ok !$plain->registry->{on_tls_change},
        'a fleet with no TLS listener never wires the reload - that is the '
      . 'deployment with a balancer in front, and it must cost nothing';

    my $off = Maat::Fleet->new(
        config => Maat::Fleet->from_hash({
            control_plane  => 'http://control.invalid',
            registry_token => 'reg-token',
            tls_reload     => 0,
            listen         => [ { port => 80 } ],
        }, '.'),
        fetch      => $stub->fetcher,
        fetch_spec => $stub->spec_fetcher,
    );
    ok !$off->registry->{on_tls_change}, 'and tls_reload: false turns it off';
}

done_testing;
