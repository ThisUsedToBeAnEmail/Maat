use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Maat;
use Maat::Registry;
use Maat::Poller;

# Phase 12b: the C tenant table.
#
# What the phase-12 dispatcher will read per request instead of walking
# Perl - bench/fleet.pl measured that walk at 6.3us, 141% on top of the
# C path it guards. The table itself is only a cache over
# Maat::Registry, so the tests that matter here are about LIFETIME, not
# lookup: an entry must outlive a publish for exactly as long as a
# request is still finishing against it, and not one moment longer.

sub table { Maat::Fleet::Table->new }

subtest 'a published host is found, normalised the way a Host header arrives'
=> sub {
    my $t   = table();
    my $app = sub { [ 200, [], ['x'] ] };
    ok $t->publish('T1.Example.COM', { app => $app, proxy => 7,
        version => '4', max_body => 1024, concurrency => 3 }),
        'publish takes';

    for my $probe ('t1.example.com', 'T1.EXAMPLE.COM', 't1.example.com:8443') {
        ok $t->lookup($probe), "found as '$probe'";
    }
    ok !$t->lookup('nobody.example.com'), 'and an unknown host is not';

    my $e = $t->lookup('t1.example.com');
    is $e->{proxy}, 7, 'the proxy id rides along - the only metrics dimension';
    is $e->{version}, '4', 'and the version, for the stamp';
    is $e->{app}, $app, 'the app is the very coderef published, not a copy';
    is $e->{concurrency}, 3, 'caps are resolved once here, not merged per request';
};

subtest 'caps that arrive as nonsense fall back to the ceilings' => sub {
    my $t = table();
    $t->publish('a.example', { app => sub { }, max_body => 0,
                               max_header_bytes => -1, concurrency => 0 });
    my $e = $t->lookup('a.example');
    is $e->{max_body}, 16777216, 'a zero cap is not a licence to have none';
    is $e->{max_header_bytes}, 65536, '...nor a negative one';
    is $e->{concurrency}, 128, '...nor a missing concurrency ceiling';
};

subtest 'DIRECT is only for a bare gateway' => sub {
    my $t = table();
    my $gw = bless {}, 'Fake::Gateway';

    $t->publish('bare.example',   { app => sub { }, gw => $gw });
    $t->publish('wrapped.example',{ app => sub { }, gw => $gw, portal => 1 });
    $t->publish('poisoned.example',{ app => sub { }, gw => $gw, poison => 1 });
    $t->publish('closure.example', { app => sub { } });

    ok $t->lookup('bare.example')->{direct},
        'a bare gateway is callable at its C entry point';
    ok !$t->lookup('wrapped.example')->{direct},
        'a portal-wrapped host is not - DIRECT there would serve /docs as '
      . 'an API path';
    ok !$t->lookup('poisoned.example')->{direct},
        'a poisoned host is not - its 503 is a Perl closure';
    ok !$t->lookup('closure.example')->{direct},
        'and neither is an app with no gateway behind it at all';
};

subtest 'an app is required; anything else is refused rather than half-stored'
=> sub {
    my $t = table();
    ok !$t->publish('x.example', { proxy => 1 }), 'no app, no entry';
    ok !$t->lookup('x.example'), 'and nothing was left behind';
    ok !$t->publish('', { app => sub { } }), 'no host, no entry';
};

# ---- the property the whole file exists for --------------------------------

subtest 'a publish under load does not disturb the request in flight' => sub {
    my $t = table();
    my ($v4, $v5) = (sub { 'four' }, sub { 'five' });

    $t->publish('a.example', { app => $v4, version => '4' });
    my $held = $t->acquire('a.example');          # a request starts on v4
    ok $held, 'a request takes a reference';
    is $t->lookup('a.example')->{inflight}, 1, 'and is counted in flight';

    $t->publish('a.example', { app => $v5, version => '5' });   # the publish
    is $t->lookup('a.example')->{version}, '5',
        'every NEW request gets the new version immediately';
    is $t->lookup('a.example')->{inflight}, 0,
        '...on an entry with no in-flight requests of its own';

    my $s = $t->stats;
    is $s->{live}, 1, 'one live entry';
    is $s->{waiting}, 1, 'and the old one waiting on its last request';
    is $s->{freed}, 0, 'nothing freed while somebody is still inside it';
    is $t->drain, 0, 'a drain cannot take it either - refcount, not a timer';

    $t->done($held);                              # the old request finishes
    is $t->stats->{freed}, 1, 'the last one out frees it';
    is $t->stats->{waiting}, 0, 'and the retired list empties';
};

subtest 'retire keeps a held entry alive, and the table forgets it at once'
=> sub {
    my $t = table();
    $t->publish('gone.example', { app => sub { } });
    my $held = $t->acquire('gone.example');

    ok $t->retire('gone.example'), 'the host is retired';
    ok !$t->lookup('gone.example'),
        'and is unfindable immediately - a tenant that left the bundle '
      . 'stops being served on the poll that removed it';
    is $t->stats->{waiting}, 1, 'while the request inside it holds on';
    $t->done($held);
    is $t->stats->{waiting}, 0, 'and lets go when it is done';

    ok !$t->retire('never.published.example'),
        'retiring a host that was never published is a no-op, not a crash';
};

subtest 'many publishes over one host leave nothing behind' => sub {
    my $t = table();
    $t->publish('churn.example', { app => sub { }, version => $_ })
        for 1 .. 50;
    my $s = $t->stats;
    is $s->{live}, 1, 'one live entry after fifty publishes';
    is $s->{published}, 50, 'all fifty counted';
    is $s->{retired}, 49, 'forty-nine retired';
    is $s->{freed}, 49, '...and every one of them freed, none held';
    is $s->{waiting}, 0, 'nothing waiting';
    is $t->lookup('churn.example')->{version}, 50, 'the last one serves';
};

# ---- the seam with Maat::Registry ------------------------------------------

subtest 'the registry publishes what it compiles, and retires what it drops'
=> sub {
    my $stub = RegistryStub->new(token => 'tok');
    $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 11, version => 4,
        plan => 'team', spec => RegistryStub->tenant_spec(11));
    $stub->add_tenant(host => 'b.openapi-proxy.com', proxy => 12, version => 1,
        plan => 'free', spec => RegistryStub->tenant_spec(12));

    my $reg = Maat::Registry->new(
        fetch_spec => $stub->spec_fetcher,
        # The caps hook: resolved once per compile here rather than
        # merged per request in the router.
        caps => sub {
            my ($meta) = @_;
            return { max_body => 2048, max_header_bytes => 4096,
                     concurrency => ($meta->{plan} eq 'team' ? 64 : 8) };
        },
    );
    my $poller = Maat::Poller->new(registry => $reg,
        url => 'http://control/registry/bundle', token => 'tok',
        fetch => $stub->fetcher);
    is $poller->poll_once, 'applied', 'the bundle applies';

    ok $reg->table, 'the registry built a table';
    ok !$reg->table->lookup('a.openapi-proxy.com'),
        'nothing is published before the first request - the compile is '
      . 'lazy and so is the table';

    my ($app) = $reg->resolve('a.openapi-proxy.com');
    ok $app, 'the host resolves';
    my $e = $reg->table->lookup('a.openapi-proxy.com');
    ok $e, 'and is published to the table by the compile';
    is $e->{proxy}, 11, 'with its proxy id';
    is $e->{version}, 4, 'its version';
    is $e->{concurrency}, 64, 'and the caps the hook resolved for its plan';
    is $e->{app}, $app, 'the app is the one resolve just handed out';
    ok $e->{direct},
        'a bare gateway tenant is DIRECT - which is the entire point of '
      . 'phase 12';

    $reg->resolve('b.openapi-proxy.com');
    is $reg->table->lookup('b.openapi-proxy.com')->{concurrency}, 8,
        'the free tenant gets the free ceiling';

    # A tenant leaving the bundle takes its table entry with it.
    $stub->clear_tenants;
    $stub->add_tenant(host => 'a.openapi-proxy.com', proxy => 11, version => 4,
        plan => 'team', spec => RegistryStub->tenant_spec(11));
    is $poller->poll_once, 'applied', 'the removal bundle applies';
    ok !$reg->table->lookup('b.openapi-proxy.com'),
        'the departed tenant is out of the table too, within one poll';
    ok $reg->table->lookup('a.openapi-proxy.com'),
        '...and the one that stayed is untouched';
};

subtest 'a republish moves the table entry with the compiled one' => sub {
    my $stub = RegistryStub->new(token => 'tok');
    $stub->add_tenant(host => 'c.openapi-proxy.com', proxy => 21, version => 1,
        plan => 'team', spec => RegistryStub->tenant_spec(21));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher);
    my $poller = Maat::Poller->new(registry => $reg,
        url => 'http://control/registry/bundle', token => 'tok',
        fetch => $stub->fetcher);
    $poller->poll_once;
    $reg->resolve('c.openapi-proxy.com');
    is $reg->table->lookup('c.openapi-proxy.com')->{version}, 1,
        'version 1 is published';

    # A new spec under the same host: a different digest, so the compiled
    # entry is dropped and rebuilt on the next request.
    $stub->clear_tenants;
    $stub->add_tenant(host => 'c.openapi-proxy.com', proxy => 21, version => 2,
        plan => 'team', spec => RegistryStub->tenant_spec(99));
    $poller->poll_once;
    ok !$reg->table->lookup('c.openapi-proxy.com'),
        'the publish retires the stale entry rather than serving it';

    $reg->resolve('c.openapi-proxy.com');
    is $reg->table->lookup('c.openapi-proxy.com')->{version}, 2,
        'and the next request republishes at the new version';
};

subtest 'the table is an accelerator, never the record' => sub {
    # Explicitly table-less: everything must still work. This is the
    # fallback the dispatcher relies on for any host it cannot find, and
    # the reason a bug in the table can cost speed and nothing else.
    my $stub = RegistryStub->new(token => 'tok');
    $stub->add_tenant(host => 'd.openapi-proxy.com', proxy => 31, version => 1,
        plan => 'free', spec => RegistryStub->tenant_spec(31));
    my $reg = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
                                  table => undef);
    Maat::Poller->new(registry => $reg, url => 'http://control/registry/bundle',
        token => 'tok', fetch => $stub->fetcher)->poll_once;

    ok !$reg->table, 'no table at all';
    my ($app, $meta) = $reg->resolve('d.openapi-proxy.com');
    ok $app, 'and resolve still answers';
    is $meta->{proxy}, 31, 'with the tenant it always answered with';
    is scalar @{ $reg->hosts }, 1, 'the registry is unchanged in every way';
};

subtest 'an MCP endpoint rides along without costing the API path' => sub {
    # The portal wraps the gateway and so takes DIRECT away from the whole
    # tenant. MCP must not: its branch answers /mcp BEFORE the tenant app is
    # entered at all, so the API path is exactly what it was. That is the
    # whole reason it is a flag and a path compare rather than a wrapper.
    my $t   = table();
    my $gw  = bless {}, 'Maat::Gateway';
    my $mcp = sub { [ 200, [], ['mcp'] ] };

    $t->publish('with.example', { app => sub { }, gw => $gw, mcp => $mcp });
    $t->publish('without.example', { app => sub { }, gw => $gw });

    my $e = $t->lookup('with.example');
    ok $e->{mcp},    'the tenant is flagged as serving MCP';
    ok $e->{direct}, 'and keeps its direct C entry point for everything else';

    my $p = $t->lookup('without.example');
    ok !$p->{mcp},  'a tenant without one is not flagged';
    ok $p->{direct}, 'and is unchanged';

    # A flag with no app behind it would be a branch into nothing.
    $t->publish('empty.example', { app => sub { }, gw => $gw, mcp => undef });
    ok !$t->lookup('empty.example')->{mcp},
        'an undef endpoint does not arm the flag';

    # Belt and braces the other way: the portal still clears DIRECT even
    # when MCP is on, because a portal-wrapped app must go through Perl.
    $t->publish('both.example',
        { app => sub { }, gw => $gw, mcp => $mcp, portal => 1 });
    my $b = $t->lookup('both.example');
    ok $b->{mcp},     'MCP is flagged beside the portal';
    ok !$b->{direct}, 'but the portal still takes DIRECT away';
};

done_testing;
