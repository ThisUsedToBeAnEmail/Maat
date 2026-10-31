use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;

use Maat::Shard;
use Maat::Registry;
use Maat::Router;

# The blast-radius function (gate 5's topology half): free/anon tenants
# never share a pool with paid ones, and within a tier the pool is a
# stable hash of the host, so the edge and the workers agree without
# talking. Plus its integration with the registry, which uses it to keep
# only a pool's own tenants.

# ---- tier separation -------------------------------------------------------

{
    my $shard = Maat::Shard->new(pools => { paid => 4, free => 2 });
    like $shard->pool_for('anon',    'x.openapi-proxy.com'), qr/\Afree-/,
        'anon lands on a free pool';
    like $shard->pool_for('free',    'y.openapi-proxy.com'), qr/\Afree-/,
        'free lands on a free pool';
    like $shard->pool_for('starter', 'z.openapi-proxy.com'), qr/\Apaid-/,
        'starter lands on a paid pool';
    like $shard->pool_for('team',    'w.openapi-proxy.com'), qr/\Apaid-/,
        'team lands on a paid pool';
    like $shard->pool_for('business','v.openapi-proxy.com'), qr/\Apaid-/,
        'business lands on a paid pool';
    # an unknown plan (a control plane newer than the worker) is treated
    # as the cheapest tier, so the mistake risks free capacity
    like $shard->pool_for('enterprise-ultra', 'q.x'), qr/\Afree-/,
        'an unknown plan defaults to the free tier';
}

# ---- the hash is stable and reimplementable -------------------------------

{
    # FNV-1a is documented so an edge can compute the same answer. Pin a
    # couple of known vectors so a change to the function is caught.
    is Maat::Shard::fnv1a_32(''),     0x811c9dc5, 'FNV-1a of the empty string is the offset basis';
    is Maat::Shard::fnv1a_32('a'),    0xe40c292c, 'FNV-1a of "a" matches the reference';
    is Maat::Shard::fnv1a_32('foobar'), 0xbf9cf968, 'FNV-1a of "foobar" matches the reference';

    my $shard = Maat::Shard->new(pools => { paid => 8, free => 4 });
    my $host = 'acme.openapi-proxy.com';
    is $shard->pool_for('team', $host), $shard->pool_for('team', $host),
        'the same host maps to the same pool every time';
    is $shard->pool_for('team', uc $host), $shard->pool_for('team', $host),
        'the mapping is case-insensitive on the host';
}

# ---- member() is the filter a poller applies ------------------------------

{
    my $shard = Maat::Shard->new(pools => { paid => 3, free => 2 });
    my $host  = 'shop.openapi-proxy.com';
    my $pool  = $shard->pool_for('starter', $host);
    ok $shard->member($pool, 'starter', $host), 'a tenant is a member of its own pool';
    my ($other) = grep { $_ ne $pool } map { "paid-$_" } 0 .. 2;
    ok !$shard->member($other, 'starter', $host),
        'and is not a member of a different pool in its tier';
}

# ---- the registry keeps only its pool's tenants ---------------------------

{
    my $shard = Maat::Shard->new(pools => { paid => 2, free => 2 });

    # Build a fleet and find which paid pool the first paid host belongs
    # to, then stand a registry up as a worker in that pool.
    my $stub = RegistryStub->new;
    my @paid = map { "p$_.openapi-proxy.com" } 1 .. 20;
    my @free = map { "f$_.openapi-proxy.com" } 1 .. 20;
    my $i = 0;
    $stub->add_tenant(host => $_, proxy => ++$i, plan => 'team',
        spec => RegistryStub->tenant_spec($i)) for @paid;
    $stub->add_tenant(host => $_, proxy => ++$i, plan => 'anon',
        spec => RegistryStub->tenant_spec($i)) for @free;

    my $pool = $shard->pool_for('team', $paid[0]);
    my $reg  = Maat::Registry->new(fetch_spec => $stub->spec_fetcher,
        shard => $shard, pool => $pool);
    $reg->apply_bundle({ tenants => $stub->{tenants}, domains => [], challenges => [] });

    my %kept = map { $_ => 1 } @{ $reg->hosts };
    # Every kept host really maps to this pool; nothing from another pool
    # or the other tier leaked in.
    my $leaked = grep { $shard->member($pool, ($stub->{tenants}[$_]{plan}), $stub->{tenants}[$_]{host}) ? 0 : 1 }
                 grep { $kept{ $stub->{tenants}[$_]{host} } } 0 .. $#{ $stub->{tenants} };
    is $leaked, 0, 'the registry holds only tenants that shard to its pool';
    ok !grep({ $shard->tier_for($stub->{tenants}[$_]{plan}) eq 'free' && $kept{$stub->{tenants}[$_]{host}} } 0 .. $#{ $stub->{tenants} }),
        'no free-tier tenant leaked onto a paid pool';

    # A host that shards elsewhere is an unknown host to this worker - the
    # mis-routed-request case, answered 404 with zero blast radius.
    my $elsewhere = (grep { $shard->pool_for('team', $_) ne $pool } @paid)[0];
    is_deeply [ $reg->resolve($elsewhere) ], [],
        'a tenant that belongs to another pool is unknown here (a 404 at the edge)';
}

done_testing;
