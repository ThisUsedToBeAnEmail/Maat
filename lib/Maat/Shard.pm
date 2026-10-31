package Maat::Shard;

use 5.010;
use strict;
use warnings;
use Carp ();

our $VERSION = '0.04';

# Which worker pool serves a tenant. Two decisions, deliberately simple:
#
#   1. The TIER: free and anonymous tenants never share a pool with paid
#      ones. The free tier is where the abuse arrives - a pasted spec
#      from a stranger must not be able to take a paying customer's pool
#      down with it.
#   2. The SHARD within the tier: a stable hash of the hostname. A bug
#      that takes one pool down takes 1/Nth of that tier's customers
#      with it, and the same host always lands on the same pool, so the
#      edge and the workers can compute the answer independently and
#      agree.
#
# The hash is FNV-1a: stable across processes, machines and perl
# versions, trivially reimplementable at the edge (nginx, HAProxy, a
# lua_shared_dict, anything), and good enough - the tenants are
# hostnames, not adversarial keys, and the worst a skewed shard costs is
# an uneven pool, not a wrong answer.

my %TIER = (
    anon     => 'free',
    free     => 'free',
    starter  => 'paid',
    team     => 'paid',
    business => 'paid',
);

sub new {
    my ($class, %o) = @_;
    my $pools = $o{pools} || { paid => 1, free => 1 };
    Carp::croak('Maat::Shard: pools must be a hash of tier => count')
        unless ref $pools eq 'HASH';
    for my $tier (sort keys %$pools) {
        Carp::croak("Maat::Shard: pools.$tier must be a positive integer")
            unless defined $pools->{$tier}
                && $pools->{$tier} =~ /\A\d+\z/ && $pools->{$tier} >= 1;
    }
    my $tiers = $o{tiers} || { %TIER };
    return bless { pools => $pools, tiers => $tiers }, $class;
}

sub pools { $_[0]{pools} }

# 32-bit FNV-1a. Stable everywhere; documented so the edge can agree.
sub fnv1a_32 {
    my ($str) = @_;
    my $h = 0x811c9dc5;
    for my $c (unpack 'C*', $str) {
        $h ^= $c;
        $h = ($h * 0x01000193) & 0xffffffff;
    }
    return $h;
}

sub tier_for {
    my ($self, $plan) = @_;
    my $tier = $self->{tiers}{ defined $plan ? $plan : '' };
    # An unknown plan is a control plane newer than this worker. The
    # safe pool for a tenant we cannot classify is the free tier: the
    # mistake then risks our cheapest capacity, not a paying customer's.
    return defined $tier ? $tier : 'free';
}

sub pool_for {
    my ($self, $plan, $host) = @_;
    my $tier = $self->tier_for($plan);
    my $n    = $self->{pools}{$tier} || 1;
    return $tier . '-' . (fnv1a_32(lc(defined $host ? $host : '')) % $n);
}

# Does a tenant belong on this pool? What a worker asks of every bundle
# row; the poller uses it to filter.
sub member {
    my ($self, $pool, $plan, $host) = @_;
    return $self->pool_for($plan, $host) eq $pool ? 1 : 0;
}

1;

__END__

=head1 NAME

Maat::Shard - which worker pool serves a tenant

=head1 SYNOPSIS

    my $shard = Maat::Shard->new(pools => { paid => 4, free => 2 });

    $shard->pool_for('team', 'acme.openapi-proxy.com');   # e.g. "paid-3"
    $shard->pool_for('anon', 'x9k2.openapi-proxy.com');   # e.g. "free-1"

    # a worker in pool paid-3 filters its bundle:
    $shard->member('paid-3', $row->{plan}, $row->{host});

=head1 DESCRIPTION

The blast-radius function for the hosted data plane: every tenant maps
to exactly one worker pool, computed from nothing but the plan and the
hostname, so the edge and the workers agree without talking to each
other.

Two rules:

=over 4

=item * B<Tier first.> C<anon> and C<free> tenants map to C<free-*>
pools; C<starter>, C<team> and C<business> map to C<paid-*> pools. The
free tier is where the abuse arrives, and a pasted spec from a stranger
must never share a process with a paying customer. A plan this worker
does not recognise (a control plane newer than the fleet) lands on the
free tier: the mistake then risks the cheapest capacity.

=item * B<Hash second.> Within a tier the pool is
C<fnv1a_32(lc $host) % N>. FNV-1a is stable across processes, machines
and perl versions and is trivial to reimplement at the edge, which is
the point - the shard function IS the routing table.

=back

=head1 THE TOPOLOGY

What this function implies about deployment, documented here because the
code cannot enforce it:

=over 4

=item * One Hyperman fleet per pool: C<free-0..M-1>, C<paid-0..N-1>.
Every worker in a pool runs the same L<Maat::Registry> and
L<Maat::Poller>, configured with its pool name; the poller keeps only
the bundle rows for which C<member($pool, ...)> is true, so a worker
never compiles - never even holds metadata for - a tenant that is not
its own.

=item * The edge (the L4/L7 balancer in front of the fleets) computes
the same function on the Host header and forwards to the matching pool.
Where the edge cannot run code, the control plane exports the host to
pool map (it is a pure function of the bundle) as balancer
configuration.

=item * A mis-routed request - edge and workers momentarily disagreeing,
say during a pool count change - reaches a worker whose registry has
never heard of the host and is answered 404 by L<Maat::Router> without
touching any tenant's code path. Wrong answer for the client, zero blast
radius; the fix is redeploying the edge map, not the workers.

=item * Changing a tier's pool count remaps C<(count-1)/count> of that
tier's tenants to new pools. That is a deliberate cost: plain modulo is
auditable at the edge in one line, resharding is rare (it means the tier
outgrew its fleet), and a remapped tenant costs one lazy recompile on
its new pool. If resharding ever becomes routine, replace the modulo
with a ring - the function is the only thing that changes.

=back

=head1 METHODS

=head2 new(pools => { paid => N, free => M }, tiers => \%plan_to_tier)

Both optional; one pool per tier by default. C<tiers> overrides the
plan-to-tier map (the default maps C<anon>/C<free> to C<free> and the
paid plans to C<paid>).

=head2 pool_for($plan, $host) / tier_for($plan) / member($pool, $plan, $host)

=head2 fnv1a_32($str)

The hash itself, exposed so an edge implementation can be tested against
this one.

=cut
