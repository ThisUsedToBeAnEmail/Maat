package Maat::Registry;

use 5.010;
use strict;
use warnings;
use Carp ();
use Digest::SHA ();
use File::Spec ();
use File::Temp ();
use POSIX ();
use Time::HiRes ();
use Maat::Config ();
use Maat::Gateway ();
use Maat::RateLimit ();
use Maat::Log ();

our $VERSION = '0.06';

# The per-worker host -> compiled-tenant map: the pivot phase 6 is built
# around. A compiled spec is DATA, not program - Open::API->new is a
# runtime constructor and the freeze lives inside the object - so one
# worker holds every tenant it has been asked for, keyed by host, and a
# publish replaces one entry without recycling anything.
#
# Four properties this file exists to guarantee, each the reason for a
# piece of the machinery below:
#
#   ATOMIC PUBLISH. apply_bundle swaps the whole tenant table in one
#   assignment and drops any compiled entry whose digest moved. An
#   in-flight request already holds a Perl reference to the old compiled
#   object and finishes against it; refcounting frees it when the last
#   one lets go. No recycle, no half-applied window, no neighbour
#   touched.
#
#   LAZY, BOUNDED. An entry is compiled on the FIRST request for its
#   host, not at boot, and the cache is capped on BOTH a compiled-spec
#   count and a total resident-bytes figure. Over either cap the
#   least-recently-used entry is evicted; the next request for it simply
#   recompiles. A worker pays for the tenants it actually serves.
#
#   OFF-PATH COMPILE BUDGET. A spec that is pathological to compile - a
#   deep $ref chain that spins in C, ten megabytes of schemas - is
#   rejected under a time-and-size budget and never allowed to hold the
#   loop. An oversized input is refused before it is ever compiled; a
#   runaway compile is bounded by a wall-clock deadline in a forked
#   child the parent can kill. The blast radius of a bad spec is the one
#   tenant that published it: its host is poisoned and answered 503, and
#   nobody else's latency moves because nobody else's entry is touched.
#
#   METRICS WITHOUT CARDINALITY. Every decision moves an aggregate
#   counter - hits, misses, compiles, evictions, bytes_resident,
#   bad_signature, compile_rejected - and nothing is keyed by anything
#   unbounded.

my $DEFAULT_MAX_SPECS = 1000;
my $DEFAULT_MAX_BYTES = 256 * 1024 * 1024;   # resident spec bytes per worker

sub new {
    my ($class, %o) = @_;

    # How a spec body is obtained from its digest. In production this is
    # a closure over Fetch against GET /registry/spec/<digest> (see
    # Maat::Poller); in a test it is a stub. Either way the body is
    # verified against the digest here before a byte of it is compiled,
    # so a mangled or substituted spec is refused rather than served.
    my $fetch = $o{fetch_spec};
    Carp::croak('Maat::Registry: fetch_spec (a coderef $digest -> $bytes) is required')
        unless ref $fetch eq 'CODE';

    my $self = bless {
        fetch_spec => $fetch,

        # How bytes become a compiled object. Open::API->new by default;
        # overridable so the budget's deadline-and-kill can be proven
        # against a deterministically slow compile rather than a real
        # spec's timing, which this compiler (it memoizes $ref
        # resolution) makes it hard to be pathological about.
        compile => $o{compile} || sub { Open::API->new(spec => $_[0]) },

        max_specs  => $o{max_specs} || $DEFAULT_MAX_SPECS,
        max_bytes  => defined $o{max_bytes} ? $o{max_bytes} : $DEFAULT_MAX_BYTES,

        # The compile budget. Undef turns the forked preflight off (the
        # size cap and a soft deferred alarm still apply); a hashref
        # turns it on. Both named pathologies are covered without it -
        # ten megabytes is refused by max_spec_bytes, a deep $ref is
        # refused by the deadline - but the forked preflight is what
        # makes the time budget HARD against a compile that never returns
        # to Perl for a deferred signal to reach it.
        budget => _budget($o{compile_budget}),

        # Optional blast-radius filter: a worker in pool 'paid-3' keeps
        # only the tenants Maat::Shard maps there. Absent, every tenant
        # in the bundle is this worker's.
        shard => $o{shard},
        pool  => $o{pool},

        # How a compiled api becomes a servable app. The default builds a
        # Maat::Gateway (the whole phase 1-4 request path); a test injects
        # a lighter one. It is handed ($api, \%meta) and returns a PSGI
        # coderef.
        builder => $o{builder} || \&_default_builder,

        # Where domain PEMs are written for Hyperman's tls_sni map, which
        # loads cert and key from FILES, not memory - so the bundle's PEM
        # bytes have to land on disk, the key readable only by us.
        tls_dir => $o{tls_dir} || File::Temp::tempdir('maat-tls-XXXXXX',
                                                      TMPDIR => 1, CLEANUP => 1),

        # If a tenant carries a report token and the worker knows the
        # control plane's violation endpoint, the tenant's own pipeline
        # ships under its token. Off by default; a tenant then aggregates
        # in-process and nothing leaves.
        report_url => $o{report_url},

        # Where each tenant's violation spool goes, one directory per
        # proxy under it. Optional: without it a tenant still meters and
        # still reports coverage, since both are running totals the next
        # drain restates - it is the violation records that need a disk.
        spool_dir  => $o{spool_dir},

        # Which environment this worker is. Taken from report.environment
        # so there is one place a deployment says what it is, rather than
        # a second name that can disagree with the one on its violations.
        environment => $o{environment},

        # The docs portal (phase 10), and the gate for it. Off by default:
        # with `portal` false no tenant gets a /docs route at all, and the
        # compiled app is exactly the phase 1-9 request path (gate 4). On,
        # each tenant's portal is rendered from its OWN compiled spec at
        # compile time - off the request path, here - and wrapped around
        # its gateway app so /docs is a hash lookup into frozen bytes.
        portal => $o{portal} ? 1 : 0,

        # How a proxy's prose guides are fetched from their revision, the
        # exact mirror of fetch_spec: a coderef ($proxy_id) -> { rev,
        # guides => [...] }, called lazily (off the request path) only when
        # a tenant's portal.guides_rev is non-empty and has moved. A proxy
        # with no guides carries an empty guides_rev and is never fetched.
        fetch_guides => $o{fetch_guides},
        guides       => {},   # proxy id -> { rev, guides }

        # The per-(key, operation) rate limiter, shared by every tenant
        # app this worker builds and anchored in a Legba slot so a publish
        # (which rebuilds a tenant's app) does not reset a count. Explicit
        # undef disables it; otherwise the process-wide shared instance is
        # used, its counter files under rl_dir when one is given so the
        # workers of one gateway share them.
        ratelimit => (exists $o{ratelimit} ? $o{ratelimit}
                      : Maat::RateLimit->shared(
                            $o{rl_dir} ? (dir => $o{rl_dir}) : ())),

        # The C tenant table (phase 12b): what the dispatcher reads per
        # request, published from here per compile. An accelerator over
        # this object and never the record - see mt_fleet.h - so it is
        # built when the XS is there and simply absent when it is not,
        # and `caps` (a coderef $meta -> the merged caps, wired by
        # Maat::Fleet from the router's table) is what lets the caps be
        # resolved once here instead of merged on every request.
        table => (exists $o{table} ? $o{table} : _new_table()),
        caps  => $o{caps},

        tenants    => {},   # host -> meta
        by_proxy   => {},   # proxy id -> tenant host
        alias      => {},   # custom-domain host -> tenant host
        domains    => {},   # custom-domain host -> { proxy, tls_crt, tls_key, expires }
        challenges => {},   # acme token -> key authorization
        jwks       => undef,# the authorization server's public keys, or undef
        tls_files  => {},   # host -> { cert => path, key => path, digest }

        # Moves when the materialised certificate set changes - a domain
        # added, removed, or renewed - and not when a bundle carries the
        # same certificates again. `on_tls_change` is called with the new
        # tls_sni map when it moves, which is how Maat::Fleet knows to
        # ask Hyperman to rebuild a listener's SSL context. Same shape as
        # on_challenges and on_aliases below.
        tls_generation => 0,
        on_tls_change  => $o{on_tls_change},

        compiled   => {},   # host -> { api, app, bytes, digest, version, lru }
        poison     => {},   # host -> { digest, reason }
        resident   => 0,
        clock      => 0,

        metrics => {
            hits           => 0,
            misses         => 0,
            compiles       => 0,
            evictions      => 0,
            bytes_resident => 0,
            bad_signature  => 0,
            bad_digest     => 0,
            compile_rejected => 0,
            unknown_host   => 0,
            expired        => 0,
            poll_ok        => 0,
            poll_fail      => 0,
            not_modified   => 0,
            bundles        => 0,
        },
    }, $class;

    return $self;
}

# The table, when this build has one. Maat's XS is a hard prerequisite
# of the gateway, but the table arrived in phase 12 - so a Maat.so from
# before it, or a stripped build, gets undef and every host falls back to
# the Perl dispatch path rather than a boot failure over a cache.
sub _new_table {
    return eval { require Maat; Maat::Fleet::Table->new };
}

sub _budget {
    my ($b) = @_;
    return undef unless defined $b;
    $b = {} unless ref $b eq 'HASH';
    return {
        seconds        => $b->{seconds}        || 5,
        max_spec_bytes => $b->{max_spec_bytes} || 5 * 1024 * 1024,
        rss            => $b->{rss}            || 512 * 1024 * 1024,
        fork           => exists $b->{fork} ? ($b->{fork} ? 1 : 0) : 1,
    };
}

# The size cap is always in force, budget or no budget: it is the cheap
# half of the memory guard, refusing an input too big to compile before
# a byte of it is parsed.
sub _max_spec_bytes {
    my ($self) = @_;
    return $self->{budget} ? $self->{budget}{max_spec_bytes} : 5 * 1024 * 1024;
}

sub metric {
    my ($self, $name, $n) = @_;
    $self->{metrics}{$name} = 0 unless defined $self->{metrics}{$name};
    $self->{metrics}{$name} += defined $n ? $n : 1;
    return;
}

# ---- publish ---------------------------------------------------------------

# Swap in a new bundle. The whole tenant/domain/challenge picture is
# replaced in one shot, then the compiled cache is reconciled against it:
# an entry whose host has left, or whose digest has moved, is dropped so
# the next request recompiles the current version. Everything a request
# already holds survives in that request - it has its own reference.
#
# The bundle is a plain hash already parsed and (in Maat::Poller) already
# signature-verified: { tenants => [...], domains => [...],
# challenges => [...] }. This never fetches or compiles; a publish is
# metadata only, and the compile stays lazy and off this path.
sub apply_bundle {
    my ($self, $bundle) = @_;
    Carp::croak('Maat::Registry: bundle must be a hashref')
        unless ref $bundle eq 'HASH';

    my (%tenants, %by_proxy);
    for my $t (@{ $bundle->{tenants} || [] }) {
        my $host = $t->{host};
        next unless defined $host && length $host;

        # The blast-radius filter: a pooled worker holds only its own
        # tenants, so a bug in this pool cannot reach a tenant that lives
        # in another.
        if ($self->{shard} && defined $self->{pool}) {
            next unless $self->{shard}->member($self->{pool},
                                               $t->{plan}, $host);
        }
        $host = lc $host;
        my %meta = (%$t, host => $host);

        # Environments. A worker that says what it is gets the version
        # that environment points at; one that says nothing gets the
        # published version, which is what every worker got before
        # environments existed.
        #
        # Resolved here, once per publish, so nothing downstream has to
        # know: the compile cache, the poison list and the reconcile all
        # key on the digest, so promoting or rolling back an environment
        # is the same event as a publish and needs no new machinery.
        #
        # An environment nobody has pointed anywhere falls through to
        # the published version rather than serving nothing. Naming an
        # environment must not be able to take a gateway down.
        if (defined $self->{environment}
            && ref $t->{environments} eq 'HASH') {
            my $e = $t->{environments}{ $self->{environment} };
            if (ref $e eq 'HASH' && defined $e->{digest}
                && length $e->{digest}) {
                $meta{version} = $e->{version};
                $meta{digest}  = $e->{digest};
            }
        }

        $tenants{$host} = \%meta;
        $by_proxy{ $t->{proxy} } = $host if defined $t->{proxy};
    }

    # Custom domains alias to their proxy's tenant host. A domain whose
    # proxy is not in this worker's slice (filtered out above, or simply
    # absent) contributes nothing servable - the same 404 an unknown host
    # gets, which is correct: this worker does not serve that proxy.
    my (%alias, %domains);
    for my $d (@{ $bundle->{domains} || [] }) {
        my $host = defined $d->{host} ? lc $d->{host} : undef;
        next unless defined $host && length $host;
        my $thost = $by_proxy{ $d->{proxy} };
        next unless defined $thost;
        $alias{$host}   = $thost;
        $domains{$host} = { %$d, host => $host };
    }

    my %challenges;
    for my $ch (@{ $bundle->{challenges} || [] }) {
        next unless defined $ch->{token} && defined $ch->{auth};
        $challenges{ $ch->{token} } = $ch->{auth};
    }

    # What moved, computed against the table about to be replaced. Only
    # when the log is on: this is a walk of both tenant sets and a fleet
    # holding a thousand of them polls every fifteen seconds.
    my (@added, @gone);
    if (Maat::Log->enabled) {
        my $old = $self->{tenants} || {};
        @added = grep { !exists $old->{$_} } sort keys %tenants;
        @gone  = grep { !exists $tenants{$_} } sort keys %$old;
    }

    # The atomic swap. From the statement after this line a new request
    # sees the new world; a request already in flight kept the compiled
    # object it resolved and is unaffected by any of it.
    $self->{tenants}    = \%tenants;
    $self->{by_proxy}   = \%by_proxy;
    $self->{alias}      = \%alias;
    $self->{domains}    = \%domains;
    $self->{challenges} = \%challenges;

    # The authorization server's public keys, top level because there is one
    # authorization server for the fleet rather than one per tenant. A bundle
    # that carries none leaves this undef and nothing downstream changes.
    $self->{jwks} = (ref $bundle->{jwks} eq 'ARRAY' && @{ $bundle->{jwks} })
        ? $bundle->{jwks}
        : ((ref $bundle->{jwks} eq 'HASH'
            && ref $bundle->{jwks}{keys} eq 'ARRAY'
            && @{ $bundle->{jwks}{keys} })
             ? $bundle->{jwks}{keys} : undef);

    # The diff, not the total. "7 tenants" says nothing about whether
    # the one somebody just published is among them; "added=1" does. The
    # hosts ride along while there are few enough to read - past that it
    # is a bulk change and the counts are the story.
    if (@added || @gone) {
        Maat::Log->event(ev => 'bundle', tenants => scalar keys %tenants,
            added => scalar @added, removed => scalar @gone,
            (@added + @gone <= 8
                ? (added_hosts   => \@added,
                   removed_hosts => \@gone) : ()));
    }

    $self->_reconcile_compiled;
    $self->_table_refresh;
    $self->_table_jwks;
    $self->_table_challenges;
    $self->_table_aliases;
    $self->_materialize_tls;
    $self->metric('bundles');
    return;
}

# Drop a compiled entry whose tenant has left, whose digest has moved, or
# whose build identity (mode/upstream/enforce) has moved. A moved digest is
# a publish, not an eviction, and is not counted as one - eviction is a
# capacity event, a republish is a deploy, and conflating them would make
# the eviction metric lie about memory pressure.
#
# build_rev is here and not only in resolve() because the C table serves a
# portal-off tenant from a DIRECT gateway pointer, skipping resolve
# entirely - so resolve's own build_rev check never runs for it. Clearing a
# tenant's upstream (proxy -> mock) or adding one (mock -> proxy) leaves the
# spec, and so the digest, unchanged; without this the C path would go on
# calling the old responder - forwarding to an upstream the customer just
# removed - until the spec happened to change. Dropping here retires the C
# entry too (_drop), so the next request rebuilds the app against the new
# terms.
sub _reconcile_compiled {
    my ($self) = @_;
    for my $host (keys %{ $self->{compiled} }) {
        my $meta = $self->{tenants}{$host};
        my $e    = $self->{compiled}{$host};
        my $keep = $meta
            && defined $meta->{digest}
            && $meta->{digest} eq $e->{digest}
            && ($e->{build_rev} // '') eq $self->_build_rev($meta);
        $self->_drop($host) unless $keep;
    }
    # A poisoned host whose digest changed gets another chance: the
    # publish may have fixed the spec that breached the budget.
    for my $host (keys %{ $self->{poison} }) {
        my $meta = $self->{tenants}{$host};
        delete $self->{poison}{$host}
            if !$meta || ($meta->{digest} || '') ne $self->{poison}{$host}{digest};
    }
    return;
}

sub _drop {
    my ($self, $host) = @_;
    my $e = delete $self->{compiled}{$host} or return;
    $self->{resident} -= $e->{bytes};
    $self->{metrics}{bytes_resident} = $self->{resident};
    # The C table mirrors this cache, so it loses the host at the same
    # moment. An in-flight request keeps its own entry alive over there
    # by refcount - the same property this Perl side gets from the app
    # closure the request is already inside.
    $self->{table}->retire($host) if $self->{table};
    return;
}

# ---- the C tenant table ------------------------------------------------------

# Publish what the phase-12 dispatcher reads per request: the app, the
# gateway behind it when there is a bare one to call, the caps resolved
# ONCE here rather than merged per request, and the live key table.
#
# Deliberately best-effort. The table is an accelerator over this very
# object (see mt_fleet.h): if the XS is not built, if `caps` was never
# wired, if a publish returns false, resolve() still answers exactly as
# it did before any of this existed and the dispatcher falls back to the
# Perl path for that host. Nothing here may be the only copy of
# anything.
sub _table_publish {
    my ($self, $host, $meta, $e) = @_;
    my $t = $self->{table} or return;

    # With the portal on, this tenant does not get a table entry at all.
    #
    # resolve() rebuilds a host whose portal_rev has moved - a guide
    # edited, a badge toggled - even though the spec digest has not, and
    # that staleness check is resolve's. The C path exists precisely to
    # SKIP resolve, so a portal tenant served from the table would keep
    # serving yesterday's documentation until its spec happened to
    # change. Mirroring portal_rev into C would buy the docs pages a few
    # microseconds they do not need; the portal is off by default and its
    # traffic is people reading, not clients calling.
    return if $self->{portal};

    my $caps = $self->{caps} ? eval { $self->{caps}->($meta) } : undef;
    $caps = {} unless ref $caps eq 'HASH';

    # `gw` is what makes an entry DIRECT - callable at its C entry point
    # with no Perl frame. Only a bare gateway qualifies: a portal wrap or
    # a poison app is a Perl closure and stays one, and mt_fleet_publish
    # clears the flag itself if either is set, so this is belt and
    # braces rather than the only guard.
    my $portal = $self->{portal} ? 1 : 0;
    eval {
        $t->publish($host, {
            app     => $e->{app},
            gw      => (!$portal && $e->{gw}) ? $e->{gw} : undef,
            # The endpoint the dispatcher answers /mcp with, before the
            # tenant app is entered. Unlike the portal it does NOT cost this
            # host its direct C entry point: the branch runs ahead of the
            # call, so the API path is exactly what it was.
            mcp     => $e->{mcp},
            version => $meta->{version},
            keys    => ($meta->{keys} && @{ $meta->{keys} }) ? $meta->{keys} : undef,
            proxy   => ($meta->{proxy} || 0) + 0,
            expires => ($meta->{expires} || 0) + 0,
            portal  => $portal,
            poison  => 0,
            map { $_ => defined $caps->{$_} ? $caps->{$_} + 0 : 0 }
                qw(max_body max_header_bytes concurrency),
        });
        1;
    } or do {
        # A table that will not take a publish is a table that is not
        # accelerating that host, and nothing worse. Say so once rather
        # than per request.
        warn "Maat::Registry: could not publish $host to the C table: $@"
            unless $self->{table_warned}++;
    };
    return;
}

# The terms of every tenant the table is already serving, brought up to
# the bundle just applied.
#
# A tenant's SPEC changing retires its entry (the digest moved, so
# _reconcile_compiled dropped the compiled app and the next request
# rebuilds both). A tenant's TERMS changing does not: a revoked key or a
# plan change moves the bundle without moving the digest, and the
# compiled app is still exactly right. Before this existed the C path
# went on reading keys and caps frozen at compile time - so a revoked key
# kept working, and a downgraded tenant kept the ceilings it had stopped
# paying for. Both are one poll's staleness in Perl and unbounded
# staleness in C, which is the difference that matters.
sub _table_refresh {
    my ($self) = @_;
    my $t = $self->{table} or return;
    for my $host (keys %{ $self->{tenants} }) {
        my $meta = $self->{tenants}{$host} or next;
        my $caps = $self->{caps} ? eval { $self->{caps}->($meta) } : undef;
        $caps = {} unless ref $caps eq 'HASH';
        eval {
            $t->refresh($host, {
                keys    => ($meta->{keys} && @{ $meta->{keys} })
                             ? $meta->{keys} : undef,
                expires => ($meta->{expires} || 0) + 0,
                map { $_ => defined $caps->{$_} ? $caps->{$_} + 0 : 0 }
                    qw(max_body max_header_bytes concurrency),
            });
            1;
        };
    }
    return;
}

# The authorization server's public keys, into the C table.
#
# Straight onto the table rather than through a callback: the challenges and
# aliases below are shared with Maat::Fleet's listener machinery, and this is
# not - the only reader is the MCP endpoint, one branch further on. A table
# that will not take it simply has no OAuth, which is the same fallback every
# other publish here has.
sub _table_jwks {
    my ($self) = @_;
    my $t = $self->{table} or return;
    eval { $t->jwks($self->{jwks}); 1 };
    return;
}

# The pending http-01 challenges, into the C table. The edge answers
# these for ANY host - a domain is validated before it routes anywhere -
# so they cannot live behind a routing decision.
sub _table_challenges {
    my ($self) = @_;
    my $cb = $self->{on_challenges} or return;
    eval { $cb->($self->{challenges} || {}); 1 };
    return;
}

# The custom-domain map, into the C table. Phase 7's aliases are how a
# customer's own hostname reaches their tenant, and the edge has to
# follow them or a domain that resolves perfectly well in Perl is a 404
# in C.
sub _table_aliases {
    my ($self) = @_;
    my $cb = $self->{on_aliases} or return;
    eval { $cb->($self->{alias} || {}); 1 };
    return;
}

sub table { $_[0]{table} }

# ---- resolve ---------------------------------------------------------------

# Host -> ($app, $meta), or the empty list for a host this worker does
# not serve. The one call the edge makes per request; everything lazy and
# bounded hangs off it.
sub resolve {
    my ($self, $host) = @_;
    return () unless defined $host && length $host;
    $host = lc $host;
    $host =~ s/:\d+\z//;                     # a Host header may carry a port

    my $thost = exists $self->{tenants}{$host} ? $host
              : $self->{alias}{$host};
    if (!defined $thost) {
        $self->metric('unknown_host');
        return ();
    }
    my $meta = $self->{tenants}{$thost};

    # Defence in depth against a stale bundle: the control plane already
    # drops an expired tenant, but a worker holding an old bundle must
    # not keep serving one. An expired tenant is an unknown host.
    if ($meta->{expires} && $meta->{expires} > 0 && $meta->{expires} < time) {
        $self->metric('expired');
        return ();
    }

    # A spec that breached the budget under the current digest is served
    # a 503 rather than recompiled on every request - retrying a compile
    # known to be pathological would turn one bad spec into a busy loop.
    # The poison lifts when the digest changes (a new publish).
    if (my $p = $self->{poison}{$thost}) {
        return ($self->_poison_app($p), $meta)
            if ($meta->{digest} || '') eq $p->{digest};
    }

    my $e = $self->{compiled}{$thost};
    if ($e && $e->{digest} eq ($meta->{digest} || '')
        && $e->{portal_rev} eq $self->_portal_rev($meta)
        && $e->{build_rev} eq $self->_build_rev($meta)) {
        $e->{lru} = ++$self->{clock};
        $self->metric('hits');
        return ($e->{app}, $meta);
    }

    # A miss: compile now, once, under the budget, and cache it. A miss can
    # come from a digest change (a publish), from a mode/upstream/enforce
    # change that leaves the spec identical but the compiled app stale (an
    # upstream added to a mock, say - see _build_rev), or, with the portal
    # on, from a guides_rev or badges change - either way the entry is
    # rebuilt off this path. Drop any existing entry first so its resident
    # bytes are not double-counted; normally a digest change already dropped
    # it in _reconcile, but a build_rev- or portal-only change did not.
    $self->_drop($thost) if $self->{compiled}{$thost};
    $self->metric('misses');
    my ($app, $bytes, $api, $gw, $mcp) = $self->_compile_tenant($thost, $meta);
    return ($app, $meta) if !defined $api;   # poisoned; _compile returned a 503 app

    $e = $self->{compiled}{$thost} = {
        api        => $api,
        app        => $app,
        bytes      => $bytes,
        digest     => $meta->{digest},
        version    => $meta->{version},
        portal_rev => $self->_portal_rev($meta),
        build_rev  => $self->_build_rev($meta),
        gw         => $gw,
        mcp        => $mcp,
        lru        => ++$self->{clock},
    };
    $self->_table_publish($thost, $meta, $e);
    $self->{resident} += $bytes;
    $self->{metrics}{bytes_resident} = $self->{resident};
    $self->metric('compiles');
    $self->_evict_to_cap;
    return ($e->{app}, $meta);
}

# Compile one tenant's current spec into a servable app. Returns
# ($app, $bytes, $api) on success, or ($poison_app, 0, undef) when the
# spec cannot be had or breaches the budget - and in that case the host
# is poisoned so the next request is answered without trying again.
sub _compile_tenant {
    my ($self, $host, $meta) = @_;
    my $digest = $meta->{digest};

    # The pair that matters. A `start` with no `ok` and no `fail` beside
    # it is a compile that never came back - which is exactly the shape
    # of a hung spec fetch, and exactly what there was no way to see
    # before this. Everything between them is off the request path in
    # principle and on it in practice, so the duration is worth having.
    my $t0 = Time::HiRes::time();
    Maat::Log->event(ev => 'compile', phase => 'start',
                     host => $host, digest => $digest);

    my $ok = eval {
        my $bytes = $self->{fetch_spec}->($digest);
        die "empty spec body\n" unless defined $bytes && length $bytes;
        die "spec too large (" . length($bytes) . " > "
          . $self->_max_spec_bytes . " bytes)\n"
            if length($bytes) > $self->_max_spec_bytes;

        my $got = Digest::SHA::sha256_hex($bytes);
        if ($got ne $digest) {
            $self->metric('bad_digest');
            die "digest mismatch (asked $digest, got $got)\n";
        }

        $self->_budgeted_compile_ok($bytes)
            or die "compile budget exceeded\n";

        my $api = $self->{compile}->($bytes);
        [ $api, length $bytes ];
    };
    if (!$ok) {
        my $why = $@ || 'unknown compile failure';
        $why =~ s/\s+\z//;
        $self->{poison}{$host} = { digest => $digest, reason => $why };
        $self->metric('compile_rejected');
        Maat::Log->event(ev => 'compile', phase => 'fail', host => $host,
                         digest => $digest, err => $why,
                         took => Maat::Log->since($t0));
        # Poisoned as well as failed, and said separately: the compile is
        # one event, the host being answered 503 until its digest moves
        # is a different and longer-lived fact.
        Maat::Log->event(ev => 'poison', host => $host,
                         digest => $digest, reason => $why);
        return ($self->_poison_app($self->{poison}{$host}), 0, undef);
    }

    my ($api, $bytes) = @$ok;
    Maat::Log->event(ev => 'compile', phase => 'ok', host => $host,
                     digest => $digest, bytes => $bytes,
                     took => Maat::Log->since($t0));

    # The portal's prose, fetched here (off the request path) only when the
    # gateway switch is on and this tenant actually has guides. A failed
    # fetch is not allowed to fail the compile: the reference still renders
    # from the spec, so the portal degrades to no-guides rather than the
    # host being poisoned over a guides endpoint having a bad minute.
    my $guides = $self->{portal} ? $self->_guides_for($meta) : [];

    my $app = $self->{builder}->($api, $meta,
        report_url => $self->{report_url},
        environment => $self->{environment},
        spool_dir  => $self->{spool_dir},
        ratelimit  => $self->{ratelimit},
        portal     => $self->{portal},
        guides     => $guides);

    # A builder may hand back the bare PSGI coderef (every injected one
    # does, and did before phase 12) or { app => ..., gw => ... } - the
    # gateway behind the app, when there is one to call directly. The
    # second form is the only way the C table can learn that a host's app
    # is a Maat::Gateway rather than somebody's closure, and the first
    # form keeps every existing builder working untouched.
    my ($gw, $mcp);
    if (ref $app eq 'HASH') {
        $gw  = $app->{gw};
        $mcp = $app->{mcp};
        $app = $app->{app};
    }
    return ($app, $bytes, $api, $gw, $mcp);
}

# The portal identity of a tenant: what, besides the spec digest, the
# frozen portal depends on. When it moves with the digest unchanged (a
# guides edit, a badge opt-in) resolve rebuilds the portal off the request
# path. Empty when the portal is off, so it never forces a rebuild there.
sub _portal_rev {
    my ($self, $meta) = @_;
    return '' unless $self->{portal};
    my $p = ref $meta->{portal} eq 'HASH' ? $meta->{portal} : {};
    return join "\x1f",
        (defined $p->{badges} ? $p->{badges} : 0),
        (defined $p->{guides_rev} ? $p->{guides_rev} : '');
}

# The build identity of a tenant: what, besides the spec digest, the
# compiled gateway app is baked from. mode and upstream decide mock vs
# proxy (Maat::Gateway picks the responder at compile time), and the
# enforce limit can downgrade enforce to observe (Maat::Config->tenant) -
# none of the three is in the digest. When one moves with the digest
# unchanged, resolve rebuilds the app rather than serving the old one.
# The bug this closes: a mock given an upstream and switched to observe
# keeps answering as a mock, because its spec - and so its digest - never
# changed, and _reconcile keys on the digest alone.
sub _build_rev {
    my ($self, $meta) = @_;
    my $limits = ref $meta->{limits} eq 'HASH' ? $meta->{limits} : {};
    my $mcp = ref $meta->{mcp} eq 'HASH' ? $meta->{mcp} : {};
    return join "\x1f",
        ($meta->{mode}     // 'observe'),
        ($meta->{upstream} // ''),
        ($limits->{enforce} ? 1 : 0),
        # Turning MCP on or changing which operations it offers rebuilds the
        # compiled app without touching the spec, so it belongs here for the
        # same reason mode and upstream do.
        ($mcp->{enabled} ? 1 : 0),
        join(',', sort @{ ref $mcp->{ops} eq 'ARRAY' ? $mcp->{ops} : [] });
}

# A tenant's prose guides, mirroring the spec fetch: fetched lazily from
# their revision, cached per proxy, and never fetched at all when the
# revision is empty (a proxy with no guides). A fetch failure degrades to
# no guides rather than poisoning the host.
sub _guides_for {
    my ($self, $meta) = @_;
    my $p = ref $meta->{portal} eq 'HASH' ? $meta->{portal} : {};
    my $rev = $p->{guides_rev};
    return [] unless defined $rev && length $rev;
    my $proxy = $meta->{proxy};
    return [] unless defined $proxy;

    my $cached = $self->{guides}{$proxy};
    return $cached->{guides} if $cached && ($cached->{rev} || '') eq $rev;

    my $fetch = $self->{fetch_guides};
    return [] unless ref $fetch eq 'CODE';

    my $got = eval { $fetch->($proxy) };
    if (ref $got eq 'HASH' && ref $got->{guides} eq 'ARRAY') {
        $self->{guides}{$proxy} = { rev => ($got->{rev} // $rev),
                                    guides => $got->{guides} };
        $self->metric('guides_fetched');
        return $got->{guides};
    }
    $self->metric('guides_fetch_failed');
    return [];
}

# The hard part of the budget: prove a spec compiles within a wall-clock
# deadline (and, where BSD::Resource is present, an address-space limit)
# WITHOUT letting a runaway compile hold this process. A deferred Perl
# alarm cannot interrupt a compile that never returns to Perl to receive
# it, so the preflight runs in a forked child the parent can SIGKILL. The
# child only compiles and _exits - it never touches the worker's loop, so
# it cannot corrupt a shared epoll on the way out.
#
# Off (budget undef, or fork => 0), the size cap already refused the
# oversized input and a soft deferred alarm is the only time guard; that
# is enough for every spec that yields to Perl between phases, which is
# every well-formed one.
sub _budgeted_compile_ok {
    my ($self, $bytes) = @_;
    my $b = $self->{budget};
    return 1 unless $b;

    return $self->_budgeted_compile_ok_nofork($bytes) unless $b->{fork};

    my $pid = fork;
    if (!defined $pid) {
        # Cannot fork: fall back to the soft in-parent guard rather than
        # refuse a tenant over a transient resource shortage.
        return $self->_budgeted_compile_ok_nofork($bytes);
    }
    if (!$pid) {
        # Child: bound ourselves and compile. _exit, never exit - we must
        # not run this process's destructors or flush its buffers, which
        # on a worker means we never touch its event loop on the way out.
        eval {
            local $SIG{ALRM} = sub { POSIX::_exit(3) };
            if (eval { require BSD::Resource; 1 }) {
                BSD::Resource::setrlimit(
                    BSD::Resource::RLIMIT_AS(), $b->{rss}, $b->{rss});
            }
            Time::HiRes::alarm($b->{seconds} + 1);   # a floor under the parent's kill
            $self->{compile}->($bytes);
        };
        POSIX::_exit($@ ? 1 : 0);
    }

    # Parent: wait up to the deadline, then kill. A compile spinning in C
    # will not reap on its own, so the deadline is enforced by us, with a
    # fractional clock so a tight budget is honoured to the millisecond.
    my $deadline = Time::HiRes::time() + $b->{seconds};
    while (1) {
        my $done = waitpid($pid, POSIX::WNOHANG());
        if ($done == $pid) {
            return ($? == 0) ? 1 : 0;
        }
        if (Time::HiRes::time() >= $deadline) {
            kill 'KILL', $pid;
            waitpid($pid, 0);
            return 0;
        }
        Time::HiRes::sleep(0.005);
    }
}

sub _budgeted_compile_ok_nofork {
    my ($self, $bytes) = @_;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "compile deadline\n" };
        Time::HiRes::alarm($self->{budget}{seconds});
        $self->{compile}->($bytes);
        Time::HiRes::alarm(0);
        1;
    };
    Time::HiRes::alarm(0);
    return $ok ? 1 : 0;
}

# Evict least-recently-used entries until both caps are satisfied. Rare
# (only when a worker is at capacity) so an O(n log n) sort on eviction
# is cheaper than the bookkeeping an ordered structure would cost on the
# hot resolve path, which stays a hash lookup and a counter bump.
sub _evict_to_cap {
    my ($self) = @_;
    return if @{[ keys %{ $self->{compiled} } ]} <= $self->{max_specs}
           && $self->{resident} <= $self->{max_bytes};

    my @by_age = sort { $self->{compiled}{$a}{lru} <=> $self->{compiled}{$b}{lru} }
                 keys %{ $self->{compiled} };
    while (@by_age
        && (keys %{ $self->{compiled} } > $self->{max_specs}
            || $self->{resident} > $self->{max_bytes})) {
        my $victim = shift @by_age;
        $self->_drop($victim);
        $self->metric('evictions');
    }
    return;
}

# ---- the acme edge responder -----------------------------------------------

# The http-01 key authorization for a token, or undef. The control plane
# runs the ACME protocol; the edge only answers the probe Let's Encrypt
# makes at /.well-known/acme-challenge/<token>, which is why this is the
# whole of phase 7 that lives here.
sub challenge {
    my ($self, $token) = @_;
    return undef unless defined $token;
    return $self->{challenges}{$token};
}

# ---- tls ------------------------------------------------------------------

# Materialize the current domains' PEMs to disk and hand back the map
# Hyperman->run wants: { host => { cert => path, key => path } }. Hyperman
# loads a cert and key from FILES, so the bundle's PEM bytes have to be
# written; the key file is created readable only by this user, since the
# bundle unsealed it for a worker trusted to terminate TLS and it must
# not widen from there.
#
# A domain that has left the bundle has its files removed here, so the
# next Hyperman start (or reload) no longer offers its certificate - the
# "dropped within one poll" the plan asks for, at the file layer that
# feeds the SSL contexts.
sub _materialize_tls {
    my ($self) = @_;
    my %want;
    my $moved = 0;
    for my $host (keys %{ $self->{domains} }) {
        my $d = $self->{domains}{$host};
        next unless defined $d->{tls_crt} && length $d->{tls_crt}
                 && defined $d->{tls_key} && length $d->{tls_key};
        my $safe = $host;
        $safe =~ s/[^A-Za-z0-9._-]/_/g;
        my $cert = File::Spec->catfile($self->{tls_dir}, "$safe.crt");
        my $key  = File::Spec->catfile($self->{tls_dir}, "$safe.key");
        _write_file($cert, $d->{tls_crt}, 0644);
        _write_file($key,  $d->{tls_key}, 0600);

        # A digest of the bytes, not of the path. The paths are derived
        # from the hostname and so never move; a RENEWAL is the same host
        # at the same path with different bytes, and it is the case a
        # listener most needs to be told about.
        my $digest = Digest::SHA::sha256_hex($d->{tls_crt} . "\0" . $d->{tls_key});
        $moved++ if !$self->{tls_files}{$host}
                 || ($self->{tls_files}{$host}{digest} // '') ne $digest;
        $want{$host} = { cert => $cert, key => $key, digest => $digest };
    }
    # Drop files for domains that are gone.
    for my $host (keys %{ $self->{tls_files} }) {
        next if $want{$host};
        my $old = $self->{tls_files}{$host};
        unlink $old->{cert} if $old->{cert};
        unlink $old->{key}  if $old->{key};
        $moved++;
    }
    $self->{tls_files} = \%want;

    # Only when it actually moved. This runs on every bundle, and a fleet
    # whose domains have not changed - which is nearly every poll - must
    # not rebuild an SSL context for the sake of it.
    return unless $moved;
    $self->{tls_generation}++;
    Maat::Log->event(ev => 'tls', phase => 'materialised',
                     generation => $self->{tls_generation},
                     hosts => scalar keys %want, changed => $moved);
    $self->{on_tls_change}->($self->tls_sni) if $self->{on_tls_change};
    return;
}

sub _write_file {
    my ($path, $bytes, $mode) = @_;
    my $tmp = "$path.tmp.$$";
    open my $fh, '>', $tmp or return;
    binmode $fh;
    print $fh $bytes;
    close $fh;
    chmod $mode, $tmp;
    rename $tmp, $path;
    return;
}

# The tls_sni hash for Hyperman->run / a listener's tls_sni key, and for
# Hyperman->tls_reload. A pure read of what _materialize_tls last wrote.
#
# cert and key only: tls_files also carries the digest that decides
# whether the map moved, and that is this file's bookkeeping rather than
# anything a listener should be handed.
sub tls_sni {
    my ($self) = @_;
    return { map { $_ => { cert => $self->{tls_files}{$_}{cert},
                           key  => $self->{tls_files}{$_}{key} } }
             keys %{ $self->{tls_files} } };
}

# How many times the materialised certificate set has changed. Moves when
# a domain is added, removed, or renewed; does not move when a bundle
# carries the same certificates again.
sub tls_generation { $_[0]{tls_generation} }

# ---- introspection ---------------------------------------------------------

sub metrics {
    my ($self) = @_;
    return {
        %{ $self->{metrics} },
        bytes_resident => $self->{resident},
        specs_resident => scalar keys %{ $self->{compiled} },
        tenants        => scalar keys %{ $self->{tenants} },
        domains        => scalar keys %{ $self->{domains} },
        challenges     => scalar keys %{ $self->{challenges} },
        poisoned       => scalar keys %{ $self->{poison} },
    };
}

# Everything one worker knows about itself, in one hashref, for the stats
# file `apip-fleet stats` reads.
#
# Per worker and never aggregated here, deliberately. Each worker has its
# own registry and polls on its own timer, so they can and do disagree -
# a worker that has never served a request has never polled and is still
# holding the boot-time tenant table. A fleet-wide total would average
# that away and hide the very thing worth seeing.
#
# `router` and `poller` are passed in rather than reached for: this
# object does not own either, and a registry that went looking for its
# router would be a cycle for the sake of a number.
sub snapshot {
    my ($self, %o) = @_;
    my $r = $o{router};
    my $p = $o{poller};
    return {
        worker  => $$,
        t       => time,
        started => $o{started},
        pool    => $self->{pool},
        registry => $self->metrics,
        # The poisoned hosts by name, not just a count: "poisoned=3" is a
        # number to worry about, and the three hostnames are the thing to
        # act on.
        poisoned_hosts => [ sort keys %{ $self->{poison} } ],
        ($r ? (router => { %{ $r->{metrics} || {} } }) : ()),
        ($p ? (poller => { last_ok => $p->last_ok,
                           etag    => $p->etag,
                           armed   => $p->{armed} ? 1 : 0 }) : ()),
    };
}

# Drop a key from every tenant's live table right now, without waiting
# for a poll. `apip revoke` uses this when it runs in the gateway's own
# process; out of process it signals a re-poll instead (see Maat::Poller).
# It is belt-and-braces with the bundle: the control plane has already
# dropped the key, and the next poll would remove it anyway, but this
# makes it gone this instant. Returns how many key entries were removed.
sub revoke_key {
    my ($self, $key_id) = @_;
    return 0 unless defined $key_id;
    my $removed = 0;
    for my $host (keys %{ $self->{tenants} }) {
        my $keys = $self->{tenants}{$host}{keys};
        next unless $keys && ref $keys eq 'ARRAY';
        my @kept = grep { !(defined $_->{id} && $_->{id} eq $key_id) } @$keys;
        $removed += @$keys - @kept;
        $self->{tenants}{$host}{keys} = \@kept;
    }
    # The C table holds its own reference to each tenant's key list, and
    # what happened above was a REPLACEMENT of the arrayref, not an edit
    # of it - so the table would go on pointing at the list that still
    # contains the revoked key. `apip revoke` promises the key stops
    # working at once, in process, with no poll; that promise is this
    # line.
    $self->_table_refresh if $removed;
    $self->metric('keys_revoked', $removed) if $removed;
    return $removed;
}

sub tenant   { $_[0]{tenants}{ lc $_[1] } }
sub hosts    { [ sort keys %{ $_[0]{tenants} } ] }
sub domains  { [ sort keys %{ $_[0]{domains} } ] }
sub resident_bytes { $_[0]{resident} }
sub is_poisoned    { exists $_[0]{poison}{ lc $_[1] } ? 1 : 0 }

# ---- the poison app --------------------------------------------------------

# What a host whose spec would not compile within budget serves: an
# honest 503, never a hang and never a wrong answer, so the one tenant
# that published a bad spec is the only one that feels it.
sub _poison_app {
    my ($self, $p) = @_;
    my $body = File::Raw::JSON::file_json_encode({
        type   => 'https://openapi-proxy.com/problem/spec-rejected',
        title  => 'Service Unavailable',
        status => 503,
        detail => 'the API description for this host could not be compiled '
                . 'within its budget and is not being served',
    });
    return sub {
        return [ 503,
                 [ 'Content-Type'   => 'application/problem+json',
                   'Content-Length' => length $body,
                   'Retry-After'    => '30' ],
                 [ $body ] ];
    };
}

# ---- the default builder ---------------------------------------------------

# A compiled api plus its tenant metadata becomes the phase 1-4 request
# path: a Maat::Gateway, in mock mode when the tenant has no upstream and
# proxying otherwise. The tenant's plan limits ride in through
# Maat::Config->tenant, which builds an in-memory config around the
# already-compiled api.
sub _default_builder {
    my ($api, $meta, %o) = @_;
    my $limits = $meta->{limits} || {};

    my %report;
    if ($o{report_url} && defined $meta->{report_token}) {
        %report = (url => $o{report_url}, token => $meta->{report_token});

        # Stamped on every violation record this worker ships. A fleet
        # is deployed per environment - staging polls the same control
        # plane as production - so without it a drift report cannot say
        # which of them a violation came from. The SAME name that selects
        # a tenant's pinned spec version above, deliberately: two names
        # for one deployment's identity is two names that can disagree.
        $report{environment} = $o{environment}
            if defined $o{environment} && length $o{environment};

        # A spool of this tenant's own, when the deployment has somewhere
        # to put one. Violations are accumulated detail - a batch lost is
        # lost - so they land on disk before they are shipped, and each
        # tenant gets its own directory so one noisy proxy filling its
        # cap cannot crowd out a quiet neighbour's records. Without a
        # spool_dir the tenant still meters and still reports coverage;
        # only the violation records need the disk.
        if (defined $o{spool_dir} && length $o{spool_dir}
            && defined $meta->{proxy}) {
            $report{spool} = File::Spec->catdir($o{spool_dir},
                                                'p' . $meta->{proxy});
        }
    }

    my $config = Maat::Config->tenant(
        mode     => $meta->{mode} || 'observe',
        upstream => $meta->{upstream},
        limits   => $limits,
        # The plan's sampling allowance, already resolved into the
        # gateway's vocabulary by the control plane. Config->tenant
        # clamps it against limits.sampling regardless.
        sampling => $meta->{sampling},
        version  => $meta->{version},
        plan     => $meta->{plan},
        (%report ? (report => { %{ Maat::Config->tenant->{report} }, %report }) : ()),
    );

    my $gw = Maat::Gateway->new(
        config    => $config,
        api       => $api,
        keys      => $meta->{keys},      # spec-driven auth arms only if present
        ratelimit => $o{ratelimit},
    );
    my $app = $gw->to_app;

    # The docs portal wraps the gateway app when the gateway switch is on:
    # a /docs request is served from frozen bytes rendered here, off the
    # request path, from this same compiled spec; everything else falls
    # straight through to the C request path. Off, the app is returned bare
    # - no wrapper, no /docs route, not a single added op on the API path
    # (gate 4). The per-tenant `portal.badges` opt-in gates the reality
    # badge only; the reference and guides are served whenever the switch
    # is on.
    if ($o{portal}) {
        require Maat::Portal;
        my $p = ref $meta->{portal} eq 'HASH' ? $meta->{portal} : {};
        my $portal = eval {
            Maat::Portal->new(
                api       => $api,
                host      => $meta->{host},
                version   => $meta->{version},
                digest    => $meta->{digest},
                guides    => ($o{guides} || []),
                badges    => $p->{badges} ? 1 : 0,
                violation => $gw->violation,
            );
        };
        # A portal that would not build is not worth refusing traffic over:
        # the gateway still enforces, it just has no /docs. The failure is
        # visible in the log, not in the customer's request path.
        if ($portal) { $app = $portal->wrap($app); }
        else         { warn "Maat: could not build the docs portal for "
                          . ($meta->{host} // '?') . ": $@"; }
    }

    # The MCP endpoint, when this tenant carries one. Built from the SAME
    # compiled spec the gateway enforces, so the tools an agent is offered and
    # the contract its calls are held to cannot drift apart - which is the
    # whole argument for serving agents from here rather than from a
    # generator somewhere else.
    my $mcp;
    my $mcfg = ref $meta->{mcp} eq 'HASH' ? $meta->{mcp} : undef;
    if ($mcfg && $mcfg->{enabled}) {
        require Maat;                      # Maat::MCP is XS, in the bundle
        my $endpoint = eval {
            Maat::MCP->new(
                api     => $api,
                gw      => $gw,
                host    => $meta->{host},
                version => $meta->{version},
                proxy   => $meta->{proxy},
                mcp     => $mcfg,
            );
        };
        if ($endpoint) {
            # The one line that makes it a PSGI app lives here, beside the
            # gateway's own app and the portal's wrap, rather than as a
            # closure factory in XS that this distribution has no other use
            # for. Everything the closure calls is C.
            $mcp = sub { Maat::MCP::_serve($endpoint, $_[0]) };

            # With the portal on, _table_publish gives this tenant no C table
            # entry at all, so the dispatcher's /mcp branch never runs. The
            # wrap is what keeps the endpoint reachable in that one shape.
            if ($o{portal}) {
                my $inner = $app;
                $app = sub {
                    my ($env) = @_;
                    my $p = defined $env->{PATH_INFO} ? $env->{PATH_INFO} : '';
                    return $mcp->($env)
                        if $p eq '/mcp'
                        || $p eq '/.well-known/oauth-protected-resource';
                    return $inner->($env);
                };
            }
        }
        else {
            # An endpoint that would not build is not worth refusing traffic
            # over: the API path is untouched, there is simply no /mcp.
            warn "Maat: could not build the MCP endpoint for "
               . ($meta->{host} // '?') . ": $@";
        }
    }

    # The gateway rides along so Maat::Registry can tell the C table this
    # host has a bare C entry point to call. It is NOT a licence to skip
    # the app: a portal-wrapped host must go through the wrapper, and
    # both _table_publish and mt_fleet_publish refuse DIRECT when the
    # portal is on.
    return { app => $app, gw => $gw, mcp => $mcp };
}

require File::Raw::JSON;

1;

__END__

=head1 NAME

Maat::Registry - the per-worker host to compiled-tenant map

=head1 SYNOPSIS

    my $reg = Maat::Registry->new(
        fetch_spec => sub {
            my ($digest) = @_;
            # GET /registry/spec/<digest>, verified against $digest here
            return $spec_bytes;
        },
        max_specs => 1000,
        max_bytes => 256 * 1024 * 1024,
        compile_budget => { seconds => 5, max_spec_bytes => '5M' },
        shard => $shard, pool => 'paid-3',   # optional blast-radius filter
    );

    $reg->apply_bundle($bundle);             # atomic publish (Maat::Poller drives it)

    my ($app, $meta) = $reg->resolve($host); # lazy compile on first request
    my $auth = $reg->challenge($token);      # phase-7 http-01 responder
    my $sni  = $reg->tls_sni;                # { host => { cert, key } } for Hyperman

=head1 DESCRIPTION

One fleet of workers serves every customer's proxy, routed by hostname.
This is the per-worker table that makes it possible: host to compiled
L<Open::API> object, published atomically, compiled lazily, bounded by an
LRU with two caps, and guarded by an off-path compile budget.

=head2 Atomic publish

C<apply_bundle> replaces the whole tenant/domain/challenge picture in one
assignment and drops any compiled entry whose spec digest has moved. A
request already in flight holds its own reference to the compiled object
and finishes against it; Perl's refcounting frees the old object when the
last such request lets go. No worker recycle, no window in which half a
request sees a new contract, no neighbour disturbed by another tenant's
deploy.

=head2 Lazy and bounded

A host is compiled on its first request, not at boot, so a worker pays
nothing for a tenant it never serves. The compiled cache is capped on
B<both> a count of specs and a total of resident spec bytes; over either
cap the least-recently-used entry is evicted and its next request simply
recompiles. C<resolve> on a resident host is a hash lookup and a counter
bump - the sort that finds an eviction victim runs only when a cap is
actually breached.

=head2 The compile budget

A spec that is pathological to compile is rejected without holding the
loop. An input over C<max_spec_bytes> is refused before it is parsed -
the "ten megabytes of schemas" case. A compile that runs away - a deep
C<$ref> chain spinning in C, where a deferred Perl alarm can never reach
it - is bounded by a wall-clock deadline in a forked child the parent can
kill; the child limits its own address space (via L<BSD::Resource> when
present) and only ever compiles and C<_exit>s, so it cannot corrupt the
worker's event loop on the way out. On breach the host is B<poisoned>:
answered C<503> until its digest changes, so a bad spec is never
recompiled in a busy loop, and B<only that tenant> is affected - no other
host's compiled entry is touched, so no other tenant's latency moves.

Set C<compile_budget> to a hashref to arm the forked preflight, or leave
it undef for the size cap and a soft deferred alarm alone.

=head2 Metrics

C<metrics> returns aggregate counters only, nothing keyed by anything
unbounded: C<hits>, C<misses>, C<compiles>, C<evictions>,
C<bytes_resident>, C<bad_signature>, C<bad_digest>, C<compile_rejected>,
C<unknown_host>, C<expired>, and the poll counters
C<poll_ok>/C<poll_fail>/C<not_modified> that L<Maat::Poller> moves.

=head2 Custom domains and TLS

A domain in the bundle aliases a hostname to its proxy's tenant, so
C<resolve('api.customer.com')> returns that tenant's app. Its PEM cert
and key are written to C<tls_dir> - the key readable only by this user -
and C<tls_sni> returns the C<< { host => { cert => path, key => path } } >>
map L<Hyperman> loads certificates from. A domain that leaves the bundle
has its files removed within the poll that dropped it; the running SSL
contexts follow on the next Hyperman start or zero-downtime reload, which
0.15 builds once before forking.

=head1 METHODS

=head2 new(fetch_spec => \&code, max_specs => N, max_bytes => B, compile_budget => \%b, shard => $s, pool => $name, builder => \&code, tls_dir => $dir, report_url => $url, environment => $name, portal => 0, fetch_guides => \&code)

C<fetch_spec> is required: a coderef mapping a digest to raw spec bytes,
verified against the digest before compilation.

C<portal> (default off) turns on the phase-10 docs portal for every
tenant this worker serves. C<fetch_guides> is its guides fetcher: a
coderef C<< ($proxy_id) -> { rev, guides => [ { slug, title, body, order
} ] } >>, the exact mirror of C<fetch_spec>, called only when a tenant has
guides.

=head2 apply_bundle(\%bundle)

Atomically publish C<{ tenants => [...], domains => [...], challenges => [...] }>.
Metadata only - never fetches or compiles.

=head2 Environments

A tenant may carry C<< environments => { staging => { version, digest },
... } >>. A registry built with an C<environment> resolves each tenant's
version and digest from that map when the environment is named there,
and falls back to the tenant's published C<version>/C<digest> when it is
not - so a worker that names an environment nobody has pointed anywhere
still serves, and a worker that names none behaves exactly as it did
before environments existed.

Resolution happens here, once per publish. Everything downstream - the
compile cache, the poison list, the reconcile - keys on the digest, so
promoting an environment or rolling it back is the same event as a
publish and needed no new machinery.

=head2 The docs portal

With C<portal> true, each tenant's compiled app is wrapped in a
L<Maat::Portal> rendered from that tenant's B<own> compiled spec at
compile time - here, off the request path, under the same budget as the
spec. A C</docs> request is then a hash lookup into frozen bytes; every
other request falls straight through to the C request path, so an API
request pays nothing for the portal existing. With C<portal> false
(the default) the app is returned bare and there is no C</docs> route at
all (gate 4).

The prose guides are fetched exactly as specs are: lazily, from their
revision, through the C<fetch_guides> coderef, cached per proxy, and never
fetched when a tenant's C<portal.guides_rev> is empty. A guides_rev or
C<portal.badges> change with the spec digest unchanged rebuilds only that
tenant's frozen portal, off the request path, on its next request.

=head2 resolve($host)

C<($app, $meta)> for a host this worker serves (compiling lazily on the
first request), or the empty list for one it does not - which the edge
answers C<404> without touching any tenant's code path.

=head2 revoke_key($key_id)

Drop a key from every tenant's live in-memory table right now, without
waiting for a poll, and return how many entries were removed. Used by
C<apip revoke> when it runs in the gateway's own process; out of process
the CLI signals a re-poll instead (see L<Maat::Poller>). Belt and braces
with the bundle: the control plane has already dropped the key and the
next poll would remove it anyway, but this makes it gone this instant.

=head2 challenge($token) / tls_sni / metrics / tenant($host) / hosts / domains / resident_bytes / metric($name, $n)

=cut
