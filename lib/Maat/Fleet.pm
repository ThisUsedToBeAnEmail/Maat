package Maat::Fleet;

use 5.010;
use strict;
use warnings;

use Carp ();
use Maat::Config ();
use Maat::Registry ();
use Maat::Poller ();
use Maat::Router ();
use Maat::Log ();
use Time::HiRes ();
use File::Spec ();

our $VERSION = '0.06';

# The hosted data plane, as one deployable.
#
# `apip run` serves ONE tenant from an apip.yml a human wrote. This
# serves every tenant the control plane publishes, routed by hostname,
# and it is what answers <slug>.openapi-proxy.com. The pieces have
# existed since phase 6; this is the file that puts them together and
# hands the result to Hyperman, which is the part that was missing and
# the reason a tenant hostname answered nothing at all.
#
#   Maat::Registry  host -> compiled Open::API, published atomically
#   Maat::Poller    GET /registry/bundle, verify the HMAC, apply
#   Maat::Router    hostname -> that tenant's app, caps, ACME challenges
#   Maat::Shard     which tenants belong to this pool (blast radius)
#
# ---- the order of the two polls, which is the whole design ----
#
# The parent polls ONCE, synchronously, before Hyperman->run. Not for
# warm-up: Hyperman builds every listener's SSL_CTX before it forks,
# from `tls_sni`, and that map is whatever the registry has materialised
# by then. A fleet that polled only in its workers would bring every
# custom domain's certificate up AFTER the context it belonged in was
# built, and every one of them would fail its handshake.
#
# Each worker then arms the poller on its own loop, from its first
# request, and picks up bundles asynchronously from there.
#
# The consequence is worth stating rather than discovering: a tenant
# added, a spec published or a domain routed is live within one poll. A
# custom domain whose CERTIFICATE was issued after this process started
# is served on the next RESTART. SIGHUP is not enough - it re-forks
# workers from a supervisor still holding the context it built at boot,
# which is why examples/apip-fleet.service deliberately does not wire
# `systemctl reload` to it.

# ---- configuration ----------------------------------------------------------
#
# A fleet config is not a gateway config with extra keys: it has no
# upstream, no spec and no mode, because those are per tenant and arrive
# in the bundle. So it gets its own schema, through Maat::Config's
# applier - same unknown-key croak with a did-you-mean, same
# `{ $env: NAME }` and `{ $file: path }` resolution, same "everything
# wrong is a boot failure" promise. See examples/fleet.yml.

# Borrowed from Maat::Config rather than reimplemented - they are this
# distribution's config vocabulary, and a second `_url` that disagreed
# about trailing slashes would be worse than the coupling. \&Foo::bar on
# a sub that no longer exists autovivifies a stub and fails at CALL
# time, which would be a croak in a deployment rather than here, so the
# names are checked at load.
BEGIN {
    for my $v (qw(_apply _resolve _url _string _boolean _bytes
                  _positive_int _positive_number _listeners)) {
        Maat::Config->can($v)
            or die "Maat::Fleet: Maat::Config has no $v - the config "
                 . "validators this borrows have been renamed\n";
    }
}

my %BUDGET_SCHEMA = (
    seconds        => [ 0, \&Maat::Config::_positive_number, 5 ],
    max_spec_bytes => [ 0, \&Maat::Config::_bytes, 5 * 1024 * 1024 ],
);

my %FLEET_SCHEMA = (
    # Where the control plane is. One base URL rather than three: the
    # bundle, the specs and the guides are siblings under /registry, and
    # a deployment that moved one moved all three.
    control_plane  => [ 1, \&Maat::Config::_url ],
    registry_token => [ 1, \&Maat::Config::_string ],
    interval       => [ 0, \&Maat::Config::_positive_number, 15 ],
    timeout        => [ 0, \&Maat::Config::_positive_number, 10 ],

    listen     => [ 0, \&Maat::Config::_listeners, undef ],
    workers    => [ 0, \&Maat::Config::_positive_int, 0 ],   # 0 = per CPU
    access_log => [ 0, \&Maat::Config::_string, undef ],

    # What this worker will hold. A miss recompiles from a digest it
    # already has, so these are memory decisions, not correctness ones.
    # Concrete defaults rather than undef: `apip-fleet check` prints
    # them, and these are Maat::Registry's own.
    max_specs      => [ 0, \&Maat::Config::_positive_int, 1000 ],
    max_bytes      => [ 0, \&Maat::Config::_bytes, 256 * 1024 * 1024 ],
    compile_budget => [ 0, \&_budget, undef ],

    # Blast radius. `pools` is the shape of the fleet, `pool` is which
    # slot this process is - both, or neither. One without the other is
    # a config that reads as sharded and serves everything.
    pools => [ 0, \&_pools, undef ],
    pool  => [ 0, \&Maat::Config::_string, undef ],

    # Real paths: the defaults are temporary directories, so a restart
    # re-materialises certificates it already had and drops every rate
    # limiter counter on the floor.
    tls_dir   => [ 0, \&Maat::Config::_string, undef ],
    rl_dir    => [ 0, \&Maat::Config::_string, undef ],
    spool_dir => [ 0, \&Maat::Config::_string, undef ],

    # Where a tenant's violations ship, under that tenant's own report
    # token from the bundle. Without it nothing leaves the process.
    report_url  => [ 0, \&Maat::Config::_url, undef ],
    environment => [ 0, \&Maat::Config::_string, undef ],

    portal => [ 0, \&Maat::Config::_boolean, 0 ],
    caps   => [ 0, \&_caps, undef ],

    # Rebuild the listener's TLS context in place when the bundle brings
    # a new or renewed custom-domain certificate. On by default: without
    # it a certificate this fleet has already written to tls_dir is not
    # served until the process is restarted, which is the last manual
    # step in an otherwise automatic lifecycle. The switch exists to turn
    # it off if it ever misbehaves in production, not because off is a
    # reasonable steady state.
    tls_reload => [ 0, \&Maat::Config::_boolean, 1 ],

    # Where each worker drops its counters, for `apip-fleet stats`. A
    # file rather than an endpoint on purpose: this fleet serves arbitrary
    # customer hostnames, so any metrics PATH would shadow some tenant's
    # real route - and a file is still readable when a worker is too busy
    # to answer HTTP, which is the state most worth inspecting.
    stats_dir => [ 0, \&Maat::Config::_string, undef ],

    # The structured event log on STDERR, which both supervisors already
    # capture - fleet_server redirects it to /var/log/maat/fleet.log and
    # the systemd unit sends it to journald. On by default; bin/apip-fleet
    # is what acts on this, so a library caller writes nothing uninvited.
    log => [ 0, \&Maat::Config::_boolean, 1 ],
);

sub _budget {
    my ($v, $where, $base) = @_;
    Carp::croak("Maat::Config: '$where' must be a mapping")
        unless ref $v eq 'HASH';
    my %b = Maat::Config::_apply(\%BUDGET_SCHEMA, $v, $where, $base);
    return \%b;
}

sub _pools {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a mapping of tier to count")
        unless ref $v eq 'HASH';
    for my $tier (sort keys %$v) {
        Carp::croak("Maat::Config: '$where.$tier' must be a positive integer")
            unless defined $v->{$tier} && $v->{$tier} =~ /\A\d+\z/
                && $v->{$tier} >= 1;
    }
    return $v;
}

sub _caps {
    my ($v, $where) = @_;
    Carp::croak("Maat::Config: '$where' must be a mapping of plan to caps")
        unless ref $v eq 'HASH';
    for my $plan (sort keys %$v) {
        Carp::croak("Maat::Config: '$where.$plan' must be a mapping")
            unless ref $v->{$plan} eq 'HASH';
    }
    return $v;
}

# ---- the configuration object -----------------------------------------------
#
# from_hash() and load() return the CONFIG, not the fleet: apip-fleet and
# fleet_server both read $config->{control_plane}, $config->{listen} and
# $config->{pool} straight off it before anything is built, and only then
# call new(config => $config). Its own class so those keys can never
# collide with the fleet's own (registry, poller, router, ua).

sub from_hash {
    my ($class, $raw, $base) = @_;
    Carp::croak('Maat::Fleet: from_hash needs a hashref')
        unless ref $raw eq 'HASH';
    my %c = Maat::Config::_apply(\%FLEET_SCHEMA, $raw, '', $base // '.');

    $c{listen} ||= [ { port => 8080, host => '0.0.0.0' } ];

    # The three registry endpoints, from the one base. The bundle, the
    # specs and the guides are siblings under /registry, so a deployment
    # that moved one moved all three.
    $c{bundle_url} = "$c{control_plane}/registry/bundle";
    $c{spec_url}   = "$c{control_plane}/registry/spec";
    $c{guides_url} = "$c{control_plane}/registry/guides";

    return bless \%c, 'Maat::Fleet::Config';
}

sub load {
    my ($class, $file) = @_;
    Carp::croak('Maat::Fleet: no configuration file given')
        unless defined $file;
    -r $file or Carp::croak("Maat::Fleet: cannot read '$file'");

    require YAML::XS;
    my $raw = eval { YAML::XS::LoadFile($file) };
    Carp::croak("Maat::Fleet: '$file' is not valid YAML: $@") if $@;
    Carp::croak("Maat::Fleet: '$file' is empty") unless defined $raw;
    Carp::croak("Maat::Fleet: '$file' must be a mapping, not a "
              . (ref($raw) || 'scalar')) unless ref $raw eq 'HASH';

    require File::Basename;
    my $c = $class->from_hash($raw, File::Basename::dirname($file));
    $c->{file} = $file;
    return $c;
}

# ---- the fleet --------------------------------------------------------------

sub new {
    my ($class, %o) = @_;
    my $c = $o{config}
        or Carp::croak('Maat::Fleet: new needs config => a Maat::Fleet->load');
    # A plain hashref is raw configuration, for a caller building one in
    # memory rather than from a file.
    $c = $class->from_hash($c) unless ref $c eq 'Maat::Fleet::Config';

    my $self = bless { config => $c, started => time }, $class;

    # Blast radius, and the refusals that go with it. A pool nothing
    # hashes to is refused HERE rather than at the first request: a fleet
    # that started, polled, filtered every tenant out and served 404 to
    # all of them would look like a working process with an empty
    # control plane, which is the most expensive way to find a typo.
    my $shard;
    if ($c->{pools} || defined $c->{pool}) {
        Carp::croak("Maat::Fleet: 'pools' needs 'pool' - it says how many "
                  . "slices the fleet has but not which one this process is")
            if $c->{pools} && !defined $c->{pool};
        Carp::croak("Maat::Fleet: 'pool' needs 'pools' - it names a slice "
                  . "of a fleet whose shape is not configured")
            if defined $c->{pool} && !$c->{pools};

        require Maat::Shard;
        $shard = Maat::Shard->new(pools => $c->{pools});
        my @real = map { my $t = $_; map { "$t-$_" } 0 .. $c->{pools}{$t} - 1 }
                   sort keys %{ $c->{pools} };
        Carp::croak("Maat::Fleet: pool '$c->{pool}' is not one of "
                  . join(', ', @real))
            unless grep { $_ eq $c->{pool} } @real;
    }

    # The directory the bundle unseals customers' private keys into.
    # Made here, 0700, and made even when it is two levels of nothing on
    # a fresh box - Maat::Registry would otherwise not notice it was
    # missing until the first custom domain arrived, weeks later.
    if (defined $c->{tls_dir}) {
        _mkpath_private($c->{tls_dir});
    }

    my $rl;
    if (defined $c->{rl_dir}) {
        require Maat::RateLimit;
        # Made here, in the parent, before Hyperman forks: every worker
        # then inherits the same path and so shares the same counters,
        # which is what makes a per-key rate limit true for the box
        # rather than true per worker.
        $rl = Maat::RateLimit->new(dir => $c->{rl_dir});
    }

    $self->{registry} = Maat::Registry->new(
        # `fetch_spec` is overridable so a test can serve specs without a
        # socket; the default is this fleet's own, over the registry token.
        fetch_spec => $o{fetch_spec} || $self->_spec_fetcher,
        report_url => $c->{report_url},
        environment => $c->{environment},
        spool_dir  => $c->{spool_dir},
        tls_dir    => $c->{tls_dir},
        portal     => $c->{portal},
        max_specs  => $c->{max_specs},
        max_bytes  => $c->{max_bytes},
        ($shard ? (shard => $shard, pool => $c->{pool}) : ()),
        ($rl    ? (ratelimit => $rl) : ()),
        ($c->{portal} ? (fetch_guides => $self->_guides_fetcher) : ()),
        ($c->{compile_budget}
            ? (compile_budget => $c->{compile_budget}) : ()),
    );

    $self->{poller} = Maat::Poller->new(
        registry => $self->{registry},
        url      => $c->{bundle_url},
        token    => $c->{registry_token},
        interval => $c->{interval},
        timeout  => $c->{timeout},
        ($o{fetch} ? (fetch => $o{fetch}) : ()),
    );

    $self->{router} = Maat::Router->new(
        registry => $self->{registry},
        ($c->{caps} ? (caps => $c->{caps}) : ()),
    );

    # Serve a certificate that arrives after this process started.
    #
    # The registry writes it to tls_dir within one poll and routes the
    # host immediately, but the listener's SSL context was built before
    # the first fork and knows nothing about it - so without this the
    # customer's domain is verified, issued, routed, and still fails the
    # handshake until somebody restarts the process. That was the last
    # manual step in an otherwise automatic lifecycle.
    #
    # Decided once, here, rather than tested on every poll:
    #
    #   - a fleet with no TLS listener has no context to rebuild. That is
    #     the deployment with a balancer terminating in front, and it is
    #     the common shape, so it must cost nothing;
    #   - an older Hyperman has no tls_reload, and degrades to the
    #     restart-to-pick-up behaviour rather than dying on a missing
    #     method;
    #   - `tls_reload: false` is the operator's switch.
    if ($c->{tls_reload} && grep { $_->{tls_cert} } @{ $c->{listen} }) {
        require Hyperman;
        if (Hyperman->can('tls_reload')) {
            # Called from Maat::Registry::_materialize_tls, which runs on
            # the worker's own loop inside poll_async - so this is inside
            # a worker, which is the only place a reload means anything.
            # Each worker reloads as its own poll comes round, which
            # staggers the pool for free.
            # Unconditional, and nothing is said about the answer.
            #
            # tls_reload returns 0 outside a worker, and that is the
            # ordinary case rather than a fault: the boot poll runs in
            # the parent, before the fork, and its certificates reach the
            # listener through the tls_sni map `run` is given.
            # `apip-fleet check` never forks at all. A warning here would
            # print an alarming line on every check that worked.
            #
            # The case that IS worth reporting - in a worker, rebuild
            # refused because it would have served less than what is
            # running - Hyperman already reports itself, from the C, with
            # the counts. Saying it again in Perl would be a second,
            # vaguer version of a message that already exists.
            $self->{registry}{on_tls_change} = sub {
                Hyperman->tls_reload($_[0]);
                return;
            };
        }
        else {
            warn "Maat::Fleet: this Hyperman has no tls_reload, so a "
               . "certificate issued after start is not served until this "
               . "process restarts. Upgrade Hyperman, or restart after a "
               . "domain is issued.\n";
        }
    }

    return $self;
}

# 0700 the whole way down: everything under here is a customer's private
# key, unsealed.
sub _mkpath_private {
    my ($dir) = @_;
    return if -d $dir;
    my $path = '';
    for my $part (split m{/}, $dir) {
        $path .= "$part/";
        next if -d $path;
        mkdir $path, 0700
            or Carp::croak("Maat::Fleet: cannot make tls_dir '$path': $!");
    }
    chmod 0700, $dir;
    return;
}

sub config   { $_[0]{config} }
sub registry { $_[0]{registry} }
sub poller   { $_[0]{poller} }
sub router   { $_[0]{router} }

# ---- the lazy fetches -------------------------------------------------------
#
# Both are the same shape: a GET carrying the registry token, undef on
# anything that is not a clean 200. Returning undef rather than dying is
# deliberate - Maat::Registry treats a failed fetch as "this tenant is
# not servable yet" and keeps serving everyone else, which is what a
# control plane having a bad minute deserves.

sub _ua {
    my ($self) = @_;
    require Fetch;

    # A fresh agent per process. The fleet object is built in the parent
    # and every worker inherits it, so an agent made before the fork
    # would have its socket shared with every sibling - the same reason
    # Maat::Poller::arm calls forget_agent, and the same fix.
    $self->{ua} = undef
        if defined $self->{ua_pid} && $self->{ua_pid} != $$;
    return $self->{ua} if $self->{ua};

    # THE AGENT MUST SHARE THE WORKER'S LOOP. This is not a preference,
    # and getting it wrong took a production fleet down.
    #
    # A loop-less Fetch puts its socket on a private standalone loop,
    # but Fetch::Future->get pumps the ACTIVE loop - which inside a
    # worker is Hyperman's. So the request's fd sits on a loop nobody
    # pumps while the caller spins on one the request is not registered
    # with: it never completes, and the timeout never fires either,
    # because the timer is on the abandoned loop too. That is a wedge,
    # not a wait, and it is unbounded.
    #
    # It presents as the whole product working and then not: a tenant
    # compiled before it happens keeps serving, a tenant whose FIRST
    # request lands here never answers at all, and the process looks
    # perfectly healthy in ps because the worker is spinning a loop
    # rather than blocked in a syscall.
    #
    # Maat::Poller::_ua carries this same note. It was written after the
    # poller hit it; this file is what hit it next.
    #
    # Outside a worker - the boot poll in the parent, `apip-fleet check`,
    # every test - Hyperman->loop answers undef and a plain standalone
    # agent is right, because there its blocking get pumps its own loop.
    my $loop = eval { Hyperman->loop };
    $self->{ua_pid} = $$;
    return $self->{ua} = Fetch->new(
        timeout => $self->{config}->{timeout},
        agent   => "Maat::Fleet/$VERSION",
        ($loop ? (loop => $loop) : ()),
    );
}

sub _get {
    my ($self, $url) = @_;
    my $t0 = Time::HiRes::time();

    my $res = eval {
        $self->_ua->get($url, headers => {
            Authorization => 'Bearer ' . $self->{config}->{registry_token},
        })->get;
    };
    # Failures only, and every one of them says which URL and how long it
    # took. A spec that will not fetch used to be indistinguishable from
    # a spec that would not compile - both arrived at the same "empty
    # spec body" and the host was poisoned without anyone learning which.
    if (!$res) {
        my $why = $@ || 'no response';
        $why =~ s/\s+at\s+\S+\s+line\s+\d+.*//s;
        $why =~ s/\s+\z//;
        Maat::Log->event(ev => 'fetch', phase => 'fail', url => $url,
                         err => $why, took => Maat::Log->since($t0));
        return undef;
    }

    my $status = eval { $res->status } || 0;
    if ($status != 200) {
        Maat::Log->event(ev => 'fetch', phase => 'fail', url => $url,
                         status => $status, took => Maat::Log->since($t0));
        return undef;
    }
    return $res->content;
}

# digest -> raw spec bytes. Maat::Registry verifies the bytes against the
# digest before it compiles them, so this does not: a fetcher that
# checked would be a second implementation of the thing that makes the
# registry safe against a control plane serving the wrong document.
sub _spec_fetcher {
    my ($self) = @_;
    return sub {
        my ($digest) = @_;
        return undef unless defined $digest && $digest =~ /\A[0-9a-f]{64}\z/;
        return $self->_get("$self->{config}->{spec_url}/$digest");
    };
}

# proxy id -> { rev, guides => [...] }, the portal's prose.
sub _guides_fetcher {
    my ($self) = @_;
    return sub {
        my ($proxy) = @_;
        return undef unless defined $proxy && $proxy =~ /\A[0-9]+\z/;
        my $body = $self->_get("$self->{config}->{guides_url}/$proxy")
            or return undef;
        require File::Raw::JSON;
        my $data = eval { File::Raw::JSON::file_json_decode($body) };
        return ref $data eq 'HASH' ? $data : undef;
    };
}

# ---- serving ----------------------------------------------------------------

# One synchronous poll, in the parent, before anything binds. Returns the
# poller's status word and never dies.
#
# A failure here is NOT fatal, on purpose: a fleet that cannot reach the
# control plane at boot should come up answering 404 and start serving
# the moment a bundle arrives, rather than refuse to start and take a
# working fleet down because the control plane is restarting.
sub boot_poll {
    my ($self) = @_;
    return eval { $self->{poller}->poll_once } // 'error';
}

sub app {
    my ($self) = @_;
    my $inner  = $self->{router}->to_app;
    my $poller = $self->{poller};

    # The poller has to be armed from inside a worker, on that worker's
    # own loop, and to_app runs before the fork - so the first request of
    # each worker process arms it. Hyperman has no post-fork hook to do
    # this more directly.
    #
    # After the first request this is a lexical read and a short-circuit.
    # arm() is itself guarded and returns 0 without a loop, so plackup
    # and the tests simply never poll on a timer.
    my $armed = 0;
    return sub {
        $armed ||= $poller->arm($_[0]);
        # Belt-and-suspenders: if this worker's arm() timer never fires
        # (a loop that did not survive the fork), traffic itself keeps the
        # bundle fresh - at most one poll per interval, so a new tenant is
        # picked up within an interval of the next request instead of
        # waiting for a restart. A no-op when the timer is doing its job.
        $poller->poll_if_stale($_[0]);
        # Same shape, same reasoning: driven by traffic rather than by a
        # timer, so a worker whose loop did not survive the fork still
        # reports. Throttled to one write per interval, and a no-op
        # without stats_dir.
        $self->write_stats;
        return $inner->($_[0]);
    };
}

# This worker's counters, on disk, at most once per interval.
#
# Written to a temp file and renamed, the way Maat::Registry::_write_file
# does it, so `apip-fleet stats` reading concurrently never sees half a
# file rather than occasionally reporting nonsense.
#
# One file per worker and never merged here. Each worker has its own
# registry and polls on its own timer, so they can and do disagree - a
# worker that has never served a request has never polled and is still
# holding the boot-time tenant table. That divergence IS the interesting
# signal; a fleet-wide total would average it away.
sub write_stats {
    my ($self, $force) = @_;
    my $dir = $self->{config}->{stats_dir};
    return 0 unless defined $dir && length $dir;

    my $now = time;
    return 0 unless $force
                 || !$self->{stats_at}
                 || ($now - $self->{stats_at}) >= $self->{config}->{interval};
    $self->{stats_at} = $now;

    # Never let reporting break serving: this is called from the request
    # path, and a full disk must cost a metric, not a request.
    my $ok = eval {
        unless (-d $dir) {
            require File::Path;
            File::Path::make_path($dir);
        }
        require File::Raw::JSON;
        my $snap = $self->{registry}->snapshot(
            router  => $self->{router},
            poller  => $self->{poller},
            started => $self->{started},
        );
        my $file = File::Spec->catfile($dir, "worker-$$.json");
        my $tmp  = "$file.tmp.$$";
        open my $fh, '>', $tmp or die "open $tmp: $!\n";
        print {$fh} File::Raw::JSON::file_json_encode($snap, sort_keys => 1);
        close $fh;
        rename $tmp, $file or die "rename: $!\n";
        1;
    };
    return $ok ? 1 : 0;
}

# The SNI map from what the bootstrap poll materialised, onto the TLS
# listeners only - a plain :80 has no context to add a certificate to.
sub tls_sni { my $s = eval { $_[0]{registry}->tls_sni } || {}; return $s }

sub listeners {
    my ($self) = @_;
    my @listen = map {
        my %l = %$_;
        delete $l{$_} for grep { !defined $l{$_} } keys %l;
        \%l;
    } @{ $self->{config}->{listen} };

    my $sni = $self->tls_sni;
    if (%$sni) {
        for my $l (@listen) {
            next unless $l->{tls_cert} && $l->{tls_key};
            $l->{tls_sni} = $sni;
        }
    }
    return \@listen;
}

sub run {
    my ($self) = @_;
    require Hyperman;
    Hyperman->run(
        app     => $self->app,
        listen  => $self->listeners,
        workers => $self->{config}->{workers},
        ($self->{config}->{access_log}
            ? (access_log => $self->{config}->{access_log}) : ()),
    );
    return 0;
}

1;

__END__

=head1 NAME

Maat::Fleet - the hosted data plane: every tenant, routed by hostname

=head1 SYNOPSIS

    apip-fleet check /etc/maat/fleet.yml     # before you deploy it
    apip-fleet run   /etc/maat/fleet.yml

    # or from Perl
    my $fleet = Maat::Fleet->load('fleet.yml');
    $fleet->boot_poll;    # one synchronous poll, before anything binds
    $fleet->run;          # Hyperman, forever

=head1 DESCRIPTION

C<apip run> serves one tenant from a config a human wrote. This serves
every tenant the control plane publishes, routed by hostname - it is
what answers C<< <slug>.openapi-proxy.com >>.

It assembles pieces that already existed: L<Maat::Registry> (host to
compiled spec, published atomically), L<Maat::Poller> (fetch the signed
bundle, verify, apply), L<Maat::Router> (hostname to that tenant's app,
plan caps, ACME challenges), and optionally L<Maat::Shard> for blast
radius and L<Maat::RateLimit> for counters shared across this box's
workers. What this adds is the wiring and the order.

See F<examples/fleet.yml> for a commented configuration and
F<examples/apip-fleet.service> for a systemd unit.

=head2 Two polls, and why the order matters

The parent polls B<once, synchronously>, before anything binds. Not for
warm-up: L<Hyperman> builds each listener's SSL context before it forks,
from C<tls_sni>, and that map is whatever the registry has materialised
by then. A fleet that polled only in its workers would bring every
custom domain's certificate up B<after> the context it belonged in was
built, and every one would fail its handshake.

Each worker then arms the poller on its own loop, from its first
request, and picks up bundles asynchronously from there.

So a tenant added, a spec published or a domain routed is live within
one poll.

=head2 And so is a certificate, now

A certificate issued after this process started used to need a restart:
the registry wrote it to C<tls_dir> within one poll and routed the host
immediately, but the listener's context was built before the first fork
and knew nothing about it. C<SIGHUP> did not help either, since it
re-forks from that same parent - which is why the shipped systemd unit
still does not wire it to C<systemctl reload>.

C<tls_reload> (default on) closes that. When the materialised
certificate set moves - a domain added, removed, or B<renewed> -
L<Maat::Registry> calls back with the new SNI map and the fleet asks
L<Hyperman/tls_reload> to rebuild that worker's context in place.
Nothing is unbound, no connection is refused, and each worker picks it
up as its own poll comes round.

It is wired only when this fleet has a TLS listener of its own - a
deployment with a balancer terminating in front has no context to
rebuild - and only when the installed Hyperman has the call, so an
older one degrades to needing the restart rather than dying. Set
C<tls_reload: false> to turn it off.

Two limits worth knowing. A worker respawned after a crash, or recycled
by C<SIGHUP>, inherits the parent's boot-time context and serves the old
certificate until its own next poll, at most C<interval> seconds later.
And a rebuild that would serve B<less> than what is running - a PEM that
will not load, whether the wildcard's or one customer's - is refused by
Hyperman, which keeps the running certificates and says so on C<STDERR>;
the next poll tries again.

=head2 A failed boot poll is not fatal here

C<boot_poll> returns the poller's status word and never dies, because
what to do about a failure is not this module's decision. C<apip-fleet>
makes it: C<check> fails on it, and C<run> retries a few times and then
refuses to start, on the grounds that a worker which comes up empty
answers 404 to real traffic on hostnames customers have published while
looking perfectly healthy.

A B<running> fleet survives a failed poll on its last good bundle; a
B<starting> one has nothing to fall back to. Same failure, different
answer, which is why the policy lives in the program that starts it.

=head1 CONFIGURATION

Through L<Maat::Config>'s applier, so an unknown key is a boot croak
with a did-you-mean and any scalar may be written C<< { $env: NAME } >>
or C<< { $file: path } >>.

=over 4

=item * C<control_plane> (required) - the base URL. The bundle, spec and
guides endpoints are its C</registry/*> siblings.

=item * C<registry_token> (required) - authenticates the bundle feed and
is the HMAC key it is verified with. The control plane's
C<MAAT_REGISTRY_TOKEN>.

=item * C<interval> (15), C<timeout> (10).

=item * C<listen>, C<workers>, C<access_log> - as the gateway's.
C<listen> defaults to one plain listener on 8080.

=item * C<max_specs>, C<max_bytes>, C<compile_budget> - what this worker
will hold, and the off-path compile preflight.

=item * C<pools> and C<pool> - blast radius, through L<Maat::Shard>.
Both or neither: C<pools> without C<pool> is a config that reads as
sharded and serves everything.

=item * C<tls_dir>, C<rl_dir>, C<spool_dir> - real paths, because the
defaults are temporary directories.

=item * C<report_url>, C<environment> - where violations ship, and what
they are stamped with. The per-tenant token comes from the bundle.

=item * C<tls_reload> (default on) - rebuild the listener's certificates
in place when the bundle brings a new or renewed one, rather than
needing a restart. See above.

=item * C<portal>, C<caps>.

=back

=head1 METHODS

=head2 load($file) / new(%config)

=head2 boot_poll

One synchronous poll. Returns the status word from
L<Maat::Poller/poll_once>. Never dies.

=head2 app

The PSGI app: L<Maat::Router>'s C dispatcher, wrapped only to arm the
poller on each worker's first request.

=head2 listeners

The C<listen> list with the SNI map attached to the TLS listeners.

=head2 run

L<Hyperman>, with that list. Call C<boot_poll> first, or the first
listener is built without any custom-domain certificates.

=head2 config / registry / poller / router

=head1 SEE ALSO

L<Maat::Registry>, L<Maat::Poller>, L<Maat::Router>, L<Maat::Shard>,
and L<Maat::Gateway> for the single-tenant case.

=head1 AUTHOR

LNATION <email@lnation.org>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by LNATION <email@lnation.org>.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
