package Maat::Gateway;

use 5.010;
use strict;
use warnings;
use Carp ();
use Scalar::Util ();
use Time::HiRes ();
use Digest::SHA ();
use Open::API ();
use Reverse::Proxy ();
use File::Raw::JSON ();
use Horus qw(uuid_v7);
use Maat::Violation ();
use Maat ();          # the XS request path (Maat.xs)
use Maat::Sampler ();

our $VERSION = '0.05';

# The policy between Open::API and Reverse::Proxy.
#
# Everything expensive is already C: the spec compiles once in
# Open::API, matching and validation are C, and the forward is C through
# Fetch's ABI. What is here is the decisions - what to do with a request
# the document does not describe, what to answer when it does not
# conform, and what to do when our own machinery breaks.
#
# The last one is the important one. See CHAOS below: a failure inside
# Maat loses the check, never the request.

sub new {
    my ($class, %o) = @_;
    my $config = $o{config} or Carp::croak('Maat::Gateway: config is required');

    my $self = bless {
        config         => $config,
        chaos          => _chaos($o{chaos}),
        record_timeout => defined $o{record_timeout} ? $o{record_timeout} : 1,
    }, $class;

    # The spec compiles here or the process does not start. `apip check`
    # is this same call, which is what makes it a pre-deploy gate.
    #
    # In the hosted data plane the compile has already happened, off the
    # request path and under a budget (see Maat::Registry): a compiled
    # spec is data, and the same object serves every worker that asks for
    # that host. So an `api` may be handed in already built, and then the
    # single-tenant `config->spec` path is not taken at all.
    $self->{api} = $o{api} || eval { Open::API->new(spec => $config->spec) }
        or Carp::croak("Maat::Gateway: the spec at "
                     . (eval { $config->spec } // '(in memory)')
                     . " did not compile: $@");

    # The reporting pipeline: aggregate in the process, spool to disk,
    # ship when the control plane will have it. Each stage is bounded and
    # none of them can make a request wait - see Maat::Violation,
    # Maat::Spool and Maat::Shipper.
    $self->{violation} = $o{violation} || $self->_build_pipeline($o{sink});

    # In mock mode there is no upstream: the "proxy" is the document
    # itself, synthesized in C by Open::API. Everything upstream of it -
    # the id, the counters, request validation, the problem+json answers -
    # is the same request path either way, which is what makes the mock a
    # client-side conformance check and not a toy.
    $self->{proxy} = $config->mode eq 'mock'
        ? $self->_mock_app
        : Reverse::Proxy->new(
              upstream      => $config->upstream,
              timeout       => $config->{timeout},
              preserve_host => $config->{preserve_host},
              tls_verify    => $config->{tls_verify},
              stream        => $config->{stream},
              pool_size     => $config->{pool_size},
          )->to_app;

    # How much of the response traffic to weigh. `sample: all` is the
    # honest ceiling and what a test environment wants; `adaptive` is the
    # default and keeps the cost per operation bounded whatever the
    # traffic does. See Maat::Sampler.
    my $r = $config->responses;
    $self->{sampler} = $o{sampler} || Maat::Sampler->new(
        mode     => !$r->{validate}          ? 'off'
                  : $r->{sample} eq 'adaptive' ? 'adaptive'
                  : 'fixed',
        fixed    => $r->{sample} eq 'all' ? 1
                  : $r->{sample} eq 'adaptive' ? 1 : $r->{sample},
        budget   => $r->{budget},
        floor    => $r->{floor},
        interval => $r->{interval},
        max_body => $r->{max_body},
    );

    # Spec-driven API keys and per-key rate limits. Off unless the tenant
    # was issued keys AND the document declares security schemes to carry
    # them - and even then the C request path only enters the auth step
    # when $self->{auth} is set, so a gateway without keys is the phase-1
    # path byte for byte (gate 4).
    $self->{ratelimit} = $o{ratelimit};
    $self->_build_auth($o{keys});

    # Observe-only drift the contract permits (Maat::Observe): undeclared
    # params/endpoints, deprecated fields, response fields not in the
    # schema. On unless the tenant turned it off, and never in mock mode -
    # there is no upstream to drift against, and an undeclared path is a
    # 404 the mock already answers, not surface it forwarded somewhere.
    # `observe_count` is the per-operation request tally the request-side
    # sampler gates on; bounded by the operation count.
    $self->{observe} = ($config->mode ne 'mock'
                        && $config->report->{undeclared}) ? 1 : 0;
    $self->{observe_count} = {};

    return $self;
}

# ---- spec-driven API keys ---------------------------------------------------

# Turn on key verification for this gateway, but only when the compiled
# document actually declares a way to carry a key. The spec is the
# authority on what is guarded: with no securitySchemes there is nothing
# to extract a credential from, so auth stays fully off whatever keys were
# issued, and the request path is unchanged.
#
# The tenant's key table is deliberately NOT captured here. A key is
# revoked by the control plane dropping it from the bundle, which moves
# the ETag but not the spec digest - so this compiled app (and this
# object) can outlive the revocation. The live keys ride in on
# $env->{'maat.keys'}, set by Maat::Router from the current tenant meta on
# every request, so a revoked key stops working on the next poll without
# this object being rebuilt. This holds only the machinery, never a
# secret.
sub _build_auth {
    my ($self, $keys) = @_;
    my $spec    = eval { $self->{api}->spec } || {};
    my $schemes = ref $spec eq 'HASH'
        ? (($spec->{components} || {})->{securitySchemes} || {}) : {};
    return unless ref $schemes eq 'HASH' && %$schemes;

    # One checker, registered under every declared scheme name. Open::API
    # extracts the credential per the scheme's type and location (an
    # apiKey header or query value, a bearer token) and hands it here, so
    # every scheme reaches the same hash-and-compare.
    my $check = $self->_key_checker;
    $self->{checkers} = { map { $_ => $check } keys %$schemes };
    $self->{auth}     = 1;
    return;
}

# The scheme checker Open::API calls. It receives the already-extracted
# credential, hashes it, and constant-time compares against the tenant's
# key hashes - hashed, never stored plain; no early return, so which key
# matched is not a timing signal. On a match it hands the key to the rate
# limiter through $env and authorizes; otherwise it rejects and Open::API
# turns that into the spec's 401.
sub _key_checker {
    my ($self) = @_;
    return sub {
        my ($cred, $env, $op_id, $scopes) = @_;
        my $keys = $env->{'maat.keys'};
        return 0 unless $keys && ref $keys eq 'ARRAY' && @$keys;
        return 0 unless defined $cred && length $cred;

        my $hash = Digest::SHA::sha256_hex($cred);
        my $matched;
        for my $k (@$keys) {
            my $h = $k->{hash};
            next unless defined $h;
            $matched = $k if _ct_eq($hash, $h);   # no early break
        }
        return 0 unless $matched;

        # The alternative's required scopes must all be granted to the
        # key. An apiKey scheme usually declares none (a no-op); this is
        # real for a bearer/oauth2 requirement.
        if ($scopes && ref $scopes eq 'ARRAY' && @$scopes) {
            my %have = map { $_ => 1 } @{ $matched->{scopes} || [] };
            for my $need (@$scopes) { return 0 unless $have{$need} }
        }

        $env->{'maat.key'} = $matched;
        return 1;
    };
}

# Constant-time equality for two equal-length strings (the sha256 hex
# digests). No early return on a mismatch.
sub _ct_eq {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b;
    return 0 unless length $a == length $b;
    my $diff = 0;
    $diff |= ord(substr $a, $_, 1) ^ ord(substr $b, $_, 1)
        for 0 .. length($a) - 1;
    return $diff == 0 ? 1 : 0;
}

# Called from the C request path once an operation is matched, before the
# body is read or the request validated - the same order the Plack
# dispatch runs security in. Returns undef to proceed (an unsecured
# operation, or an authorized-and-within-limit one), or a PSGI response
# (401 unauthorized, or 429 rate limited) to answer here. Never dies: a
# failure of our own auth machinery falls through to proceed, because a
# bug in the gateway must not become the customer's outage.
sub _authorize {
    my ($self, $op, $env, $rid) = @_;
    my $checkers = $self->{checkers} or return undef;

    # A tool call arrives already authorised, and must not be re-checked.
    #
    # The MCP endpoint authenticated the agent at /mcp and put the key it
    # matched on the environment it built. That key cannot be re-presented as
    # a credential here: the gateway stores key HASHES and never the secret,
    # so there is nothing to hand check_op_security a second time. Under
    # OAuth the credential is not even a key - it is a token naming one.
    #
    # So a synthetic request carries `maat.mcp` beside the resolved
    # `maat.key`, and both are set only by C we own, never from a header. A
    # request off the wire cannot forge either: mt_serve builds the env for
    # real requests and sets neither.
    my $preauthorised = $env->{'maat.mcp'} && $env->{'maat.key'};

    if (!$preauthorised) {
        my $denied = eval { $self->{api}->check_op_security($op, $env, $checkers) };
        if ($denied && ref $denied eq 'ARRAY') {
            $self->{violation}->count('unauthorized');
            _add_request_id($denied, $rid);
            return $denied;
        }
    }

    # Rate limit per (key, operation), after the key is known. An
    # unsecured operation set no key; a key with rate_per_min 0 is
    # unlimited; and a gateway with no limiter simply does not rate-limit.
    return undef unless $self->{ratelimit};
    my $key = $env->{'maat.key'} or return undef;
    my $rpm = $key->{rate_per_min} || 0;
    return undef if $rpm <= 0;

    my ($ok, $limit, $remaining, $reset) =
        $self->{ratelimit}->allow($key->{id}, "$op", $rpm);
    return undef if $ok;

    $self->{violation}->count('rate_limited');
    return _problem_429($rid, $limit, $remaining, $reset);
}

sub _add_request_id {
    my ($res, $rid) = @_;
    return unless ref $res eq 'ARRAY' && ref $res->[1] eq 'ARRAY';
    my $h = $res->[1];
    for (my $i = 0; $i < @$h; $i += 2) {
        return if lc $h->[$i] eq 'x-request-id';
    }
    push @$h, 'X-Request-Id', $rid;
    return;
}

# 429, in the same application/problem+json shape the gateway uses for a
# validation failure, with Retry-After and the X-RateLimit-* headers.
sub _problem_429 {
    my ($rid, $limit, $remaining, $reset) = @_;
    my $retry = $reset - time;
    $retry = 0 if $retry < 0;
    my $body = File::Raw::JSON::file_json_encode({
        type   => 'https://openapi-proxy.com/problem/rate-limit',
        title  => 'Too Many Requests',
        status => 429,
        detail => "the rate limit of $limit requests per minute for this key "
                . "and operation has been exceeded",
        request_id => $rid,
    }, sort_keys => 1);   # same bytes for the same violation - see Maat::Router::_problem
    return [ 429,
             [ 'Content-Type'          => 'application/problem+json',
               'Content-Length'        => length $body,
               'X-Request-Id'          => $rid,
               'Retry-After'           => $retry,
               'X-RateLimit-Limit'     => $limit,
               'X-RateLimit-Remaining' => $remaining,
               'X-RateLimit-Reset'     => $reset ],
             [ $body ] ];
}

sub api       { $_[0]{api} }
sub config    { $_[0]{config} }
sub violation { $_[0]{violation} }
sub counters  { $_[0]{violation}->counters }
sub sampler   { $_[0]{sampler} }
sub spool     { $_[0]{spool} }
sub shipper   { $_[0]{shipper} }

# Aggregation -> spool -> shipping. Built here rather than in
# Maat::Violation because which of the three exist is a deployment
# decision: a gateway with no `report.url` still aggregates (so `maat
# tail` and /metrics work), and one with no `report.spool` still ships,
# it just has nowhere to put a batch the control plane refused.
sub _build_pipeline {
    my ($self, $sink) = @_;
    my $r    = $self->{config}->report;
    my $spec = eval { $self->{api}->spec };

    if ($r->{spool}) {
        require Maat::Spool;
        $self->{spool} = eval {
            Maat::Spool->new(
                dir       => $r->{spool},
                max_files => $r->{spool_files},
                max_bytes => $r->{spool_bytes},
            );
        };
        # A spool directory that cannot be made is a configuration
        # mistake, but not one worth refusing to serve traffic over: the
        # gateway's job is proxying, and it can still aggregate and
        # report through /metrics without a disk to spill onto.
        warn "Maat: cannot use the spool at $r->{spool}: $@" if !$self->{spool};
    }

    if ($r->{url}) {
        require Maat::Shipper;
        # The coverage callback is a weak reference to avoid the obvious
        # cycle (gateway holds shipper holds closure holds gateway); a
        # gateway that has gone away reports nothing rather than keeping
        # itself alive to do so.
        my $weak = $self;
        require Scalar::Util;
        Scalar::Util::weaken($weak);

        $self->{shipper} = Maat::Shipper->new(
            url      => $r->{url},
            token    => $r->{token},
            spool    => $self->{spool},
            interval => $r->{interval},
            batch    => $r->{batch},
            gzip     => $r->{gzip},
            timeout  => $r->{timeout},
            coverage_interval => $r->{coverage_interval},
            coverage => sub { $weak ? $weak->coverage : undef },
            # Metering, on the same channel, token and retry story as
            # everything else here. `usage_shipped` is the commit: a
            # bucket is only marked as reported once the control plane
            # has taken it, exactly as coverage_at only advances on
            # success, so a failed POST re-sends rather than losing an
            # hour of somebody's bill.
            usage      => sub { $weak ? $weak->usage : undef },
            usage_done => sub { $weak->usage_shipped($_[0]) if $weak },
        );
    }

    # Where a closed window goes: an explicit sink wins (tests, `maat
    # tail`), then the spool, then the in-process ring.
    my $spool = $self->{spool};
    my $out   = $sink ? $sink
              : $spool ? sub { $spool->push_batch($_[0]) }
              : undef;

    require Maat::Redact;
    return Maat::Violation->new(
        sink         => $out,
        window       => $r->{window},
        max_keys     => $r->{max_keys},
        environment  => $r->{environment},
        spec         => $spec,
        spec_version => (ref $spec eq 'HASH' ? $spec->{info}{version} : undef),
        redact       => Maat::Redact->new(
            mode  => $r->{redact},
            names => $r->{redact_names},
            spec  => $spec,
        ),
    );
}

# Hand the pipeline over to the worker's own loop, once, if there is one.
#
# Without this, the request that happens to close a window pays for the
# flush and the spool write - measured at t/16, a 3ms outlier on an
# otherwise 15us path. It is bounded and rare (once per window per
# worker) and the p99 does not move, but it is a stall on a customer's
# request for work that was never theirs, and a loop can simply do it
# instead.
#
# `psgix.loop` is the test rather than `require Hyperman`, because it is
# the one that distinguishes a live worker loop from the module merely
# being installed - and off a loop Hyperman->timer would block for the
# whole interval, which on a request path would be the worst bug in this
# distribution.
sub arm {
    my ($self, $env) = @_;
    return 0 if $self->{armed};
    return 0 unless $env && $env->{'psgix.loop'};
    $self->{armed} = 1;

    my $every = $self->{config}->report->{interval} || 5;
    my $tick;
    $tick = sub {
        $self->pump;
        my $f = eval { Hyperman->timer($every) } or return;
        $f->on_done($tick);
        return;
    };
    my $ok = eval {
        require Hyperman;
        my $f = Hyperman->timer($every);
        $f->on_done($tick);
        1;
    };
    $self->{armed} = $ok ? 1 : 0;   # a failure may be retried by the next one
    return $ok ? 1 : 0;
}

# Move the pipeline along: close the window if it is due, then let the
# shipper drain if its interval has elapsed. Neither blocks - the flush
# is a hash walk and a local write, and the send is a future nobody
# waits on.
#
# Driven two ways, because a gateway has two very different rhythms. On
# a Hyperman worker the loop timer armed above calls it, so a window
# closes on time whether or not traffic is arriving. Everywhere else it
# is called from the violation path, which is where there is something
# to send anyway; that cost is paid by requests which have already
# failed their contract, never by conforming ones.
sub pump {
    my ($self, $now) = @_;
    $now = Time::HiRes::time() unless defined $now;
    my $v = $self->{violation};
    return unless $v->due($now) || $self->{shipper};

    # Under the same watchdog as the recorder, and for the same reason.
    # The sink is where a closed window goes, and a sink is somebody
    # else's code - the spool's disk write, a customer's `apip tail`, a
    # test's closure. Aggregation moved that call from record() to
    # flush(); the alarm has to move with it, or the one thing this
    # component promises - that reporting cannot hold a request - would
    # have quietly stopped being true the moment it started batching.
    my $ok = eval {
        local $SIG{ALRM} = sub { die "Maat: violation flush timed out\n" };
        Time::HiRes::alarm($self->{record_timeout});
        $v->flush($now) if $v->due($now);
        $self->{shipper}->tick($now) if $self->{shipper};
        Time::HiRes::alarm(0);
        1;
    };
    if (!$ok) {
        Time::HiRes::alarm(0);
        $v->count('failed');
    }
    return;
}

# Everything the gateway knows about itself. The pipeline's own health is
# in here on purpose: a customer whose violations stopped arriving needs
# to be able to tell "nothing went wrong" from "everything went wrong and
# we could not tell you".
sub metrics {
    my ($self) = @_;
    my %m = (
        counters => { %{ $self->{violation}->counters } },
        window   => { open_keys => $self->{violation}->open_keys },
        coverage => $self->coverage,
    );
    $m{spool}   = $self->{spool}->stats   if $self->{spool};
    $m{shipper} = $self->{shipper}->stats if $self->{shipper};
    return \%m;
}

# ---- metering ---------------------------------------------------------------
#
# What the account page bills from, and the only writer of usage_hours
# on the control plane.
#
# Requests are counted in C already - the request path bumps
# `counters->{request}` - so this samples that total rather than adding
# a second counter to the hot path. Each call takes the delta since the
# last one and drops it in the bucket for the hour it is being read in,
# which is accurate to within one shipping interval at an hour boundary:
# five seconds of traffic can land in the wrong hour, out of thirty-six
# hundred. Counting per hour in C would cost every request a
# division to remove that, and the meter bills by the month.
#
# The number reported for an hour is this reporter's RUNNING TOTAL for
# it, never a delta, because the control plane replaces rather than
# adds: a retried batch writes the same number again, which is what
# makes retries safe on a billing path. And because every worker of
# every instance meters only what it handled, the row is keyed by
# gateway id on the far side and summed - see sql/schema.sql there.

use constant USAGE_HOURS => 26;   # buckets held; a day, plus slack

sub _usage_sample {
    my ($self, $now) = @_;
    $now = time unless defined $now;
    my $hour  = $now - ($now % 3600);
    my $total = eval { $self->{violation}->counters->{request} } || 0;

    my $delta = $total - ($self->{usage_seen} || 0);
    $self->{usage_seen} = $total;
    # A counter that went backwards is a worker that restarted; its
    # buckets went with it, so start from here rather than reporting a
    # negative hour.
    $self->{usage}{$hour} = ($self->{usage}{$hour} || 0) + $delta
        if $delta > 0;

    # Tool calls, bucketed the same way. They are already in `request`
    # above - a tool call IS a request and is billed as one - so this is
    # the visibility split, not a second meter: how much of the hour an
    # agent asked for. `mcp` moves only on a delivered tool result, so
    # tools/list and initialize do not appear here.
    my $tools  = eval { $self->{violation}->counters->{mcp} } || 0;
    my $tdelta = $tools - ($self->{mcp_seen} || 0);
    $self->{mcp_seen} = $tools;
    $self->{mcp}{$hour} = ($self->{mcp}{$hour} || 0) + $tdelta
        if $tdelta > 0;

    # Bounded: an unbounded hash keyed by hour is a slow leak in a
    # process that is meant to run for months. The oldest go first, and
    # anything that old has either been shipped many times over or is
    # never going to be.
    my @hours = sort { $b <=> $a } keys %{ $self->{usage} };
    if (@hours > USAGE_HOURS) {
        delete $self->{usage}{$_}      for @hours[USAGE_HOURS .. $#hours];
        delete $self->{usage_sent}{$_} for @hours[USAGE_HOURS .. $#hours];
        delete $self->{mcp}{$_}        for @hours[USAGE_HOURS .. $#hours];
    }
    return $hour;
}

# The buckets whose totals have moved since the control plane last took
# them. Empty when nothing has been served, so an idle tenant ships
# nothing at all rather than a heartbeat every five seconds.
sub usage {
    my ($self) = @_;
    $self->_usage_sample;
    my $gateway = eval { $self->{violation}->gateway_id };
    my @out;
    for my $hour (sort { $a <=> $b } keys %{ $self->{usage} }) {
        my $n = $self->{usage}{$hour};
        my $m = $self->{mcp}{$hour} || 0;
        # Both totals decide whether the hour has moved, and both ride in
        # the same entry. usage_hours is UNIQUE (proxy_id, hour, gateway)
        # and the control plane REPLACES the row rather than adding to it
        # - which is what makes a retried batch safe - so an entry
        # carrying `requests` without `mcp` would zero the other column
        # for that hour. They travel together or the meter lies.
        next if defined $self->{usage_sent}{$hour}
             && $self->{usage_sent}{$hour} eq "$n:$m";
        push @out, { hour     => $hour + 0,
                     requests => $n + 0,
                     mcp      => $m + 0,
                     (defined $gateway ? (gateway => "$gateway") : ()) };
    }
    return @out ? \@out : undef;
}

# The commit. Called by the shipper only after the control plane has
# accepted the batch, so a bucket that failed to land is offered again
# on the next drain instead of being quietly forgotten - the same rule
# coverage_at follows, and it matters more here, because the thing being
# forgotten would be somebody's invoice.
sub usage_shipped {
    my ($self, $shipped) = @_;
    return unless ref $shipped eq 'ARRAY';
    $self->{usage_sent}{ $_->{hour} } =
        ($_->{requests} || 0) . ':' . ($_->{mcp} || 0) for @$shipped;
    return;
}

# What was actually weighed, per operation: sampled, checked, each
# skip_*, and the divisor in force. A customer turning this on asks "how
# much of my traffic are you really looking at" and this is the answer,
# with the reason for every response that was not.
sub coverage {
    my ($self) = @_;
    my $cov = eval { $self->{api}->response_coverage } || {};
    for my $op (keys %$cov) {
        $cov->{$op}{divisor} = $self->{sampler}->divisor($op);
    }
    return $cov;
}

# ---- the request path -------------------------------------------------------

sub to_app {
    my ($self) = @_;

    # The whole request path is Maat.xs: the id, the counters, the
    # routing, the validation, the forward and the header stamp, without
    # unwinding into Perl except for the calls that must (Open::API's
    # router and validator, the proxy, and - only for a request that has
    # actually violated its contract - the recorder and the problem
    # builder). The Perl subs below are those calls; everything between
    # them is C.
    #
    # The measurement that motivated it, per request: the counters were
    # 0.09us each and the three eval blocks 0.04us together, yet the path
    # was 5.5us. The cost was a dozen Perl ops and four Perl/XS crossings
    # for two calls' worth of work - a shape, not a line.
    # Start the reporting rhythm on the FIRST REQUEST, not on the first
    # violation.
    #
    # It used to be armed from _record, which is only reached by a
    # request that failed its contract - so a tenant whose traffic
    # conforms never started the timer, never ticked the shipper, and
    # never reported anything at all. That was survivable while the only
    # thing being reported was violations (a gateway with none has
    # nothing to say). It stopped being survivable with coverage, which
    # exists precisely to tell that customer they ARE being looked at,
    # and it became a billing bug with usage: a proxy can serve a million
    # perfectly conforming requests and still have an invoice.
    #
    # Only arms; it does NOT pump. Off a loop there is nothing to arm,
    # and driving the pipeline from the request path instead would put a
    # shipper's POST - DNS, a connection, a control plane having a bad
    # minute - in front of a customer's response. That is the one thing
    # this component promises never to do. Off-loop deployments keep the
    # old rhythm, driven from the violation path.
    #
    # Bounded retries because an arm that failed once will fail the same
    # way every time: a process either has a loop or it does not, and
    # `require Hyperman` plus a died eval per request is not free.
    my $tries = 0;
    my $start = sub {
        my ($env) = @_;
        return if $tries++ > 2;
        $self->arm($env);
        return;
    };

    my $metrics = $self->{config}->report->{metrics};
    return sub {
        # One hash lookup and a branch once the timer is running, which
        # is what the whole $start closure exists to buy: this is the
        # request path, and it is C either side of here.
        $self->{armed} or $start->($_[0]);
        return Maat::Gateway::_serve($self, $_[0]);
    } unless defined $metrics;

    # With a metrics path configured there is one string comparison in
    # front of the C path. A gateway that has not asked for it does not
    # get the closure at all, which is why this is a branch here rather
    # than a branch per request.
    #
    # It shadows that path on the proxied API. That is why it is off by
    # default and why the operator has to name it: silently intercepting
    # a path the upstream serves would be the single rudest thing a
    # transparent proxy could do.
    return sub {
        my ($env) = @_;
        $self->{armed} or $start->($env);
        return $self->_metrics_response
            if ($env->{PATH_INFO} || '') eq $metrics;
        return Maat::Gateway::_serve($self, $env);
    };
}

sub _metrics_response {
    my ($self) = @_;
    my $body = eval {
        require File::Raw::JSON;
        File::Raw::JSON::file_json_encode($self->metrics);
    };
    $body = '{"error":"metrics unavailable"}' unless defined $body;
    return [ 200,
             [ 'Content-Type'   => 'application/json',
               'Content-Length' => length $body,
               'Cache-Control'  => 'no-store' ],
             [ $body ] ];
}

# ---- what the C path calls back into --------------------------------------
# Each of these is either rare (a violation), or owns a piece that
# changes independently of the request path (the response check).

# The response check's context, or undef when there is nothing to check
# against. Built here because phase 2 owns its shape.
#
# Cached per operation, and holding nothing that varies within one: the
# request id and the environment are already arguments of _forward, so
# they are passed through rather than packed in here. This is called on
# every request that matched an operation, and a nine-key hash built each
# time is a real cost on a path that totals two microseconds.
sub _seen {
    my ($self, $op) = @_;
    return undef unless $self->{sampler} && $self->{sampler}->mode ne 'off';
    return $self->{seen}{$op} ||= {
        api            => $self->{api},
        op             => $op,
        generation     => -1,   # forces the first look-up (see _check_response)
        violation      => $self->{violation},
        sampler        => $self->{sampler},
        chaos          => $self->{chaos},
        record_timeout => $self->{record_timeout},
        gateway        => $self,
    };
}

# The violation record, with the watchdog. $chaos_mode is 1 for a
# reporter that dies and 2 for one that blocks - the C path decides
# whether the point is armed, this performs it, because the alarm and
# the local are Perl's.
sub _record_request {
    my ($self, $rid, $op, $env, $errors, $chaos_mode) = @_;
    my $v = $self->{violation};
    my $ok = eval {
        local $SIG{ALRM} = sub { die "Maat: violation recording timed out\n" };
        Time::HiRes::alarm($self->{record_timeout});
        die "APIP_CHAOS: injected failure at 'record'\n" if $chaos_mode == 1;
        if ($chaos_mode == 2) { sleep 60 while 1 }
        $v->record(
            request_id => $rid,
            operation  => $op,
            method     => $env->{REQUEST_METHOD},
            path       => $env->{PATH_INFO},
            errors     => $errors,
            kind       => 'request',
            # Which tool an agent called, when this request was one. Set
            # only by the C that builds a synthetic request, so it says
            # `tool` exactly when a tool is what happened, and an owner
            # can see which of their tools an agent is actually driving
            # into drift.
            tool       => $env->{'maat.mcp.tool'},
        );
        Time::HiRes::alarm(0);
        1;
    };
    if (!$ok) {
        Time::HiRes::alarm(0);
        $v->count('failed');
    }
    $self->arm($env);
    $self->pump;
    return;
}

# ---- observe-only drift (Maat::Observe) -------------------------------------

# A path with no operation, forwarded to the upstream (or a known path hit
# with an undeclared method). Called from the C request path only when the
# tenant has an upstream and the observe toggle is on - never in mock mode.
# $extra is the match's second value: an arrayref of allowed methods for a
# wrong-method, otherwise the undeclared case. Total by construction: an
# observation that will not record loses itself and nothing else.
sub _record_undeclared {
    my ($self, $rid, $env, $extra) = @_;
    return unless $self->{observe};
    my $v = $self->{violation} or return;
    my $keyword = (ref $extra eq 'ARRAY') ? 'wrong-method' : 'undeclared-endpoint';
    my $ok = eval {
        local $SIG{ALRM} = sub { die "Maat: observe recording timed out\n" };
        Time::HiRes::alarm($self->{record_timeout});
        require Maat::Observe;
        Maat::Observe::record_undeclared(
            v            => $v,
            method       => $env->{REQUEST_METHOD},
            path         => $env->{PATH_INFO},
            keyword      => $keyword,
            spec_version => $v->spec_version,
        );
        Time::HiRes::alarm(0);
        1;
    };
    if (!$ok) { Time::HiRes::alarm(0); $v->count('failed'); }
    $self->arm($env);
    $self->pump;
    return;
}

# Undeclared/deprecated request parameters on a matched, conforming request.
# Called from _forward on every matched request, but the walk runs only
# one request in N per operation - the request-side twin of the response
# sampler, off the same divisor so a hot endpoint is thinned exactly as its
# responses are. A gateway with response validation off still observes, at
# a fixed floor, so undeclared params are not silently coupled to it.
sub _observe_request {
    my ($seen, $env) = @_;
    my $g = $seen->{gateway} or return;
    return unless $g->{observe};
    my $sampler = $seen->{sampler} or return;
    my $op = $seen->{op};
    my $n = $sampler->mode eq 'off' ? 25 : ($sampler->divisor($op) || 1);
    return unless (++$g->{observe_count}{$op}) % $n == 0;

    my $v = $seen->{violation} or return;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "Maat: observe timed out\n" };
        Time::HiRes::alarm($g->{record_timeout});
        require Maat::Observe;
        Maat::Observe::request_params(
            v => $v, api => $seen->{api}, op => $op, env => $env);
        Time::HiRes::alarm(0);
        1;
    };
    if (!$ok) { Time::HiRes::alarm(0); $v->count('failed'); }
    return;
}

sub _problem_400 {
    my ($rid, $errors) = @_;
    return _problem($rid, 400, 'Bad Request',
        'the request does not conform to the API description', $errors);
}

sub _problem_405 {
    my ($rid, $allow, $method) = @_;
    my $list = join ', ', @{ $allow || [] };
    return _problem($rid, 405, 'Method Not Allowed',
        "the document declares this path but not " . (defined $method ? $method : '?'),
        [ { in => 'method', keyword => 'allow',
            message => "allowed: $list" } ],
        [ 'Allow' => $list ]);
}

# ---- forwarding -------------------------------------------------------------

# Whatever Reverse::Proxy hands back goes back unchanged except for the
# request id: a triplet gets the header pushed, a delayed response gets
# its responder wrapped, a future gets a then. Anything else is returned
# untouched rather than guessed at - phase 1's gate is that a conforming
# response is byte-identical, and inventing a wrapper for a shape we do
# not recognise is how that stops being true.
#
# The response check hooks in at the same three points. It reads the
# triplet and never writes to it: whatever the verdict, the client
# receives the upstream's bytes. `$seen` carries what the check needs -
# the operation, the request id and the machinery - or is undef when
# there is nothing to check against (an undeclared path, a chaos-broken
# match, a response Reverse::Proxy handed back in a shape we do not
# recognise).
sub _forward {
    my ($proxy, $env, $rid, $seen) = @_;
    _observe_request($seen, $env) if $seen;   # sampled, total; never fails
    my $res = $proxy->($env);

    if (ref $res eq 'ARRAY') {
        _stamp($res, $rid);
        _check_response($seen, $res, $rid, $env) if $seen;
        return $res;
    }
    if (ref $res eq 'CODE') {
        return sub {
            my ($responder) = @_;
            return $res->(sub {
                my ($r) = @_;
                if (ref $r eq 'ARRAY') {
                    _stamp($r, $rid);
                    _check_response($seen, $r, $rid, $env) if $seen;
                }
                return $responder->($r);
            });
        };
    }
    if (Scalar::Util::blessed($res) && $res->can('then')) {
        return $res->then(sub {
            my ($r) = @_;
            if (ref $r eq 'ARRAY') {
                _stamp($r, $rid);
                _check_response($seen, $r) if $seen;
            }
            return $r;
        });
    }
    return $res;
}

# ---- the response check -----------------------------------------------------

# Weigh the response against the schema its status declares, and record a
# mismatch. Everything here is bookkeeping: the response has already been
# handed back, and there is nothing this can do to it even if it wanted
# to. So every failure inside it - a validator that dies, a spec handle
# that has gone, a reporter that blocks - loses the sample and nothing
# else. That is why the whole thing sits inside one eval, and why there
# is no branch anywhere below that returns a different response.
#
# Response violations are recorded in both modes, `enforce` included. A
# response cannot be un-sent, and answering 502 because the upstream's
# body drifted from its schema would turn a documentation bug into an
# outage - the customer's outage, caused by us. Enforcement of responses
# is a product decision for a later phase, not a side effect of this one.
sub _check_response {
    my ($seen, $res, $rid, $env) = @_;
    my ($api, $op, $v, $sampler, $chaos, $rt) =
        @{$seen}{qw(api op violation sampler chaos record_timeout)};

    my $had_errors = 0;
    my $ok = eval {
        _chaos_fire($chaos, 'response');

        # This runs on every proxied response, so it is written against
        # the sampler's fields rather than its accessors - see the
        # hot-path contract in Maat::Sampler. Measured: the two method
        # calls this replaces cost 0.19us together, three times the C
        # check they were guarding.
        #
        # The retune's arithmetic happens at most once an interval, and
        # building the coverage hash to feed it costs 0.5us - so it is
        # not built unless the clock says the retune will actually run.
        my $now = time;
        if ($now >= $sampler->{next_at}) {
            $sampler->retune($api->response_coverage, $now);
        }
        my $opts = $seen->{opts};
        if (!$opts || $seen->{generation} != $sampler->{generation}) {
            $opts = $seen->{opts} = $sampler->options($op);
            $seen->{generation} = $sampler->{generation};
        }
        return 1 unless $opts;              # response validation is off

        my $errors = $api->check_response($op, $res, $opts);
        return 1 unless $errors && @$errors;
        $had_errors = 1;

        $v->count('response_violation');
        local $SIG{ALRM} = sub { die "Maat: violation recording timed out\n" };
        Time::HiRes::alarm($rt);
        _chaos_fire($chaos, 'record');
        _chaos_hang($chaos);
        $v->record(
            request_id => $rid,
            operation  => $op,
            method     => $env->{REQUEST_METHOD},
            path       => $env->{PATH_INFO},
            status     => $res->[0],
            kind       => 'response',
            errors     => $errors,
            tool       => $env->{'maat.mcp.tool'},
        );
        Time::HiRes::alarm(0);
        1;
    };
    if (!$ok) {
        Time::HiRes::alarm(0);
        $v->count('failed');
    }
    # Observe-only: a CONFORMING response can still carry fields the schema
    # never named or declared-deprecated ones still in use. Only conforming
    # responses are walked - a non-conforming one is already recorded as a
    # violation, and piling field observations on it is noise. On its own
    # sampled cadence, reading the response array without touching it.
    _observe_response($seen, $res, $env) unless $had_errors;
    $seen->{gateway}->pump if $seen->{gateway};
    return;
}

# The response-body twin of _observe_request: decode a JSON response body
# the gateway already holds and walk it for undeclared and deprecated fields
# (Maat::Observe::response_extras). Only a simple buffered body is read - a
# streamed or filehandle body is left untouched, since reading it would
# consume the client's bytes.
#
# Called only for a CONFORMING response (the caller's guard), and only when
# this operation is validated at 1-in-1. That second condition is what makes
# "conforming" trustworthy: at any coarser sampling, check_response returns
# nothing for a conforming response AND for an unsampled one alike, so we
# could not tell a clean response from one nobody looked at - and walking an
# unsampled response would both mislabel drift and add a body walk to exactly
# the hot path the sampler thinned. A thinned operation is not walked; a
# fully-validated one is.
sub _observe_response {
    my ($seen, $res, $env) = @_;
    my $g = $seen->{gateway} or return;
    return unless $g->{observe};
    return unless ref $res eq 'ARRAY' && ref $res->[2] eq 'ARRAY'
               && ref $res->[1] eq 'ARRAY';
    my $sampler = $seen->{sampler};
    my $op = $seen->{op};
    return unless $sampler && $sampler->mode ne 'off'
               && ($sampler->divisor($op) || 1) == 1;

    my $ct = _header_value($res->[1], 'content-type');
    return unless defined $ct && $ct =~ m{\bjson\b}i;
    my $body = join '', grep { defined && !ref } @{ $res->[2] };
    return unless length $body && length $body <= 262144;   # 256K observe cap

    my $v = $seen->{violation} or return;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "Maat: observe timed out\n" };
        Time::HiRes::alarm($g->{record_timeout});
        require File::Raw::JSON;
        my $decoded = File::Raw::JSON::file_json_decode($body);
        if (ref $decoded) {
            require Maat::Observe;
            Maat::Observe::response_extras(
                v => $v, api => $seen->{api}, op => $op,
                status => $res->[0], body => $decoded);
        }
        Time::HiRes::alarm(0);
        1;
    };
    if (!$ok) { Time::HiRes::alarm(0); $v->count('failed'); }
    return;
}

sub _header_value {
    my ($hdrs, $want) = @_;
    for (my $i = 0; $i + 1 < @$hdrs; $i += 2) {
        return $hdrs->[$i + 1] if lc($hdrs->[$i] // '') eq $want;
    }
    return undef;
}

sub _stamp {
    my ($res, $rid) = @_;
    return unless ref $res eq 'ARRAY' && ref $res->[1] eq 'ARRAY';
    my $h = $res->[1];
    for (my $i = 0; $i < @$h; $i += 2) {
        return if lc $h->[$i] eq 'x-request-id';   # the upstream set its own
    }
    push @$h, 'X-Request-Id' => $rid;
    return;
}

# ---- mock mode --------------------------------------------------------------

# The stand-in for Reverse::Proxy when the mode is `mock`: answer from the
# document. By the time a request reaches this, mt_serve has already
# validated it (mock shares enforce's rejection path, so a non-conforming
# request was answered 400 with its pointers and never gets here) - what
# remains is synthesis, which Open::API does in C, deterministically.
#
#   declared operation    the synthesized response for its status
#                         (Prefer: code=N / example=name are honoured)
#   undeclared path       404 problem+json naming it undeclared - a mock
#                         has no upstream to forward the unknown to, and
#                         inventing a 200 for a path the document does not
#                         declare would defeat the one thing a mock is for
#   ?__delay=250ms        an artificial delay, capped at mock.max_delay
#                         (10s default) so a public mock URL cannot be
#                         held open as a DoS lever
#
# A synthesis failure - including the APIP_CHAOS `mock` point - is a 500
# problem+json, counted `failed`. Never a hang, never a die escaping to
# the server: the response path of a mock fails closed with an honest
# error, where the proxy's fails open with a forward, because here there
# is nothing to fail open TO.
sub _mock_app {
    my ($self) = @_;
    my $api       = $self->{api};
    my $chaos     = $self->{chaos};
    my $violation = $self->{violation};
    my $max_delay = ($self->{config}->mock || {})->{max_delay} || 10;

    return sub {
        my ($env) = @_;
        my $rid = $env->{'maat.request_id'};
        my $res = eval {
            _chaos_fire($chaos, 'mock');
            _mock_delay($env->{QUERY_STRING}, $max_delay);
            my ($op, $caps) = $api->match($env->{REQUEST_METHOD},
                                         $env->{PATH_INFO});
            if (!defined $op) {
                return _problem($rid, 404, 'Not Found',
                    'the API description does not declare this path, and '
                  . 'a mock has nothing to forward it to',
                    [ { in => 'path', keyword => 'undeclared',
                        message => 'not in the API description' } ]);
            }
            # The captures go with it: a property the response schema
            # names and the request has already answered is answered
            # with what the request said, so GET /pets/42 replies with
            # id 42 rather than the schema placeholder.
            return $api->synthesize($op, {
                prefer => $env->{HTTP_PREFER},
                (ref $caps eq q{HASH} ? (path => $caps) : ()),
            });
        };
        return $res if $res;
        $violation->count('failed');
        return _problem($rid, 500, 'Internal Server Error',
            'the mock could not synthesize a response', []);
    };
}

# ?__delay=250ms, ?__delay=1.5s or ?__delay=2 (seconds) - bounded by the
# cap, so the largest ask costs a known amount.
sub _mock_delay {
    my ($qs, $cap) = @_;
    return unless defined $qs
        && $qs =~ /(?:\A|&)__delay=([0-9]*\.?[0-9]+)(ms|s)?(?:&|\z)/;
    my $secs = ($2 // 's') eq 'ms' ? $1 / 1000 : $1 + 0;
    $secs = $cap if $secs > $cap;
    Time::HiRes::sleep($secs) if $secs > 0;
    return;
}

# ---- problem+json -----------------------------------------------------------
# RFC 7807. The errors are Open::API's own - instanceLocation, keyword,
# message, in, name - so the client is told which pointer failed and
# why, not merely that something did.
sub _problem {
    my ($rid, $status, $title, $detail, $errors, $extra_headers) = @_;
    my $body = File::Raw::JSON::file_json_encode({
        type   => 'https://openapi-proxy.com/problem/request-validation',
        title  => $title,
        status => $status + 0,
        detail => $detail,
        errors => [ map { {
            in      => $_->{in},
            name    => $_->{name},
            pointer => $_->{instanceLocation},
            keyword => $_->{keyword},
            message => $_->{message},
        } } @{ $errors || [] } ],
        request_id => $rid,
    }, sort_keys => 1);   # canonical, like _problem_429 and the edge's
    return [ $status,
             [ 'Content-Type'   => 'application/problem+json',
               'Content-Length' => length $body,
               'X-Request-Id'   => $rid,
               @{ $extra_headers || [] } ],
             [ $body ] ];
}

# ---- env helpers ------------------------------------------------------------


# Read the body and put it back, so the proxy forwards the same bytes.
sub _slurp_input {
    my ($env, $len) = @_;
    my $in = $env->{'psgi.input'} or return undef;
    my $body = '';
    my $got = 0;
    while ($got < $len) {
        my $n = $in->read(my $chunk, $len - $got);
        last if !defined $n || $n == 0;
        $body .= $chunk;
        $got += $n;
    }
    open my $replay, '<', \$body or return $body;
    $env->{'psgi.input'} = $replay;
    return $body;
}

# ---- chaos ------------------------------------------------------------------
# APIP_CHAOS is a supported switch, not a test fixture: it injects the
# failures the request path is written to survive, so fail-open is a
# property anyone can verify in their own staging environment.
#
#   freed      the compiled spec handle is gone for this request; the
#              router call dies exactly as a use-after-free reaches Perl
#   validate   the validator dies mid-request
#   alloc      buffering the request body fails, as an allocation would
#   record     the violation reporter dies
#   block      the violation reporter blocks forever (the watchdog
#              abandons it after record_timeout)
#   match      a die inside routing (the generic form of `freed`)
#   all        every one of the above
#
# Each point takes an optional rate: `validate:0.1` fires one request in
# ten. Under any of them the `failed` counter moves and traffic flows.

my @CHAOS_POINTS = qw(freed match alloc validate response record block mock);

sub _chaos {
    my ($explicit) = @_;
    my $spec = defined $explicit ? $explicit : $ENV{APIP_CHAOS};
    return undef unless defined $spec && length $spec;
    my %on;
    for my $part (split /\s*,\s*/, $spec) {
        my ($name, $rate) = split /:/, $part, 2;
        $name = lc $name;
        $rate = defined $rate ? $rate + 0 : 1;
        if ($name eq 'all') { $on{$_} = $rate for @CHAOS_POINTS }
        else                { $on{$name} = $rate }
    }
    return \%on;
}

sub _chaos_on {
    my ($chaos, $where) = @_;
    return 0 unless $chaos && $chaos->{$where};
    return 0 if $chaos->{$where} < 1 && rand() > $chaos->{$where};
    return 1;
}

sub _chaos_fire {
    my ($chaos, $where) = @_;
    die "APIP_CHAOS: injected failure at '$where'\n" if _chaos_on($chaos, $where);
    return;
}

# The blocking reporter: sit still until the watchdog's alarm interrupts
# and the handler's die unwinds us.
sub _chaos_hang {
    my ($chaos) = @_;
    return unless _chaos_on($chaos, 'block');
    sleep 60 while 1;
    return;
}

1;

__END__

=head1 NAME

Maat::Gateway - validate against an OpenAPI document, then forward

=head1 SYNOPSIS

    my $config  = Maat::Config->load('apip.yml');
    my $gateway = Maat::Gateway->new(config => $config);
    my $app     = $gateway->to_app;      # a PSGI coderef

=head1 DESCRIPTION

A PSGI application that matches each request against a compiled OpenAPI
document, validates it, and forwards it to the upstream through
L<Reverse::Proxy>.

=head2 What happens to a request

=over 4

=item * B<Not in the document> - forwarded, counted C<undeclared>. A
specification that does not cover everything is the normal case, and a
gateway that rejects what it has not been told about cannot be installed
in front of a real API.

=item * B<In the document, wrong method> - forwarded and counted in
C<observe>; C<405> with an C<Allow> header in C<enforce>.

=item * B<Does not conform> - recorded, and forwarded in C<observe>. In
C<enforce> it is answered with C<application/problem+json> carrying the
failing pointers, and the upstream never sees it.

=item * B<Conforms> - forwarded, counted C<conforming>.

=back

The response is returned exactly as the upstream produced it, with
C<X-Request-Id> added when the upstream did not set one.

=head2 What happens to a response

Every response to a request that matched an operation is weighed against
the schema the document declares for its status - and B<the client
receives the upstream's bytes either way>. Status, headers and body are
read and never written. A gateway that edited what the upstream sent
would not be a gateway.

That applies in C<enforce> as well. A response cannot be un-sent, and
answering C<502> because a body drifted from its schema would turn a
documentation bug into an outage - the customer's outage, caused by us.
Response violations are recorded in both modes and rejected in neither;
whether enforcement should ever extend to responses is a product
decision, not a side effect of this one.

A response is checked only if it passes the sampling gate and then every
skip rule: the content type must be one the document declares JSON for,
the body must be within C<responses.max_body> and must be a plain scalar
(a filehandle or a streaming writer is never read), and the status must
declare a schema. Each skip has its own counter, so what was not looked
at is a number rather than a silent gap. See L</coverage>.

=head2 How much is checked

L<Maat::Sampler> chooses, per operation, how much of the traffic to
weigh: by default at most 50 validated responses a second for each
operation, and never longer than 10 seconds without one. The arithmetic
runs on a timer; the request path does a clock comparison and a hash
lookup.

The cost of all of this is measured, not asserted - see
F<bench/gateway.pl> and F<bench/RESULTS.md>.

=head2 What happens to a violation

Not one record per violation. One upstream deploy that changes a field's
type turns every request into a violation, and a gateway that emitted a
record for each would become the outage it was installed to detect. So
violations are aggregated in the process by fingerprint - see
L<Maat::Violation> - and one record per fingerprint per window leaves.
Measured at F<t/16-violation-load.t>: 270,000 violations became 8
records, with the p99 unmoved against the same run with reporting off.

From there a record goes to a L<Maat::Spool> (bounded, on disk, drops
oldest and counts it) and a L<Maat::Shipper> takes it to the control
plane (batched, gzipped, backed off). Nothing in that chain can make a
request wait: the flush is under the same watchdog as the recorder, and
the send is a future nobody awaits.

At most one example value travels, redacted by L<Maat::Redact>, and only
for the first occurrence of a fingerprint in a window. No value from a
payload ever enters a fingerprint.

=head2 Mock mode

    mode: mock        # in apip.yml; no upstream

A gateway with no upstream: responses are synthesized from the document
itself, in C, by L<Open::API/synthesize>. The request half is the same
path as the proxy - matched, validated, counted - which is what makes a
mock a client-side conformance check: send a non-conforming request and
the answer is the same C<400> C<application/problem+json>, carrying the
failing pointers, that C<enforce> would give.

=over 4

=item * B<Declared operation> - the synthesized response: the media
type's example, a named or the first C<examples> entry, the schema's
default, or a value generated from the schema. Deterministic - the same
request gives byte-identical bodies. C<Prefer: code=404> selects a
status; C<Prefer: example=name> selects a named example.

=item * B<Undeclared path> - C<404> problem+json naming it undeclared,
counted C<undeclared>. A mock has nothing to forward the unknown to,
and inventing a C<200> for a path the document does not declare would
defeat the one thing a mock is for.

=item * B<Undeclared method on a declared path> - C<405> with C<Allow>,
as in C<enforce>.

=item * B<C<?__delay=250ms>> (also C<1.5s>, or bare seconds) - holds the
response, capped at C<mock.max_delay> (10 seconds by default) so a
public mock URL cannot be held open as a denial-of-service lever.

=back

A synthesis failure - including the C<APIP_CHAOS> C<mock> point - is
answered C<500> problem+json and counted C<failed>: never a hang, and
never an invented body. The mock's response path fails closed with an
honest error where the proxy's fails open with a forward, because a mock
has nothing to fail open to.

=head2 The request id

C<X-Request-Id> is taken from the request when the client sent one and
minted as a L<Horus> v7 UUID when it did not. It is forwarded to the
upstream, echoed on the response, and carried on every violation record,
so one id joins the client's logs, the upstream's logs and the drift
report.

=head2 The body

Validating a body means reading it, and reading it consumes
C<psgi.input> - so it is buffered and replaced before the forward. A
body larger than C<max_body> is not read at all: validating without it
would invent a "required body is missing" violation, so the check is
skipped, counted C<skipped>, and the bytes stream through untouched.

=head2 CHAOS

C<APIP_CHAOS> injects the failures this code is written to survive, so
fail-open is a tested property rather than a claim. It is a supported
switch: run it in staging and watch traffic keep flowing.

    APIP_CHAOS=all              everything fails, every request forwards
    APIP_CHAOS=freed            the spec handle is gone
    APIP_CHAOS=validate         the validator dies
    APIP_CHAOS=alloc            buffering the body fails
    APIP_CHAOS=block            the violation reporter blocks forever
    APIP_CHAOS=record:0.1       one recording in ten dies

The points are C<freed>, C<match>, C<alloc>, C<validate>, C<response>,
C<record>, C<block> and C<mock> (a mock-mode synthesis that dies,
answered C<500> problem+json); C<all> switches every one on, and C<name:rate>
fires a point on that fraction of requests. Under any of them the
C<failed> counter moves and no request is ever dropped. A reporter that
blocks is abandoned by a watchdog after C<record_timeout> seconds
(default 1).

C<response> breaks the response check specifically. It is the easiest of
them to reason about: the response has already been handed back by the
time the check runs, so a failure there can only lose the sample. That
is the property, and it is why the whole check sits inside one eval with
no branch that returns a different response.

The points fall into two classes. When the check itself breaks
(C<freed>, C<match>, C<validate>, and C<alloc> where there is a body to
buffer) the request cannot be judged, so it is forwarded - guessing
"reject" would turn Maat's bug into the customer's outage. When only
the bookkeeping breaks (C<record>, C<block>) validation has already
returned its verdict and the verdict stands, C<enforce> included: if a
failing reporter downgraded enforcement, anyone who could stall the
violation pipeline could switch off request validation.

=head1 METHODS

=head2 new(config => $config, sink => \&code, chaos => $spec, record_timeout => $secs)

Compile the spec, build the proxy, return the gateway. Croaks if the
spec does not compile.

=head2 metrics

Everything the gateway knows about itself: the counters, what the open
window holds, response coverage, and - when they exist - the spool's
depth and drops and the shipper's failures and backoff.

The pipeline's own health is in there on purpose. A customer whose
violations stopped arriving needs to be able to tell "nothing went
wrong" from "everything went wrong and we could not tell you".

Served as JSON on C<report.metrics> when that path is configured.

=head2 pump($now?) / arm($env)

Move the pipeline along - close a due window, let the shipper drain -
and, once, hand that job to the worker's event loop if there is one.

C<pump> is called from the violation path, so a gateway with no
violations pays nothing for having a pipeline. C<arm> is what stops the
one unlucky request that closes a window from paying for the flush: on
a Hyperman worker the loop does it instead, on its own timer.

=head2 coverage

    my $cov = $gateway->coverage;
    # { getPet => { total => 9120, sampled => 91, checked => 88,
    #               violations => 3, skip_ctype => 3, skip_size => 0,
    #               skip_body => 0, skip_schema => 0, skip_decode => 0,
    #               unsampled => 9029, divisor => 100 }, ... }

What was actually weighed, per operation, with the divisor in force. The
first question anyone asks on turning this on is "how much of my traffic
are you really looking at", and this answers it - including, for every
response that was not checked, which rule kept it out.

The counts add up: C<checked> plus every C<skip_*> plus C<unsampled>
equals C<total>. That is deliberate, and asserted in F<t/11-responses.t>:
coverage that did not add up would be a guess.

=head2 sampler

The L<Maat::Sampler> deciding how much to check.

=head2 to_app / api / config / violation / counters

=cut
