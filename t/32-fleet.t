use 5.010;
use strict;
use warnings;
use lib 't/lib';
use MaatTest;
use RegistryStub;
use Test::More;
use IO::Socket::INET ();

use Maat::Fleet;

# Before anything localises Hyperman::loop below - a lazy require after
# the local would run XSLoader and install the real XS sub over it.
use Hyperman ();

# The fleet over a real socket.
#
# t/28-fleet.t is the composition test and injects `fetch` and
# `fetch_spec`, so it never exercises the HTTP this module actually
# does. This one points a fleet at a control plane on a port and drives
# it through Maat::Fleet's own fetchers: the registry URLs derived from
# the one base, the Bearer token on a lazy spec fetch, and the arming
# that can only happen on a worker's first request. Anything here that
# t/28 already covers would pass there by construction and prove
# nothing, so it is not repeated.

# ---- the URLs the control-plane base derives ---------------------------------
{
    my $c = Maat::Fleet->from_hash({
        control_plane  => 'https://cp.example.com',
        registry_token => 'shared',
    }, '.');
    is $c->{bundle_url}, 'https://cp.example.com/registry/bundle',
        'the bundle URL derives from the one base';
    is $c->{spec_url}, 'https://cp.example.com/registry/spec',
        '...and the spec URL';
    is $c->{guides_url}, 'https://cp.example.com/registry/guides',
        '...and the guides URL';
}

# ---- a control plane on a socket ---------------------------------------------

my $stub = RegistryStub->new;
$stub->add_tenant(host => 'one.openapi-proxy.com', proxy => 11,
    plan => 'starter', spec => RegistryStub->tenant_spec(1));
$stub->add_tenant(host => 'two.openapi-proxy.com', proxy => 22,
    plan => 'free', spec => RegistryStub->tenant_spec(2));

my $cp = MaatTest::start_upstream(respond => sub {
    my ($method, $target) = @_;
    # The stub builds the body, the ETag and the HMAC exactly as the
    # control plane does, so the poller's verification here is the real
    # one rather than a test that agrees with itself.
    my $r = $target =~ m{/registry/bundle} ? $stub->bundle_response
          : $target =~ m{/registry/spec/([0-9a-f]{64})}
                                           ? $stub->spec_response($1)
          : { status => 404, headers => {}, body => '' };
    return ($r->{status},
            [ map { ($_ => $r->{headers}{$_}) } sort keys %{ $r->{headers} } ],
            $r->{body});
});
END { MaatTest::stop_upstream($cp) if $cp }

my $fleet = Maat::Fleet->new(config => {
    control_plane  => "http://127.0.0.1:$cp->{port}",
    registry_token => $stub->token,
    interval       => 1,
});

# ---- over the wire -----------------------------------------------------------
{
    is $fleet->boot_poll, 'applied',
        'the boot poll fetches and verifies a bundle over HTTP';
    is scalar @{ $fleet->registry->hosts }, 2, '...and both tenants land';

    # The responder runs in a forked child, so what it saw has to be read
    # off disk - a hash it wrote would be the child's, not ours.
    ok scalar(grep { $_->{target} =~ m{/registry/bundle} }
                   MaatTest::upstream_log($cp)),
        'the control plane was actually asked';
}

{
    my $app = $fleet->app;
    my $env = MaatTest::psgi_env(path => '/hello');
    $env->{HTTP_HOST} = 'one.openapi-proxy.com';
    my ($status) = MaatTest::run_app($app, $env);
    is $status, 200, 'a tenant is served';

    # The point of this file: the spec came down Maat::Fleet's own
    # fetcher, lazily, on the first request for that host.
    ok scalar(grep { $_->{target} =~ m{/registry/spec/[0-9a-f]{64}} }
                   MaatTest::upstream_log($cp)),
        'its spec was fetched lazily, through the fleet fetcher';
}

# ---- arming ------------------------------------------------------------------
#
# arm() needs a worker's loop. Without one it must decline rather than
# die, because that is plackup, and every test in this distribution.
{
    my $app = $fleet->app;
    my $env = MaatTest::psgi_env(path => '/hello');
    $env->{HTTP_HOST} = 'one.openapi-proxy.com';
    delete $env->{'psgix.loop'};
    my ($status) = MaatTest::run_app($app, $env);
    is $status, 200, 'a request with no loop still serves';
    ok !$fleet->poller->{armed}, '...and the poller stays unarmed';

    # With one, the first request arms it and no later request re-arms:
    # app() is built before the fork, so this is the only hook there is.
    my $armed = 0;
    {
        no warnings 'redefine', 'once';
        local *Maat::Poller::arm = sub { $armed++; $_[0]{armed} = 1 };
        my $again = $fleet->app;
        for (1 .. 3) {
            my $e = MaatTest::psgi_env(path => '/hello');
            $e->{HTTP_HOST} = 'one.openapi-proxy.com';
            MaatTest::run_app($again, $e);
        }
    }
    is $armed, 1, 'the poller is armed once per worker, on the first request';
}

# ---- the spec fetcher's loop -------------------------------------------------
#
# This one is a scar. The fetcher used to build a loop-less Fetch agent,
# which inside a worker puts the request's fd on a private standalone
# loop while Fetch::Future->get pumps the ACTIVE one - Hyperman's. The
# request is never registered with the loop being pumped, so it never
# completes and its timeout never fires: a wedge, not a wait, and
# unbounded. It presented as a tenant compiled earlier serving fine
# while any tenant whose FIRST request landed there never answered at
# all, with the process looking healthy in ps.
{
    my $f = Maat::Fleet->new(config => {
        control_plane => 'http://control.invalid', registry_token => 't' });

    isa_ok $f->_ua->loop, 'Fetch::Loop::Standalone',
        'outside a worker the agent is standalone, so its blocking get '
      . 'pumps the loop its own request is on';

    # Inside one, it must take the worker's loop instead.
    my $fake = bless {}, 'Fetch::Loop::Standalone';   # any object will do
    my $g = Maat::Fleet->new(config => {
        control_plane => 'http://control.invalid', registry_token => 't' });
    {
        no warnings 'redefine', 'once';
        local *Hyperman::loop = sub { $fake };
        my $ua = $g->_ua;
        ok $ua, 'an agent is built inside a worker';
        is $ua->loop, $fake,
            'and it shares the worker loop rather than a private one';
    }
}

{
    # The agent must not survive the fork: the fleet is built in the
    # parent and every worker inherits it, so one made before the fork
    # would have its socket shared with every sibling. Maat::Poller::arm
    # calls forget_agent for exactly this; this is the same guard.
    my $f = Maat::Fleet->new(config => {
        control_plane => 'http://control.invalid', registry_token => 't' });
    my $first = $f->_ua;
    is $f->_ua, $first, 'the agent is reused within one process';
    $f->{ua_pid} = $$ + 1;                       # pretend we forked
    isnt $f->_ua, $first, 'and rebuilt in a process that did not make it';
}

# ---- a control plane that is not there ---------------------------------------
{
    # A port that actively refuses, not a low one a firewall may silently
    # drop - a dropped SYN waits out the OS connect timeout, which is
    # minutes, and would look exactly like a hung test.
    my $closed = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
        LocalPort => 0, Listen => 1, ReuseAddr => 1)
        or plan skip_all => "cannot bind a loopback port: $!";
    my $refused = $closed->sockport;
    $closed->close;

    my $dead = Maat::Fleet->new(config => {
        control_plane  => "http://127.0.0.1:$refused",
        registry_token => 'shared',
        timeout        => 2,
    });
    my $status = eval { $dead->boot_poll };
    ok !$@, 'an unreachable control plane does not die in boot_poll';
    isnt $status, 'applied',
        '...it returns the status word, and apip-fleet decides what it means';
    is scalar @{ $dead->registry->hosts }, 0, '...having applied nothing';
}

done_testing;
