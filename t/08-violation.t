use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;

use Maat::Violation;
use Maat::Redact;

# Aggregation, fingerprinting and the bounds. The pressure this is
# written against is volume: one upstream deploy that changes a field's
# type turns every request into a violation, and what leaves the process
# has to stay proportional to the number of distinct problems rather
# than to the number of requests.

sub err {
    my (%o) = @_;
    return {
        in => 'body', name => $o{name},
        keyword => $o{keyword} || 'type',
        instanceLocation => $o{at} || '/name',
        schemaLocation   => $o{schema},
        message => "failed '@{[ $o{keyword} || 'type' ]}' constraint",
    };
}

# ---- counters ---------------------------------------------------------------
{
    my $v = Maat::Violation->new;
    isa_ok($v, 'Maat::Violation');
    is($v->counters->{request}, 0, 'counters start at zero');
    $v->count('request') for 1 .. 2;
    $v->count('failed', 3);
    is($v->counters->{request}, 2, 'count increments');
    is($v->counters->{failed}, 3, 'count takes an amount');
}

# ---- the fingerprint --------------------------------------------------------
{
    is(Maat::Violation->collapse_pointer('/items/3/sku'), '/items/*/sku',
        'array indices collapse');
    is(Maat::Violation->collapse_pointer('/items/3'), '/items/*',
        '...at the end too');
    is(Maat::Violation->collapse_pointer('/a/0/b/12/c'), '/a/*/b/*/c',
        '...at every level');
    is(Maat::Violation->collapse_pointer('/v2/name'), '/v2/name',
        'but a segment that merely contains a digit is left alone');

    my %base = (spec_version => '1.0.0', operation => 'createPet',
                status => 400, pointer => '/name', keyword => 'type');
    is(Maat::Violation->fingerprint(%base),
       Maat::Violation->fingerprint(%base), 'the same parts give the same key');
    isnt(Maat::Violation->fingerprint(%base),
         Maat::Violation->fingerprint(%base, keyword => 'required'),
        'a different keyword is a different problem');
    isnt(Maat::Violation->fingerprint(%base),
         Maat::Violation->fingerprint(%base, spec_version => '1.0.1'),
        'and so is a different version of the contract');

    # the parts cannot run together to forge a collision
    isnt(Maat::Violation->fingerprint(%base, operation => 'a', status => 'bc'),
         Maat::Violation->fingerprint(%base, operation => 'ab', status => 'c'),
        'the join cannot be spoofed by moving a character across it');
}

# ---- aggregation: many occurrences, one record ------------------------------
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10, spec_version => '1.0.0',
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;

    $v->record(request_id => "r$_", operation => 'createPet', method => 'POST',
               path => '/pets', status => 400, errors => [ err() ], now => $t)
        for 1 .. 1000;

    is(scalar @flushed, 0, 'nothing leaves while the window is open');
    is($v->open_keys, 1, 'a thousand identical violations are one fingerprint');
    is($v->counters->{occurrences}, 1000, 'every occurrence is counted');

    $v->flush($t + 10);
    is(scalar @flushed, 1, 'and one record leaves when the window closes');
    is($flushed[0]{count}, 1000, 'carrying the count');
    is($flushed[0]{sample_count}, 1000, 'and how many requests contributed');
    is($flushed[0]{operation_id}, 'createPet', 'with the operation');
    is($flushed[0]{pointer}, '/name', 'the pointer');
    is($flushed[0]{keyword}, 'type', 'and the keyword');
    ok($flushed[0]{fingerprint}, 'the fingerprint itself travels');
}

# ---- gate 4: an array of 500 bad elements is one fingerprint ---------------
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;

    $v->record(
        request_id => 'r1', operation => 'createOrder', method => 'POST',
        path => '/orders', status => 400, now => $t,
        errors => [ map { err(at => "/items/$_/sku") } 0 .. 499 ],
    );
    $v->flush($t + 10);

    is(scalar @flushed, 1, '500 bad elements produce ONE record');
    is($flushed[0]{count}, 500, '...with count 500');
    is($flushed[0]{sample_count}, 1,
        '...and sample_count 1: it was one request, not five hundred');
    is($flushed[0]{pointer}, '/items/*/sku', 'the collapsed pointer');
}

# ---- distinct problems stay distinct ----------------------------------------
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'createPet', status => 400, now => $t,
               errors => [ err(at => '/name', keyword => 'type'),
                           err(at => '/tag',  keyword => 'required') ]);
    $v->record(operation => 'listPets', status => 500, now => $t,
               errors => [ err(at => '/name', keyword => 'type') ]);
    $v->flush($t + 10);
    is(scalar @flushed, 3, 'three different problems, three records');
}

# biggest first, so anything forced to drop keeps what happened most
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'op', status => 400, now => $t,
               errors => [ err(at => '/rare') ]);
    $v->record(operation => 'op', status => 400, now => $t,
               errors => [ err(at => '/common') ]) for 1 .. 50;
    $v->flush($t + 10);
    is($flushed[0]{pointer}, '/common', 'the commonest problem is first');
}

# ---- the window closes on its own ------------------------------------------
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'op', status => 400, errors => [ err() ], now => $t);
    ok(!$v->due($t + 5), 'not due inside the window');
    is(scalar @flushed, 0, 'and nothing has left');

    # +11 rather than +10: the window opened when the object was built,
    # on a high-resolution clock, so its end is a fraction of a second
    # past $t + 10 rather than exactly on it.
    ok($v->due($t + 11), 'due at the end of it');
    $v->record(operation => 'op', status => 400, errors => [ err() ],
               now => $t + 11);
    is(scalar @flushed, 1, 'recording past the end closes the window first');
    is($flushed[0]{count}, 1, 'with what the closed window held');
    is($v->open_keys, 1, 'and the new occurrence opened the next one');
}

# ---- the bounds hold --------------------------------------------------------
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10, max_keys => 10,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'op', status => 400, now => $t,
               errors => [ err(at => "/field$_") ]) for 1 .. 100;

    is($v->open_keys, 10, 'the window holds at most max_keys fingerprints');
    is($v->counters->{keys_dropped}, 90,
        'and counts every one it refused to remember');
    $v->flush($t + 10);
    is(scalar @flushed, 10, 'only what it held leaves');
}

# the ring, when there is no sink
{
    my $v = Maat::Violation->new(window => 10, max => 5);
    my $t = time;
    for my $i (1 .. 8) {
        $v->record(operation => "op$i", status => 400, now => $t,
                   errors => [ err() ]);
        $v->flush($t);
    }
    is(scalar @{ $v->records }, 5, 'the ring holds max records');
    is($v->counters->{dropped}, 3, 'every drop counted');
    is($v->records->[-1]{operation_id}, 'op8', 'the newest kept');
}

# ---- gate 3: no trace of a password ----------------------------------------
{
    my $spec = {
        components => { schemas => { Login => { properties => {
            password => { type => 'string', format => 'password' },
            secret   => { type => 'string' },
            token    => { type => 'string', writeOnly => 1 },
            nickname => { type => 'string' },
        } } } },
    };
    my @flushed;
    my $v = Maat::Violation->new(window => 10, spec => $spec,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    my $payload = {
        password => 'hunter2-the-real-one',
        secret   => 'sekrit-value-here',
        token    => 'tok_live_abcdefgh',
        nickname => 'rex',
    };
    $v->record(
        operation => 'login', status => 400, now => $t, payload => $payload,
        errors => [
            err(at => '/password', schema => '/$defs/Login/properties/password/type'),
            err(at => '/secret',   schema => '/$defs/Login/properties/secret/type'),
            err(at => '/token',    schema => '/$defs/Login/properties/token/type'),
            err(at => '/nickname', schema => '/$defs/Login/properties/nickname/type'),
        ],
    );
    $v->flush($t + 10);

    is(scalar @flushed, 4, 'four fields, four records');

    # the gate as the plan states it: grep the shipped batch
    my $shipped = join "\x00", map { join "\x00", map { defined $_ ? $_ : '' }
                                     %$_ } @flushed;
    unlike($shipped, qr/hunter2/, 'no trace of the password value');
    unlike($shipped, qr/sekrit-value-here/, '...nor the secret');
    unlike($shipped, qr/tok_live/, '...nor the writeOnly token');

    my %by = map { $_->{pointer} => $_ } @flushed;
    ok(!exists $by{'/password'}{example}, 'format: password keeps no example');
    ok(!exists $by{'/token'}{example},    'writeOnly keeps no example');
    ok(!exists $by{'/secret'}{example},   'and the name alone is enough');
    is($by{'/nickname'}{example}, 'rex',
        'an ordinary field does keep one - that is the point of having them');
    is($by{'/nickname'}{got_type}, 'string', 'with the type it actually was');
}

# a value is kept only for the first occurrence in a window
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'op', status => 400, now => $t,
               payload => { name => 'first' }, errors => [ err() ]);
    $v->record(operation => 'op', status => 400, now => $t,
               payload => { name => 'second' }, errors => [ err() ]);
    $v->flush($t + 10);
    is($flushed[0]{example}, 'first', 'the first occurrence supplies the example');
    is($flushed[0]{count}, 2, 'the second only adds to the count');
}

# ---- expected, from the document rather than the payload -------------------
{
    my $spec = { components => { schemas => { Pet => { properties => {
        id => { type => 'integer' },
    } } } } };
    my @flushed;
    my $v = Maat::Violation->new(window => 10, spec => $spec,
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'getPet', status => 200, now => $t,
               payload => { id => 'not-a-number' },
               errors => [ err(at => '/id',
                               schema => '/$defs/Pet/properties/id/type') ]);
    $v->flush($t + 10);
    is($flushed[0]{expected}, 'integer', 'what the schema asked for');
    is($flushed[0]{got_type}, 'string',  'and what arrived');
}

# ---- what is stamped on every record ---------------------------------------
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10, spec_version => '2.3.4',
                                 gateway_id => 'gw-7', environment => 'staging',
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(request_id => 'rid-9', operation => 'op', status => 400,
               now => $t, errors => [ err() ]);
    $v->flush($t + 10);
    is($flushed[0]{spec_version}, '2.3.4', 'the contract version');
    is($flushed[0]{gateway_id}, 'gw-7', 'which gateway');
    is($flushed[0]{environment}, 'staging', 'which environment');
    is($flushed[0]{request_id}, 'rid-9',
        'and one request id, to find it in the customer own logs');
}

# ---- the record's identity, for an idempotent receiver ---------------------
#
# The spool replays a batch whenever the acknowledgement did not arrive.
# Without a stable identity on the record, the pipeline's own retry is
# indistinguishable from the traffic getting worse, and the control
# plane counts the same window twice.
{
    my @flushed;
    my $v = Maat::Violation->new(window => 10, gateway_id => 'gw-7',
                                 sink => sub { push @flushed, @{ $_[0] } });
    my $t = time;
    $v->record(operation => 'op', status => 400, now => $t,
               errors => [ err() ]);
    $v->record(operation => 'op', status => 400, now => $t + 1,
               errors => [ err() ]);
    $v->record(operation => 'other', status => 400, now => $t + 1,
               errors => [ err() ]);
    $v->flush($t + 10);
    is(scalar @flushed, 2, 'one record per fingerprint in the window');
    ok(defined $flushed[0]{window}, 'stamped with the window it came from');
    is($flushed[1]{window}, $flushed[0]{window},
        'every record of one window carries the same window');
    is($flushed[0]{count} + $flushed[1]{count}, 3,
        'holding every occurrence');

    # the next window is a different record even though everything a
    # fingerprint is made of is identical
    $v->record(operation => 'op', status => 400, now => $t + 11,
               errors => [ err() ]);
    $v->flush($t + 21);
    is(scalar @flushed, 3, 'the next window is its own record');
    is($flushed[2]{fingerprint}, $flushed[0]{fingerprint},
        'same fingerprint');
    isnt($flushed[2]{window}, $flushed[0]{window},
        'different window - so a receiver can tell a new window from a '
      . 'replayed one');
}

done_testing();
