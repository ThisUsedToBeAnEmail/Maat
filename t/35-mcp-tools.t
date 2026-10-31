use 5.010;
use strict;
use warnings;
use FindBin ();

# Prefer a sibling Open-API checkout, the way the ratelimit tests prefer a
# sibling Hyperman: operation_schema and operation_doc arrived in 0.13 and the
# installed copy is usually older. With 0.13 installed these lines are inert.
use lib "$FindBin::Bin/../../Open-API/blib/lib",
        "$FindBin::Bin/../../Open-API/blib/arch";

use lib 't/lib';
use RegistryStub;
use Test::More;

use File::Raw::JSON ();
use Open::API ();

plan skip_all => 'needs Open::API 0.13 (operation_schema)'
    unless Open::API->can('operation_schema');

use Maat;   # Maat::MCP::Tools is XS, in the Maat bundle

# The tools a proxied document offers an agent, derived once at compile time.
#
# Everything here is BUILD work. The gateway serves tools/list from frozen
# bytes and tools/call from a hash lookup, so the assertions that matter most
# are the ones about determinism and about `builds` not moving: a derivation
# that happened per request would be a per-request spec walk on the hot path.

sub decode { File::Raw::JSON::file_json_decode($_[0]) }

# ---- derived from a real tenant spec ---------------------------------------

my $api   = Open::API->new(spec => RegistryStub->portal_spec(1));
my $tools = Maat::MCP::Tools->new(api => $api);

is($tools->count, 2, 'both operations became tools');
is($tools->builds, 1, 'derived exactly once');

my @names = sort map { $_->{name} } @{ $tools->tools };
is_deeply(\@names, ['getpet1', 'listpets1'],
          'names are the operationIds, lower cased');

for my $n (@names) {
    like($n, qr{\A[a-z0-9_-]{1,64}\z}, "$n is a legal tool name");
}

my $get = $tools->tool('getpet1');
ok($get, 'a tool is reachable by name');
is($get->{operationId}, 'getPet1', 'it remembers the operationId it came from');
is($get->{title}, 'Fetch one pet by id', 'title is the summary');
like($get->{description}, qr/Fetch one pet by id/, 'description carries the summary');

# ---- the input schema ------------------------------------------------------

my $schema = $get->{inputSchema};
is($schema->{type}, 'object', 'inputSchema is an object schema');
ok($schema->{properties}{petId}, 'the path parameter is a property');
is_deeply($schema->{required}, ['petId'], 'and it is required');

# ---- annotations, from the method alone ------------------------------------

is($get->{annotations}{readOnlyHint}, 1, 'GET is read only');
is($get->{annotations}{idempotentHint}, 1, 'GET is idempotent');
is($get->{annotations}{openWorldHint}, 1, 'every tool is open world: it is a network call');
ok(!$get->{annotations}{destructiveHint}, 'GET is not destructive');

# ---- the frozen list -------------------------------------------------------

my $bytes = $tools->list_bytes;
ok(length $bytes, 'there are frozen bytes');
my $list = decode($bytes);
is(ref $list->{tools}, 'ARRAY', 'they decode to a tools array');
is(scalar @{ $list->{tools} }, 2, 'with both tools in');
ok(exists $list->{tools}[0]{inputSchema}, 'each carrying its inputSchema');

is($tools->list_bytes, $bytes, 'the same bytes every time');
is($tools->builds, 1, 'and reading them rebuilt nothing');

my $twin = Maat::MCP::Tools->new(api => Open::API->new(spec => RegistryStub->portal_spec(1)));
is($twin->list_bytes, $bytes,
   'two objects over the same document produce byte-identical bytes');

# ---- the allow list --------------------------------------------------------

my $one = Maat::MCP::Tools->new(api => $api, mcp => { ops => ['getPet1'] });
is($one->count, 1, 'an allow list selects operations');
ok($one->tool('getpet1'), '...keeping the one named');
ok(!$one->tool('listpets1'), '...and dropping the rest');

my $unknown = Maat::MCP::Tools->new(api => $api, mcp => { ops => ['nosuchop'] });
is($unknown->count, 0, 'an allow list naming nothing yields no tools, not a croak');

# ---- curation through x-mcp ------------------------------------------------

my $curated = Open::API->new(spec => {
    openapi => '3.1.0',
    info    => { title => 'T', version => '1.0.0' },
    paths   => {
        '/a' => { get => {
            operationId => 'alpha',
            summary     => 'the original summary',
            'x-mcp'     => { name => 'find_alpha', title => 'Find an alpha',
                             description => 'a better description' },
            responses   => { 200 => { description => 'ok' } },
        } },
        '/b' => { get => {
            operationId => 'beta',
            'x-mcp'     => { exclude => 1 },
            responses   => { 200 => { description => 'ok' } },
        } },
        '/c' => { post => {
            operationId => 'gamma',
            requestBody => { required => 1, content => { 'application/json' =>
                { schema => { type => 'object',
                              properties => { name => { type => 'string' } },
                              required   => ['name'] } } } },
            responses   => { 200 => { description => 'ok' } },
        } },
    },
});
my $ct = Maat::MCP::Tools->new(api => $curated);

ok($ct->tool('find_alpha'), 'x-mcp renames a tool');
is($ct->tool('find_alpha')->{title}, 'Find an alpha', 'x-mcp sets the title');
like($ct->tool('find_alpha')->{description}, qr/a better description/,
     'x-mcp sets the description');
ok(!$ct->tool('alpha'), 'the derived name is gone once renamed');
ok(!$ct->tool('beta'), 'x-mcp exclude drops an operation entirely');

my $gamma = $ct->tool('gamma');
ok($gamma->{inputSchema}{properties}{body}, 'a JSON body becomes the body property');
ok((grep { $_ eq 'body' } @{ $gamma->{inputSchema}{required} || [] }),
   'a required body is required');
is($gamma->{annotations}{readOnlyHint}, 0, 'POST is not read only');

# ---- names that would collide ----------------------------------------------

# These three differ only in characters a tool name may not hold, so all
# three flatten to "get_user" and the suffixing is what keeps them apart.
# Sorted by operationId (space, then '+', then '.'), so which one takes the
# bare name is fixed rather than whatever order the document decoded in.
my $clash = Open::API->new(spec => {
    openapi => '3.1.0',
    info    => { title => 'T', version => '1.0.0' },
    paths   => {
        '/x' => { get  => { operationId => 'get user',
                            responses => { 200 => { description => 'ok' } } } },
        '/y' => { get  => { operationId => 'get+user',
                            responses => { 200 => { description => 'ok' } } } },
        '/z' => { get  => { operationId => 'get.user',
                            responses => { 200 => { description => 'ok' } } } },
    },
});
my $cl = Maat::MCP::Tools->new(api => $clash);
is($cl->count, 3, 'three operations that all normalise to one name');
is_deeply($cl->names, ['get_user', 'get_user_2', 'get_user_3'],
          'the collision is numbered, and which id takes the bare name is fixed');
is($cl->tool('get_user')->{operationId}, 'get user',
   'the first by operationId keeps the unsuffixed name');

# ---- the compiled validator ------------------------------------------------

my $v = $get->{validator};
ok($v, 'each tool carries a compiled argument validator');
ok($v->is_valid({ petId => 7 }), 'valid arguments validate');
ok(!$v->is_valid({}), 'a missing required argument does not');
ok(!$v->is_valid({ petId => 'not-an-integer' }), 'a wrong type does not');

done_testing;
