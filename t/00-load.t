#!perl
use strict;
use warnings;
use FindBin ();
use lib "$FindBin::Bin/lib";
use MaatTest;
use Test::More;

# Maat is a composition: what it is made of matters as much as what it
# is, so the versions it needs are asserted here rather than discovered
# at the first request.

BEGIN {
    use_ok('Maat')            || print "Bail out!\n";
    use_ok('Maat::Config')    || print "Bail out!\n";
    use_ok('Maat::Violation') || print "Bail out!\n";
    use_ok('Maat::Gateway')   || print "Bail out!\n";
    use_ok('Maat::Shard')     || print "Bail out!\n";     # phase 6: blast radius
    use_ok('Maat::Registry')  || print "Bail out!\n";     # phase 6: the host map
    use_ok('Maat::Poller')    || print "Bail out!\n";     # phase 6: config distribution
    use_ok('Maat::Router')    || print "Bail out!\n";     # phase 6/7: the edge
    use_ok('Maat::Portal')    || print "Bail out!\n";     # phase 10: the docs portal
}

# The pieces the request path is built from, and why each has a floor:
#   Open::API 0.06      - the configure-time prereq fix; anything older
#                         may not have installed at all
#   Reverse::Proxy 0.03 - 0.01 calls Fetch with the wrong arity against
#                         a current Fetch and dies on the first request
ok(Open::API->VERSION >= 0.06, 'Open::API is new enough ('
   . Open::API->VERSION . ')');
ok(Reverse::Proxy->VERSION >= 0.03, 'Reverse::Proxy is new enough ('
   . Reverse::Proxy->VERSION . ')');
ok(Horus->can('uuid_v7'), 'Horus provides uuid_v7');

diag("Testing Maat $Maat::VERSION, Perl $], $^X");
diag("  Open::API " . Open::API->VERSION
   . ", Reverse::Proxy " . Reverse::Proxy->VERSION
   . ", Horus " . Horus->VERSION);

done_testing;
