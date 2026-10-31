package Maat;

use 5.010;
use strict;
use warnings;

our $VERSION = '0.06';

require XSLoader;
XSLoader::load('Maat', $VERSION);

1;

__END__

=head1 NAME

Maat - a spec-enforcing reverse proxy for OpenAPI

=head1 SYNOPSIS

    # apip.yml
    upstream: https://api.internal:8443
    spec:     ./openapi.json
    mode:     observe

    $ apip check apip.yml      # the spec compiles, the upstream answers
    $ apip run   apip.yml

=head1 DESCRIPTION

Put an OpenAPI document in front of an existing API. Every request is
matched against the document and validated against it before it is
forwarded; what the document does not describe is forwarded anyway and
counted. In C<enforce> mode a request that does not conform is answered
with C<application/problem+json> and never reaches the upstream; in
C<observe> mode it is recorded and forwarded untouched.

This distribution is the data plane of L<https://openapi-proxy.com>. It
is a composition rather than an engine: L<Open::API> compiles the
document and validates in C, L<Reverse::Proxy> forwards in C through
L<Fetch>'s ABI, and this code is the policy between them.

=head2 Fail-open

Maat sits in a request path that is not its own. Every call into
validation is wrapped, and a failure inside Maat - a validator that
dies, a spec handle that has gone, a recorder that will not answer -
loses the check, never the request. The C<APIP_CHAOS> environment
variable injects exactly those failures on purpose, so the property is
tested rather than asserted. See L<Maat::Gateway/CHAOS>.

=head1 SEE ALSO

L<Maat::Gateway>, L<Maat::Config>, L<Open::API>, L<Reverse::Proxy>.

The hosted, multi-tenant data plane (phases 6 and 7): L<Maat::Registry>
(the per-worker host to compiled-tenant map, with the atomic publish, the
LRU and the off-path compile budget), L<Maat::Poller> (the signed-bundle
config feed, poll not push), L<Maat::Router> (the edge - host dispatch,
per-tenant isolation, the ACME http-01 responder), and L<Maat::Shard>
(the blast-radius function that keeps free tenants off paid pools).

=head1 AUTHOR

LNATION <email@lnation.org>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by LNATION <email@lnation.org>.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut
