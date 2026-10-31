package RegistryStub;

use 5.010;
use strict;
use warnings;

# A local stand-in for the control plane's /registry feed, producing the
# EXACT bytes MaatSite::Controller::Web::Registry produces: a bundle
# whose ETag hashes { tenants, domains, challenges } canonically (sorted
# keys, "generated" excluded) and whose body is signed with HMAC-SHA256
# under the registry token in X-Maat-Bundle-Signature, plus raw spec
# bytes by digest. This is the contract under test; nothing here requires
# the real site to be running.

use Digest::SHA ();
use File::Raw::JSON ();

sub new {
    my ($class, %o) = @_;
    return bless {
        token      => defined $o{token} ? $o{token} : 'test-registry-token',
        tenants    => [],
        domains    => [],
        challenges => [],
        specs      => {},    # digest -> bytes
        guides     => {},    # proxy id -> { rev, guides => [...] }
    }, $class;
}

sub token { $_[0]{token} }

# Register one tenant from a spec body; returns the tenant hash so a test
# can tweak it. The digest is content-addressed, exactly as the control
# plane derives it.
sub add_tenant {
    my ($self, %t) = @_;
    my $spec = delete $t{spec};
    my $digest;
    if (defined $spec) {
        $digest = Digest::SHA::sha256_hex($spec);
        $self->{specs}{$digest} = $spec;
    }
    my $tenant = {
        host         => $t{host},
        proxy        => $t{proxy},
        account      => $t{account},
        version      => $t{version} // 1,
        digest       => $t{digest} // $digest,
        upstream     => $t{upstream} // '',
        mode         => $t{mode} // ((defined $t{upstream} && length $t{upstream}) ? 'observe' : 'mock'),
        plan         => $t{plan} // 'anon',
        expires      => $t{expires} // 0,
        report_token => $t{report_token},
        limits       => $t{limits} || { requests => 10000, enforce => 0, sampling => 'adaptive' },
        # Phase 9: a tenant's issued API keys ride in the same signed
        # bundle. Present only when the test asked for them, so a keyless
        # tenant carries no `keys` field at all and the gateway forwards
        # exactly as phase 1 (gate 4).
        (defined $t{keys} ? (keys => $t{keys}) : ()),
        # Phase 8: named environments, each pointing at a version. Absent
        # unless the test asked for them, so a tenant with none is byte
        # for byte the phase-6 shape.
        (defined $t{environments} ? (environments => $t{environments}) : ()),
        # Phase 10: the optional portal object. `badges` is the
        # per-environment reality-badge opt-in (default 0), `guides_rev`
        # moves when the proxy's prose guides change (empty when there are
        # none). Absent unless the test asked for it, so a tenant with no
        # portal object is byte for byte the earlier shape.
        (defined $t{portal} ? (portal => $t{portal}) : ()),
        # The MCP endpoint's per-tenant settings: `enabled`, and `ops` to
        # offer only some operations as tools. Absent unless the test asked,
        # so a tenant without it is byte for byte the earlier shape and the
        # dispatcher's /mcp branch never arms.
        (defined $t{mcp} ? (mcp => $t{mcp}) : ()),
        # The plan's response sampling, already resolved by the control
        # plane into the gateway's vocabulary ('adaptive', 'all', or a
        # divisor). Absent unless the test asked, so an unaware tenant is
        # the earlier shape and Config->tenant leaves the default alone.
        (defined $t{sampling} ? (sampling => $t{sampling}) : ()),
    };
    push @{ $self->{tenants} }, $tenant;
    return $tenant;
}

# Register a proxy's prose guides under a revision. Returns the sha256hex
# revision the tenant's portal.guides_rev points with, exactly as the
# control plane derives it from the guides' content.
sub add_guides {
    my ($self, %o) = @_;
    my $proxy  = $o{proxy};
    my $guides = $o{guides} || [];
    my $canon  = File::Raw::JSON::file_json_encode($guides, sort_keys => 1);
    my $rev    = defined $o{rev} ? $o{rev} : Digest::SHA::sha256_hex($canon);
    $self->{guides}{$proxy} = { rev => $rev, guides => $guides };
    return $rev;
}

# A { rev, guides } payload for GET /registry/guides/<proxy>, or undef
# when the proxy has none.
sub guides_for { $_[0]{guides}{ $_[1] } }

# Register a spec body under its own digest and hand back the
# { version, digest } pair an environment points with.
sub add_version {
    my ($self, %o) = @_;
    my $digest = Digest::SHA::sha256_hex($o{spec});
    $self->{specs}{$digest} = $o{spec};
    return { version => $o{version} // 2, digest => $digest };
}

# One key record as the control plane puts it in the bundle: the secret's
# sha256 hex (never the secret), plus its environment, per-minute rate
# (0 = unlimited), scopes and display prefix. A revoked key is simply
# absent from a tenant's `keys` array on the next poll.
sub make_key {
    my ($class, %o) = @_;
    my $secret = defined $o{secret} ? $o{secret} : 'secret-key';
    return {
        id           => defined $o{id} ? $o{id} : 1,
        hash         => Digest::SHA::sha256_hex($secret),
        environment  => defined $o{environment} ? $o{environment} : 'production',
        rate_per_min => defined $o{rate_per_min} ? $o{rate_per_min} : 0,
        scopes       => $o{scopes} || [],
        prefix       => substr($secret, 0, 8),
    };
}

sub add_spec {
    my ($self, $bytes) = @_;
    my $digest = Digest::SHA::sha256_hex($bytes);
    $self->{specs}{$digest} = $bytes;
    return $digest;
}

sub set_tenants    { $_[0]{tenants}    = $_[1]; return }
sub set_domains    { $_[0]{domains}    = $_[1]; return }
sub set_challenges { $_[0]{challenges} = $_[1]; return }

sub add_domain {
    my ($self, %d) = @_;
    push @{ $self->{domains} }, {
        host    => $d{host},
        proxy   => $d{proxy},
        tls_crt => $d{tls_crt},
        tls_key => $d{tls_key},
        expires => $d{expires} // 0,
    };
    return;
}

sub add_challenge {
    my ($self, $token, $auth) = @_;
    push @{ $self->{challenges} }, { token => $token, auth => $auth };
    return;
}

sub clear_tenants    { $_[0]{tenants}    = []; return }
sub clear_domains    { $_[0]{domains}    = []; return }
sub clear_challenges { $_[0]{challenges} = []; return }

# The canonical content and its ETag, exactly the control plane's rule:
# tenants sorted by proxy, domains and challenges sorted, "generated"
# excluded from the hash.
sub _canon {
    my ($self) = @_;
    my @tenants = sort { ($a->{proxy}//0) <=> ($b->{proxy}//0) } @{ $self->{tenants} };
    my @domains = sort { $a->{host} cmp $b->{host} } @{ $self->{domains} };
    my @chal    = sort { $a->{token} cmp $b->{token} } @{ $self->{challenges} };
    my %content = (tenants => \@tenants, domains => \@domains, challenges => \@chal);
    my $canon = File::Raw::JSON::file_json_encode(\%content, sort_keys => 1);
    return (\%content, Digest::SHA::sha256_hex($canon));
}

sub etag { my ($c, $etag) = $_[0]->_canon; return $etag }

# A { status, headers => \%lc, body } response to GET /registry/bundle,
# honouring If-None-Match exactly as the poller sends it back.
sub bundle_response {
    my ($self, $inm) = @_;
    my ($content, $etag) = $self->_canon;

    if (defined $inm) {
        $inm =~ s/\A"|"\z//g;
        return { status => 304, headers => { etag => qq{"$etag"} }, body => '' }
            if $inm eq $etag;
    }

    my $body = File::Raw::JSON::file_json_encode(
        { generated => time, %$content }, sort_keys => 1);
    my $sig = Digest::SHA::hmac_sha256_hex($body, $self->{token});
    return {
        status  => 200,
        headers => {
            'content-type'            => 'application/json',
            'etag'                    => qq{"$etag"},
            'x-maat-bundle-signature' => $sig,
        },
        body => $body,
    };
}

# Raw spec bytes by digest, X-Maat-Digest header, exactly the control
# plane's spec endpoint.
sub spec_response {
    my ($self, $digest) = @_;
    my $bytes = $self->{specs}{$digest};
    return { status => 404, headers => {}, body => '' } unless defined $bytes;
    return {
        status  => 200,
        headers => { 'x-maat-digest' => $digest,
                     'content-type'  => 'application/octet-stream' },
        body    => $bytes,
    };
}

# The /registry/guides/<proxy> response, exactly the control plane's shape:
# 200 application/json { rev, guides } when the proxy has guides, 404
# otherwise.
sub guides_response {
    my ($self, $proxy) = @_;
    my $g = $self->{guides}{$proxy};
    return { status => 404, headers => {}, body => '' } unless $g;
    my $body = File::Raw::JSON::file_json_encode(
        { rev => $g->{rev}, guides => $g->{guides} }, sort_keys => 1);
    return {
        status  => 200,
        headers => { 'content-type' => 'application/json' },
        body    => $body,
    };
}

# A fetcher coderef for Maat::Poller: routes /registry/bundle,
# /registry/spec/<digest> and /registry/guides/<proxy> against this stub,
# checking the bearer token the way the control plane does.
sub fetcher {
    my ($self) = @_;
    return sub {
        my ($url, $etag) = @_;
        # (The stub trusts its own caller for the token; the poller always
        # sends it. A test that wants a 401 can build its own fetcher.)
        if ($url =~ m{/registry/spec/([0-9a-f]{64})}) {
            return $self->spec_response($1);
        }
        if ($url =~ m{/registry/guides/(\d+)}) {
            return $self->guides_response($1);
        }
        return $self->bundle_response($etag);
    };
}

# A fetch_guides coderef for Maat::Registry: proxy id -> { rev, guides }
# (or undef when the proxy has none), mirroring spec_fetcher.
sub guides_fetcher {
    my ($self) = @_;
    return sub {
        my ($proxy) = @_;
        return $self->{guides}{$proxy};
    };
}

# A fetch_spec coderef for Maat::Registry: digest -> raw bytes (or die).
sub spec_fetcher {
    my ($self) = @_;
    return sub {
        my ($digest) = @_;
        my $bytes = $self->{specs}{$digest};
        die "RegistryStub: no spec for digest $digest\n" unless defined $bytes;
        return $bytes;
    };
}

# ---- spec generators -------------------------------------------------------

# A tiny, valid, DISTINCT OpenAPI 3.1 document per tenant: a unique
# operationId and a response the mock can synthesize, so 1000 tenants are
# 1000 different compiled specs rather than one shared object.
sub tenant_spec {
    my ($class, $n) = @_;
    return <<"JSON";
{
  "openapi": "3.1.0",
  "info": { "title": "Tenant $n", "version": "1.0.0" },
  "paths": {
    "/hello": {
      "get": {
        "operationId": "hello$n",
        "responses": {
          "200": {
            "description": "greeting from tenant $n",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["tenant"],
                  "properties": {
                    "tenant": { "type": "integer", "const": $n },
                    "name":   { "type": "string", "default": "tenant-$n" }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
JSON
}

# A spec that declares an apiKey security scheme (X-API-Key header) and
# guards one operation with it, alongside an unsecured one - so a test can
# prove the secured op needs a key while the public op is untouched. The
# operations are distinct per $n, and both synthesize in mock mode.
sub secured_spec {
    my ($class, $n) = @_;
    $n = 1 unless defined $n;
    return <<"JSON";
{
  "openapi": "3.1.0",
  "info": { "title": "Secured $n", "version": "1.0.0" },
  "components": {
    "securitySchemes": {
      "ApiKey": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
    }
  },
  "paths": {
    "/secure": {
      "get": {
        "operationId": "secure$n",
        "security": [ { "ApiKey": [] } ],
        "responses": {
          "200": {
            "description": "guarded greeting",
            "content": { "application/json": { "schema": {
              "type": "object", "required": ["ok"],
              "properties": { "ok": { "type": "boolean", "default": true } }
            } } }
          }
        }
      }
    },
    "/public": {
      "get": {
        "operationId": "public$n",
        "responses": {
          "200": {
            "description": "open greeting",
            "content": { "application/json": { "schema": {
              "type": "object", "required": ["ok"],
              "properties": { "ok": { "type": "boolean", "default": true } }
            } } }
          }
        }
      }
    }
  }
}
JSON
}

# A spec with a description, a path parameter and two operations - enough
# to exercise the portal: the reference, per-operation client snippets
# with a filled path template, and search over prose + operations.
sub portal_spec {
    my ($class, $n) = @_;
    $n = 1 unless defined $n;
    return <<"JSON";
{
  "openapi": "3.1.0",
  "info": {
    "title": "Pets $n",
    "version": "3.2.1",
    "description": "The **Pets** API for tenant $n. Manage a herd of pets."
  },
  "paths": {
    "/pets": {
      "get": {
        "operationId": "listPets$n",
        "summary": "List all pets",
        "responses": {
          "200": {
            "description": "a list of pets",
            "content": { "application/json": { "schema": {
              "type": "object", "required": ["pets"],
              "properties": { "pets": { "type": "array",
                "items": { "type": "object", "required": ["id"],
                  "properties": { "id": { "type": "integer" } } } } }
            } } }
          }
        }
      }
    },
    "/pets/{petId}": {
      "get": {
        "operationId": "getPet$n",
        "summary": "Fetch one pet by id",
        "parameters": [
          { "name": "petId", "in": "path", "required": true,
            "schema": { "type": "integer" } }
        ],
        "responses": {
          "200": {
            "description": "one pet",
            "content": { "application/json": { "schema": {
              "type": "object", "required": ["id", "name"],
              "properties": {
                "id":   { "type": "integer" },
                "name": { "type": "string", "default": "Rex" }
              }
            } } }
          }
        }
      }
    }
  }
}
JSON
}

# A spec that is pathological to COMPILE: a very deep chain of $refs. Deep
# enough to blow a compile budget, small enough on disk to slip the size
# cap - the "deep \$ref chains" the plan names, the case a size cap alone
# would miss.
sub deep_ref_spec {
    my ($class, $depth) = @_;
    $depth ||= 4000;
    my %defs;
    for my $i (0 .. $depth) {
        $defs{"S$i"} = $i == $depth
            ? { type => 'object' }
            : { '$ref' => "#/components/schemas/S@{[ $i + 1 ]}" };
    }
    my $doc = {
        openapi => '3.1.0',
        info    => { title => 'Deep', version => '1.0.0' },
        paths   => {
            '/x' => {
                get => {
                    operationId => 'deep',
                    responses   => {
                        '200' => {
                            description => 'deep',
                            content => { 'application/json' =>
                                { schema => { '$ref' => '#/components/schemas/S0' } } },
                        },
                    },
                },
            },
        },
        components => { schemas => \%defs },
    };
    return File::Raw::JSON::file_json_encode($doc);
}

# A spec that trips the SIZE cap: a valid document padded past
# max_spec_bytes with a large description, the "ten megabytes of schemas"
# case.
sub oversized_spec {
    my ($class, $bytes) = @_;
    $bytes ||= 6 * 1024 * 1024;
    my $pad = 'x' x $bytes;
    return <<"JSON";
{
  "openapi": "3.1.0",
  "info": { "title": "Big", "version": "1.0.0", "description": "$pad" },
  "paths": {
    "/x": { "get": { "operationId": "big",
      "responses": { "200": { "description": "ok",
        "content": { "application/json": { "schema": { "type": "object" } } } } } } }
  }
}
JSON
}

1;
