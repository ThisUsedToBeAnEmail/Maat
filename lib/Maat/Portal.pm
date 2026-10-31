package Maat::Portal;

use 5.010;
use strict;
use warnings;
use Carp ();
use File::Raw::JSON ();

our $VERSION = '0.06';

# The docs portal (phase 10), on the gateway itself.
#
# The whole point of this phase is that the documentation and the runtime
# cannot disagree: the portal is rendered from the SAME compiled Open::API
# object the gateway is enforcing, so the contract that is documented is
# the contract that is checked, byte for byte. There is one artifact.
#
# Four properties this file exists to hold:
#
#   FROZEN, NOT RENDERED PER REQUEST. Every page is rendered ONCE, here,
#   at construction - which happens off the request path, in
#   Maat::Registry's compile step, the same place and budget the spec
#   itself is compiled under. A request into /docs is then a hash lookup
#   into pre-rendered bytes, not a template run. The generated reference
#   (Open::API::UI), the prose guides (Markdown::Simple), the per-operation
#   client snippets and the search index are all built at boot. `renders`
#   counts the render work, and it does not move on a request (gate 2).
#
#   THE VERSION AND ITS HASH ON EVERY PAGE. Every page carries the spec
#   version and the content digest the gateway is serving - the exact pair
#   Maat::Registry holds and the router stamps on X-Maat-Version - so a
#   reader can always tell which contract they are reading, and the docs
#   and the enforced spec move together (gate 1).
#
#   THE REALITY BADGE. Per operation, a badge from THIS gateway's own
#   local drift aggregates (Maat::Violation->drift). An operation whose
#   responses have been violating their schema says so, to its own
#   readers - the differentiator, and gated by the tenant's own opt-in
#   (`badges`): off, no badge is ever rendered. Because the same
#   aggregates are shipped to the control plane, the badge reconciles with
#   the control plane's drift view by construction (gate 3).
#
#   OFF THE REQUEST PATH. The portal is only ever entered for a /docs
#   path; an API request never touches it. When the gateway switch is off
#   the portal is not built at all and there is no /docs route (gate 4) -
#   that decision lives in Maat::Config/Maat::Registry, not here.

sub new {
    my ($class, %o) = @_;
    my $api = $o{api}
        or Carp::croak('Maat::Portal: api (a compiled Open::API) is required');

    my $base = defined $o{base} ? $o{base} : '/docs';
    $base =~ s{/\z}{} if length $base > 1;
    Carp::croak("Maat::Portal: base must start with '/'")
        unless $base =~ m{\A/};

    my $self = bless {
        api      => $api,
        base     => $base,
        host     => $o{host},
        version  => (defined $o{version} ? $o{version} : _spec_version($api)),
        digest   => (defined $o{digest}  ? $o{digest}  : ''),
        title    => $o{title},

        # The tenant's opt-in for the reality badge. Off (0) is the default
        # and the safe reading: some customers will not want their drift
        # public, so no badge is rendered and the reality endpoint reports
        # nothing until they opt in.
        badges   => $o{badges} ? 1 : 0,

        # The live drift source for the badge. A Maat::Violation (the
        # gateway's own), read but never written; undef when the portal is
        # standalone, in which case the badge falls back to whatever was
        # true at build (usually clear).
        violation => $o{violation},

        guides   => (ref $o{guides} eq 'ARRAY' ? $o{guides} : []),

        pages    => {},   # exact PATH_INFO -> a frozen PSGI triplet
        renders  => 0,    # render work done; must not move on a request
    }, $class;

    $self->_build;
    return $self;
}

sub base      { $_[0]{base} }
sub version   { $_[0]{version} }
sub digest    { $_[0]{digest} }
sub badges    { $_[0]{badges} }
sub renders   { $_[0]{renders} }

# The digest, short, for a banner - enough to tell two contracts apart.
sub short_digest {
    my ($self) = @_;
    my $d = $self->{digest};
    return (defined $d && length $d) ? substr($d, 0, 12) : '';
}

# ---- the request surface ---------------------------------------------------

# Is this a path the portal owns? The router/gateway asks before entering
# the portal, so an API request is never even offered to it. A prefix test
# and nothing more.
sub handles {
    my ($self, $path) = @_;
    return 0 unless defined $path;
    my $b = $self->{base};
    return 1 if $path eq $b;
    return 1 if index($path, "$b/") == 0;
    return 0;
}

# Serve a /docs request. A static page is a hash lookup into the frozen
# table; only the two data endpoints (search and reality) do any work per
# request, and neither is on the API path. Returns a PSGI triplet.
sub serve {
    my ($self, $env) = @_;
    my $path = defined $env->{PATH_INFO} ? $env->{PATH_INFO} : '';
    my $b    = $self->{base};

    my $method = $env->{REQUEST_METHOD} || 'GET';
    return _text(405, 'Method Not Allowed')
        unless $method eq 'GET' || $method eq 'HEAD';

    # The live data endpoints, before the frozen table: a trigram query and
    # the reality badge state. Both are cheap, and both are /docs paths, so
    # neither adds a thing to a validated API request.
    if ($path eq "$b/search") {
        return $self->_search_response($env);
    }
    if ($path eq "$b/reality.json") {
        return $self->_reality_response;
    }

    # A per-operation page carries a live badge when the tenant opted in:
    # the frozen page holds a placeholder, and here it becomes the current
    # drift state with a single substitution (never a re-render).
    if (my $op = $self->{op_path}{$path}) {
        return $self->_op_response($op);
    }

    if (my $trip = $self->{pages}{$path}) {
        return _maybe_head($method, $trip);
    }

    # A /docs path we do not serve is a 404 within the portal - it never
    # falls through to the tenant's API.
    return _text(404, 'Not Found');
}

# The whole thing as a PSGI wrapper around an inner app (the gateway). A
# /docs request is served here; everything else falls straight through to
# the inner app untouched - one prefix test in front of the C request
# path, and nothing more.
sub wrap {
    my ($self, $inner) = @_;
    my $b = $self->{base};
    return sub {
        my ($env) = @_;
        my $path = defined $env->{PATH_INFO} ? $env->{PATH_INFO} : '';
        if ($path eq $b || index($path, "$b/") == 0) {
            return $self->serve($env);
        }
        return $inner->($env);
    };
}

# ---- the reality view ------------------------------------------------------

# The badge state, per operation, from the live drift aggregates. Gated by
# the tenant's opt-in: with badges off this is always empty, whatever the
# drift, so no reality is ever exposed for a tenant that did not ask for
# it. With badges on it is exactly what Maat::Violation->drift holds,
# projected to the operations this spec declares - so the badge equals the
# aggregate by construction (gate 3), and the aggregate is what is shipped
# to the control plane (gate 3, the reconciliation half).
sub reality {
    my ($self, $violation) = @_;
    return {} unless $self->{badges};
    $violation = $self->{violation} unless defined $violation;
    my $drift = ($violation && $violation->can('drift')) ? $violation->drift : {};

    my %out;
    for my $op (@{ $self->{op_ids} }) {
        my $d = $drift->{$op};
        $out{$op} = $d
            ? { drift => 1,
                count        => $d->{count},
                sample_count => $d->{sample_count},
                last_seen    => $d->{last_seen},
                statuses     => [ sort keys %{ $d->{statuses} || {} } ] }
            : { drift => 0 };
    }
    return \%out;
}

sub _reality_response {
    my ($self) = @_;
    my $body = _bytes(File::Raw::JSON::file_json_encode({
        version => $self->{version},
        digest  => $self->{digest},
        badges  => $self->{badges},
        reality => $self->reality,
    }));
    return [ 200,
             [ 'Content-Type'   => 'application/json',
               'Content-Length' => length $body,
               'Cache-Control'  => 'no-store' ],
             [ $body ] ];
}

# ---- search ----------------------------------------------------------------

sub _search_response {
    my ($self, $env) = @_;
    my $q = _query_param($env->{QUERY_STRING}, 'q');
    my @results;
    if (defined $q && length $q && $self->{search}) {
        my $hits = eval { $self->{search}->search($q, 10) } || [];
        for my $h (@$hits) {
            my $doc = $self->{search_docs}[ $h->{doc_id} ] or next;
            push @results, {
                title => $doc->{title},
                url   => $doc->{url},
                kind  => $doc->{kind},
                score => $h->{score} + 0,
            };
        }
    }
    my $body = _bytes(File::Raw::JSON::file_json_encode({
        query   => (defined $q ? $q : ''),
        version => $self->{version},
        results => \@results,
    }));
    return [ 200,
             [ 'Content-Type'   => 'application/json',
               'Content-Length' => length $body,
               'Cache-Control'  => 'no-store' ],
             [ $body ] ];
}

# ---- the build (all render work is here, off the request path) ------------

sub _build {
    my ($self) = @_;

    require Open::API::UI;
    require Search::Trigram;

    my $api = $self->{api};
    $self->{op_ids}   = [ map { $_->{operationId} } @{ $api->operations } ];
    $self->{op_path}  = {};   # /docs/op/<id> -> operationId

    # The search index and its doc table are built here, once, from the
    # same content the pages are built from (gate: "built at boot").
    $self->{search}      = Search::Trigram->new;
    $self->{search_docs} = [];

    $self->_build_reference;   # Open::API::UI, rebased under /docs/reference
    $self->_build_guides;      # the fetched prose, through Markdown::Simple
    $self->_build_operations;  # per-op pages: snippets + the reality badge
    $self->_build_index;       # the landing page
    $self->_build_version_json;

    return;
}

# The generated reference. Open::API::UI renders eagerly in its
# constructor (one render), and its routes hand back the frozen bytes for
# the page, its stylesheet, its script and the raw document. We rebase
# them all under /docs/reference and inject the version banner into the
# HTML page.
sub _build_reference {
    my ($self) = @_;
    my $b = $self->{base};

    my $ui = Open::API::UI->new(
        api       => $self->{api},
        path      => "$b/reference",
        spec_path => "$b/openapi.json",
        try_it    => 0,     # a docs page is not a live-call console here
        title     => ($self->{title} // undef),
    );
    $self->{renders}++;     # the one eager UI render

    for my $r (@{ $ui->routes }) {
        # Open::API::UI hands back a ready PSGI triplet per route: freeze it
        # as-is (it is already the exact bytes), injecting the version
        # banner into the HTML page(s) only. Assets and the raw document
        # are stored untouched.
        my $trip = $r->{response}->();
        my $ct = _content_type($trip);
        if ($ct =~ m{text/html}) {
            $trip = _inject_banner($trip, $self->_banner_html);
        } else {
            $trip = _normalize_trip($trip);
        }
        $self->{pages}{ $r->{path} } = $trip;
    }
    $self->{reference_url} = "$b/reference";
    return;
}

# The prose guides: a directory of markdown that versions with the API.
# Each guide is rendered once, through Markdown::Simple, into a frozen
# page under /docs/guides/<slug>, and indexed for search. A guide with no
# slug is skipped rather than colliding on the empty path.
sub _build_guides {
    my ($self) = @_;
    my $base = $self->{base};

    require Markdown::Simple;
    my $md = Markdown::Simple->new;

    my @guides = sort { ($a->{order} // 0) <=> ($b->{order} // 0)
                     || ($a->{title} // '') cmp ($b->{title} // '') }
                 grep { ref $_ eq 'HASH' && defined $_->{slug} && length $_->{slug} }
                 @{ $self->{guides} };
    $self->{guide_list} = [];

    for my $g (@guides) {
        my $slug  = _safe_slug($g->{slug});
        my $title = defined $g->{title} && length $g->{title} ? $g->{title} : $slug;
        my $html_body = eval { $md->render(defined $g->{body} ? $g->{body} : '') };
        $html_body = _escape(defined $g->{body} ? $g->{body} : '')
            unless defined $html_body;
        $self->{renders}++;

        my $url  = "$base/guides/$slug";
        my $page = $self->_page($title, $url,
            qq{<article class="maat-guide"><h1>} . _escape($title) . qq{</h1>\n}
          . $html_body
          . qq{</article>});
        $self->{pages}{$url} = _freeze($page);
        push @{ $self->{guide_list} }, { slug => $slug, title => $title, url => $url };

        # search: the guide's prose, plain text
        $self->_index_doc($title, $url, 'guide',
            "$title " . _plain(defined $g->{body} ? $g->{body} : ''));
    }

    # The guides index page.
    my $list = @{ $self->{guide_list} }
        ? '<ul class="maat-list">'
          . join('', map {
                qq{<li><a href="} . _escape($_->{url}) . qq{">}
              . _escape($_->{title}) . qq{</a></li>}
            } @{ $self->{guide_list} })
          . '</ul>'
        : '<p class="maat-empty">No guides have been published for this API yet.</p>';
    my $gi = "$base/guides";
    $self->{pages}{$gi} = _freeze(
        $self->_page('Guides', $gi, "<h1>Guides</h1>\n$list"));
    return;
}

# Per-operation pages: the client snippets (curl and Open::API::Client),
# and - when the tenant opted in - the reality badge as a placeholder the
# serve path fills with the live drift state.
sub _build_operations {
    my ($self) = @_;
    my $b   = $self->{base};
    my $api = $self->{api};

    $self->{op_list} = [];
    for my $op (@{ $api->operations }) {
        my $id     = $op->{operationId};
        next unless defined $id && length $id;
        my $info   = eval { $api->operation_info($id) } || $op;
        my $method = uc($info->{method} // $op->{method} // 'GET');
        my $opath  = $info->{path} // $op->{path} // '/';
        my $url    = "$b/op/" . _safe_slug($id);

        my $snips = $self->_snippets($id, $info, $method, $opath);

        my $badge = '';
        if ($self->{badges}) {
            # A placeholder the serve path replaces with the live state -
            # never a re-render, a single substitution. Off (badges 0)
            # there is no placeholder and no badge at all.
            $badge = "<!--MAAT_REALITY:$id-->";
        }

        my $params = _params_html($info);
        my $body = qq{<article class="maat-op">\n}
          . qq{<h1><span class="maat-method">$method</span> }
          . _escape($opath) . qq{</h1>\n}
          . qq{<p class="maat-opid">operationId: <code>} . _escape($id)
          . qq{</code></p>\n}
          . $badge
          . (length $params ? "<h2>Parameters</h2>\n$params\n" : '')
          . qq{<h2>curl</h2>\n} . $snips->{curl}
          . qq{<h2>Perl (Open::API::Client)</h2>\n} . $snips->{perl}
          . qq{<p><a href="} . _escape($self->{reference_url} // "$b/reference")
          . qq{">Full reference</a></p>\n}
          . qq{</article>};

        $self->{renders}++;
        my $page = $self->_page("$method $opath", $url, $body);
        $self->{pages}{$url}   = _freeze($page);
        $self->{op_path}{$url} = $id;
        push @{ $self->{op_list} }, { id => $id, method => $method,
                                      path => $opath, url => $url };

        $self->_index_doc("$method $opath", $url, 'operation',
            "$method $opath $id " . ($info->{summary} // ''));
    }
    return;
}

# The landing page: the API's identity, the version/hash, and links into
# the reference, the guides and each operation (with a badge marker when
# opted in). The badge markers here are filled live on serve too.
sub _build_index {
    my ($self) = @_;
    my $b    = $self->{base};
    my $spec = $self->{api}->spec;
    my $info = (ref $spec eq 'HASH' ? $spec->{info} : {}) || {};
    my $title = $self->{title} // $info->{title} // 'API';

    my $desc = '';
    if (defined $info->{description} && length $info->{description}) {
        require Markdown::Simple;
        $desc = eval { Markdown::Simple->new->render($info->{description}) }
             // _escape($info->{description});
        $self->{renders}++;
    }

    my $ops = @{ $self->{op_list} || [] }
        ? '<ul class="maat-list">'
          . join('', map {
                qq{<li><a href="} . _escape($_->{url}) . qq{">}
              . qq{<span class="maat-method">$_->{method}</span> }
              . _escape($_->{path}) . qq{</a></li>}
            } @{ $self->{op_list} })
          . '</ul>'
        : '';

    my $body = qq{<h1>} . _escape($title) . qq{</h1>\n}
      . ($desc ? qq{<div class="maat-desc">$desc</div>\n} : '')
      . qq{<h2>Operations</h2>\n$ops\n};

    # The index is itself the top of the reference/guides/search, so this
    # is the landing page the /docs base resolves to.
    my $page = $self->_page($title, $b, $body);
    my $frozen = _freeze($page);
    $self->{pages}{$b}       = $frozen;
    $self->{pages}{"$b/"}    = $frozen;

    $self->_index_doc($title, $b, 'overview', "$title " . _plain($info->{description} // ''));
    return;
}

sub _build_version_json {
    my ($self) = @_;
    my $b = $self->{base};
    my $body = _bytes(File::Raw::JSON::file_json_encode({
        version => $self->{version},
        digest  => $self->{digest},
    }));
    $self->{pages}{"$b/version.json"} = [ 200,
        [ 'Content-Type'   => 'application/json',
          'Content-Length' => length $body ],
        [ $body ] ];
    return;
}

# ---- client snippets -------------------------------------------------------

# curl and the Perl client, generated from the compiled operation. The
# curl is syntax-highlighted through Eshu; the Perl is HTML-escaped (Eshu
# has no Perl highlighter, and an un-highlighted-but-correct snippet beats
# a wrong one).
sub _snippets {
    my ($self, $id, $info, $method, $path) = @_;

    my $host = defined $self->{host} && length $self->{host}
             ? $self->{host} : 'your-proxy.openapi-proxy.com';
    my $url_path = _fill_path($path, $info);

    my @query;
    for my $p (@{ $info->{parameters} || [] }) {
        next unless ($p->{in} // '') eq 'query' && $p->{required};
        push @query, _escape_uri($p->{name}) . '=' . _escape_uri(_sample_param($p));
    }
    my $qs  = @query ? '?' . join('&', @query) : '';
    my $has_body = ($info->{body_required} || (ref $info->{body} eq 'ARRAY' && @{ $info->{body} }))
                 ? 1 : 0;

    my $curl = "curl -s -X $method 'https://$host$url_path$qs'";
    $curl .= " \\\n  -H 'Accept: application/json'";
    if ($has_body) {
        $curl .= " \\\n  -H 'Content-Type: application/json'";
        $curl .= " \\\n  --data '{ }'";
    }

    my @args;
    for my $p (@{ $info->{parameters} || [] }) {
        next unless $p->{required};
        push @args, _perl_str($p->{name}) . ' => ' . _perl_val(_sample_param($p));
    }
    my $arglist = @args ? ', ' . join(', ', @args) : '';
    my $perl = <<"PERL";
use Open::API::Client;

my \$client = Open::API::Client->new(
    spec     => 'openapi.json',
    base_url => 'https://$host',
);

my \$res = \$client->call('$id'$arglist)->get;
# \$res->{status}, \$res->{data}
PERL

    return {
        curl => _code_block(_highlight_bash($curl), 'bash'),
        perl => _code_block(_escape($perl), 'perl'),
    };
}

sub _highlight_bash {
    my ($src) = @_;
    my $out = eval { require Eshu; Eshu->highlight_bash($src) };
    return defined $out ? $out : _escape($src);
}

sub _code_block {
    my ($inner, $lang) = @_;
    return qq{<pre class="maat-code" data-lang="$lang"><code>$inner</code></pre>\n};
}

# Fill a templated path (/pets/{petId}) with sample values so the snippet
# is copy-pasteable, matching parameter names to their declared schema.
sub _fill_path {
    my ($path, $info) = @_;
    my %by_name = map { ($_->{name} // '') => $_ }
                  grep { ($_->{in} // '') eq 'path' }
                  @{ $info->{parameters} || [] };
    $path =~ s/\{([^}]+)\}/ _escape_uri(_sample_param($by_name{$1} || { name => $1 })) /ge;
    return $path;
}

# A deterministic sample value for a parameter, from its schema when it
# has one and its name when it does not - never random, so a snippet is
# byte-identical across processes.
sub _sample_param {
    my ($p) = @_;
    my $schema = ref $p->{schema} eq 'HASH' ? $p->{schema} : {};
    my $type = $schema->{type};
    $type = $type->[0] if ref $type eq 'ARRAY' && @$type;
    if (ref $schema->{enum} eq 'ARRAY' && @{ $schema->{enum} }) {
        return $schema->{enum}[0];
    }
    return $schema->{const} if exists $schema->{const} && !ref $schema->{const};
    if (defined $type) {
        return 1     if $type eq 'integer' || $type eq 'number';
        return 'true' if $type eq 'boolean';
    }
    my $name = defined $p->{name} ? $p->{name} : 'value';
    return 123 if $name =~ /(?:\A|_)id\z/i || $name =~ /id\z/i;
    return 'example';
}

sub _params_html {
    my ($info) = @_;
    my @rows;
    for my $p (sort { ($a->{in} // '') cmp ($b->{in} // '')
                   || ($a->{name} // '') cmp ($b->{name} // '') }
               @{ $info->{parameters} || [] }) {
        push @rows, '<tr><td>' . _escape($p->{in} // '')
          . '</td><td><code>' . _escape($p->{name} // '') . '</code></td><td>'
          . ($p->{required} ? 'required' : 'optional') . '</td></tr>';
    }
    return '' unless @rows;
    return '<table class="maat-params"><thead><tr><th>in</th><th>name</th>'
         . '<th></th></tr></thead><tbody>' . join('', @rows)
         . '</tbody></table>';
}

# ---- per-op serve (the live badge) ----------------------------------------

sub _op_response {
    my ($self, $op) = @_;
    my $trip = $self->{pages}{ "$self->{base}/op/" . _safe_slug($op) }
        or return _text(404, 'Not Found');

    # No opt-in, no placeholder, nothing to do: the frozen page is served
    # as-is (a hash lookup).
    return $trip unless $self->{badges};

    # Fill the placeholder with the current drift state. This is a string
    # substitution on a copy, never a template re-render, and it only ever
    # runs for a /docs/op request.
    my $marker = "<!--MAAT_REALITY:$op-->";
    my $body   = $trip->[2][0];
    return $trip if index($body, $marker) < 0;

    my $r = $self->reality->{$op} || { drift => 0 };
    my $badge = $r->{drift}
        ? qq{<div class="maat-badge maat-badge-drift" role="status">}
          . qq{&#9888; Reality: this operation's responses have drifted from }
          . qq{their schema (}
          . _escape($r->{count} // 0) . qq{ occurrence(s) in }
          . _escape($r->{sample_count} // 0) . qq{ response(s))</div>}
        : qq{<div class="maat-badge maat-badge-ok" role="status">}
          . qq{&#10003; Reality: responses conform to the schema</div>};

    (my $filled = $body) =~ s/\Q$marker\E/$badge/;
    my $bytes = _bytes($filled);
    my @headers = @{ $trip->[1] };
    for (my $i = 0; $i < @headers; $i += 2) {
        $headers[$i + 1] = length $bytes if lc $headers[$i] eq 'content-length';
    }
    return [ $trip->[0], \@headers, [ $bytes ] ];
}

# ---- page shell + banner ---------------------------------------------------

# The version and content-hash banner that rides on every page. The digest
# is what Maat::Registry holds and the router stamps on X-Maat-Version's
# sibling - so a reader always knows which contract they are reading, and
# the docs and the enforced spec are provably the same version (gate 1).
sub _banner_html {
    my ($self) = @_;
    my $v = defined $self->{version} ? $self->{version} : '';
    my $d = $self->short_digest;
    return qq{<div class="maat-version" data-version="} . _escape($v)
         . qq{" data-digest="} . _escape($self->{digest} // '') . qq{">}
         . qq{contract version <strong>} . _escape($v) . qq{</strong>}
         . (length $d ? qq{ &middot; <code>} . _escape($d) . qq{</code>} : '')
         . qq{</div>};
}

sub _nav_html {
    my ($self) = @_;
    my $b = $self->{base};
    return qq{<nav class="maat-nav">}
         . qq{<a href="} . _escape($b) . qq{">Overview</a>}
         . qq{<a href="} . _escape("$b/reference") . qq{">Reference</a>}
         . qq{<a href="} . _escape("$b/guides") . qq{">Guides</a>}
         . qq{<form class="maat-search" method="get" action="}
         . _escape("$b/search") . qq{">}
         . qq{<input type="search" name="q" placeholder="Search" aria-label="Search"></form>}
         . qq{</nav>};
}

# Wrap body HTML in the page shell: no external anything, no scripts, a
# small inline stylesheet permitted by a tight CSP. The banner is in the
# shell, so it is on every page this method builds.
sub _page {
    my ($self, $title, $url, $body_html) = @_;
    my $t = _escape(defined $title ? $title : 'API');
    return {
        html => "<!doctype html>\n"
          . qq{<html lang="en"><head><meta charset="utf-8">}
          . qq{<meta name="viewport" content="width=device-width, initial-scale=1">}
          . qq{<title>$t</title>}
          . qq{<style>$Maat::Portal::CSS</style></head><body>}
          . $self->_nav_html
          . $self->_banner_html
          . qq{<main class="maat-main">}
          . $body_html
          . qq{</main></body></html>},
    };
}

our $CSS = <<'CSS';
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;line-height:1.5;color:#111}
.maat-nav{display:flex;gap:1rem;align-items:center;padding:.75rem 1rem;border-bottom:1px solid #ddd;background:#fafafa}
.maat-nav a{text-decoration:none;color:#0645ad;font-weight:600}
.maat-search{margin-left:auto}
.maat-search input{padding:.35rem .6rem;border:1px solid #ccc;border-radius:4px}
.maat-version{padding:.4rem 1rem;font-size:.85rem;color:#555;background:#f3f3f3;border-bottom:1px solid #eee}
.maat-version code{background:#eaeaea;padding:.1rem .3rem;border-radius:3px}
.maat-main{max-width:52rem;margin:0 auto;padding:1.5rem 1rem}
.maat-list{list-style:none;padding:0}
.maat-list li{padding:.25rem 0;border-bottom:1px solid #f0f0f0}
.maat-method{display:inline-block;min-width:3.5em;font-weight:700;color:#7a3e9d}
.maat-code{background:#0d1117;color:#e6edf3;padding:1rem;border-radius:6px;overflow-x:auto}
.maat-code .esh-s{color:#a5d6ff}.maat-code .esh-k{color:#ff7b72}.maat-code .esh-c{color:#8b949e}
.maat-params{border-collapse:collapse;width:100%}
.maat-params td,.maat-params th{border:1px solid #eee;padding:.3rem .5rem;text-align:left}
.maat-badge{padding:.6rem .9rem;border-radius:6px;margin:.75rem 0;font-weight:600}
.maat-badge-drift{background:#fff3cd;color:#7a5b00;border:1px solid #ffe69c}
.maat-badge-ok{background:#e7f6e7;color:#1a5c1a;border:1px solid #bfe3bf}
.maat-empty{color:#666}
CSS

# ---- search indexing -------------------------------------------------------

sub _index_doc {
    my ($self, $title, $url, $kind, $text) = @_;
    return unless defined $text && length $text;
    my $doc_id = $self->{search}->add($text);
    $self->{search_docs}[$doc_id] = { title => $title, url => $url, kind => $kind };
    return;
}

# ---- small helpers ---------------------------------------------------------

sub _spec_version {
    my ($api) = @_;
    my $spec = eval { $api->spec };
    return (ref $spec eq 'HASH' && ref $spec->{info} eq 'HASH')
         ? $spec->{info}{version} : undef;
}

# A frozen page: exactly the bytes a request gets back, computed once.
sub _freeze {
    my ($page) = @_;
    my $html = ref $page eq 'HASH' ? $page->{html} : $page;
    my $bytes = _bytes($html);
    return [ 200,
             [ 'Content-Type'                => 'text/html; charset=utf-8',
               'Content-Length'              => length $bytes,
               'X-Content-Type-Options'      => 'nosniff',
               'Referrer-Policy'             => 'no-referrer',
               'Content-Security-Policy'     =>
                   "default-src 'none'; style-src 'unsafe-inline'; "
                 . "img-src 'self' data:; form-action 'self'; base-uri 'none'; "
                 . "frame-ancestors 'none'" ],
             [ $bytes ] ];
}

sub _inject_banner {
    my ($trip, $banner) = @_;
    my $body = $trip->[2][0];
    $body = join '', @{ $trip->[2] } if ref $trip->[2] eq 'ARRAY';
    if ($body =~ m{</body>}i) {
        $body =~ s{</body>}{$banner</body>}i;
    } else {
        $body .= $banner;
    }
    my $bytes = _bytes($body);
    my @headers = @{ $trip->[1] };
    my $seen;
    for (my $i = 0; $i < @headers; $i += 2) {
        if (lc $headers[$i] eq 'content-length') { $headers[$i + 1] = length $bytes; $seen = 1 }
    }
    push @headers, 'Content-Length', length $bytes unless $seen;
    return [ $trip->[0], \@headers, [ $bytes ] ];
}

# Collapse a triplet's body to one byte string, so serve() and the HEAD
# path have a single scalar to work with, and the Content-Length is right.
sub _normalize_trip {
    my ($trip) = @_;
    my $body = ref $trip->[2] eq 'ARRAY' ? join('', @{ $trip->[2] })
             : (defined $trip->[2] ? $trip->[2] : '');
    my $bytes = _bytes($body);
    my @headers = @{ $trip->[1] };
    my $seen;
    for (my $i = 0; $i < @headers; $i += 2) {
        if (lc $headers[$i] eq 'content-length') { $headers[$i + 1] = length $bytes; $seen = 1 }
    }
    push @headers, 'Content-Length', length $bytes unless $seen;
    return [ $trip->[0], \@headers, [ $bytes ] ];
}

sub _content_type {
    my ($trip) = @_;
    my $h = $trip->[1];
    for (my $i = 0; $i < @$h; $i += 2) {
        return $h->[$i + 1] if lc $h->[$i] eq 'content-type';
    }
    return '';
}

sub _maybe_head {
    my ($method, $trip) = @_;
    return $trip unless $method eq 'HEAD';
    return [ $trip->[0], [ @{ $trip->[1] } ], [ '' ] ];
}

sub _text {
    my ($status, $msg) = @_;
    my $bytes = _bytes($msg);
    return [ $status,
             [ 'Content-Type'   => 'text/plain; charset=utf-8',
               'Content-Length' => length $bytes ],
             [ $bytes ] ];
}

sub _bytes {
    my ($s) = @_;
    $s = '' unless defined $s;
    utf8::encode($s) if utf8::is_utf8($s);
    return $s;
}

sub _escape {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    return $s;
}

sub _escape_uri {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/([^A-Za-z0-9._~-])/sprintf('%%%02X', ord $1)/ge;
    return $s;
}

sub _safe_slug {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/[^A-Za-z0-9._-]+/-/g;
    $s =~ s/\A-+|-+\z//g;
    return length $s ? $s : 'x';
}

sub _perl_str { my ($s) = @_; $s = '' unless defined $s; $s =~ s/'/\\'/g; return "'$s'" }
sub _perl_val {
    my ($v) = @_;
    return $v if defined $v && $v =~ /\A-?\d+(?:\.\d+)?\z/;
    return _perl_str($v);
}

# Plain text from markdown for the search index. Markdown::Simple ships a
# stripper; fall back to a crude strip if the version in use lacks it.
sub _plain {
    my ($md) = @_;
    return '' unless defined $md && length $md;
    my $plain = eval { require Markdown::Simple; Markdown::Simple::strip_markdown($md) };
    return $plain if defined $plain && length $plain;
    (my $s = $md) =~ s/[#*_`>\-\[\]()!]+/ /g;
    $s =~ s/\s+/ /g;
    return $s;
}

sub _query_param {
    my ($qs, $name) = @_;
    return undef unless defined $qs;
    for my $pair (split /[&;]/, $qs) {
        my ($k, $v) = split /=/, $pair, 2;
        next unless defined $k && $k eq $name;
        $v = '' unless defined $v;
        $v =~ tr/+/ /;
        $v =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
        return $v;
    }
    return undef;
}

1;

__END__

=head1 NAME

Maat::Portal - the docs portal, rendered from the enforced spec

=head1 SYNOPSIS

    my $portal = Maat::Portal->new(
        api       => $api,          # the SAME compiled Open::API the gateway enforces
        host      => 'acme.openapi-proxy.com',
        version   => $meta->{version},
        digest    => $meta->{digest},
        guides    => \@guides,      # fetched prose, [{ slug, title, body, order }]
        badges    => 1,             # the tenant's reality-badge opt-in
        violation => $gw->violation,# live drift for the badge
    );

    my $app = $portal->wrap($gateway_app);   # /docs served here, all else falls through

    $portal->handles('/docs/op/getPet');     # 1
    $portal->serve($env);                     # a frozen PSGI triplet
    $portal->reality;                         # { getPet => { drift => 1, ... }, ... }

=head1 DESCRIPTION

The per-environment documentation site phase 10 mounts on the gateway
itself, rendered from the B<same> compiled L<Open::API> object the gateway
is enforcing - so the documented contract and the checked contract cannot
disagree.

Every page is rendered B<once>, at construction, which happens off the
request path in L<Maat::Registry>'s compile step. A request into C</docs>
is then a hash lookup into pre-rendered bytes - the generated reference
(L<Open::API::UI>), the prose guides (L<Markdown::Simple>), the
per-operation client snippets and the L<Search::Trigram> index are all
boot work. The two data endpoints, C</docs/search> and
C</docs/reality.json>, do per-request work, but neither is on the API
path.

=head2 The version and its hash on every page

Every page carries the spec version and content digest the gateway holds
for this host, so a reader always knows which contract they are reading
and the docs move with the enforced spec (gate 1).

=head2 The reality badge

Per operation, a badge from this gateway's own L<Maat::Violation/drift>
aggregates: an operation whose responses have drifted from their schema
says so. Gated by the tenant's C<badges> opt-in - off, no badge is ever
rendered and C</docs/reality.json> reports nothing. Because the same
aggregates are shipped to the control plane, the badge reconciles with the
control plane's drift view by construction (gate 3). The badge is filled
from the live drift on the C</docs/op/*> serve path by a single string
substitution, never a re-render.

=head2 Off by default

The portal is only built when the gateway switch (L<Maat::Config/portal>)
is on. Off, no portal object exists and there is no C</docs> route at all
(gate 4).

=head1 METHODS

=head2 new(api => $api, host => $h, version => $v, digest => $d, guides => \@g, badges => 0|1, violation => $v, base => '/docs', title => $t)

=head2 handles($path) / serve($env) / wrap($inner_app)

=head2 reality($violation?) / version / digest / base / badges / short_digest / renders

C<renders> is the count of render passes done - all at construction. It
does not move on a request, which is the evidence for gate 2.

=cut
