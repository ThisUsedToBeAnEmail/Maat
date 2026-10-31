# Manual gates

Two things in this product cannot be asserted by a test file, because what
they prove is that a REAL client, written by somebody else against the
published specification, works against what we built. A passing suite of our
own tests proves we agree with ourselves.

Run these before the gateway is released, and keep the transcript beside
this file so the next person can see what was actually exchanged.

## 1. The MCP Inspector, OAuth end to end

The reference client. This is the gate phase 03's acceptance names.

### What it must demonstrate

Each of these is a step the Inspector performs on its own. The point is that
none of them needed a hint from us.

1. **Discovery from the 401.** The Inspector calls `/mcp` with no credential,
   receives `401` with `WWW-Authenticate: Bearer realm="apip",
   resource_metadata="https://<slug>.openapi-proxy.com/.well-known/oauth-protected-resource"`,
   and fetches that document without being told where it is.
2. **Registration.** It finds `registration_endpoint` in the authorization
   server metadata and registers itself (RFC 7591), receiving a `client_id`
   and no secret.
3. **PKCE.** It starts the authorization code flow with `code_challenge` and
   `code_challenge_method=S256`, and includes `resource=https://<slug>.openapi-proxy.com/mcp`
   (RFC 8707).
4. **Consent.** A browser opens the site's login, then the consent screen,
   which asks which API key the agent may act as. Approving returns to the
   client with a code.
5. **A call.** The client exchanges the code, calls `tools/list`, then
   `tools/call` on a real operation, and gets a result from the upstream.
6. **A call the schema refuses.** Send a `tools/call` with an argument of
   the wrong type, or a required one missing. It must come back as a
   JSON-RPC `-32602`, and the upstream's access log must show that the
   call never reached it: the arguments are checked against the tool's
   compiled schema first, so a refused call costs the tenant nothing.
7. **A rate limit.** Call one tool harder than the key allows, or set
   `mcp_calls_per_min` low on the key first. The answer must be a tool
   RESULT with `isError` and `_meta.retry_after`, not a protocol error -
   a model has to be able to read it and wait. Check the number is
   seconds and that a client honours it.

For a proxy with more than 50 operations, also confirm the client follows
`nextCursor` through every page of `tools/list` rather than stopping at
the first 50. Most do this silently; the tell is the tool count it ends
up showing you.

### Running it

    # control plane
    cd Web/Maat-Site
    MAAT_SITE_DSN=... MAAT_SITE_VAULT_KEY=... MAAT_SITE_OAUTH=1 \
    MAAT_SITE_SESSION_KEY=... MAAT_REGISTRY_TOKEN=... \
      perl -Ilib bin/prod_server        # or plackup -Ilib

    # data plane
    cd Maat
    apip-fleet run --config /path/to/fleet.yml

    # the client
    npx @modelcontextprotocol/inspector

Point the Inspector at `https://<slug>.openapi-proxy.com/mcp`. It needs to
reach both planes by the hostnames in the bundle, so either run behind the
real DNS or add the tenant host to `/etc/hosts`.

### What to keep

Save the Inspector's own transcript as `inspector-<date>.txt` in this
directory, and note:

- the exact `WWW-Authenticate` value it received,
- the `client_id` it was issued,
- the `aud` of the access token it got (it must be the `/mcp` URL, not the
  issuer),
- and that the upstream's access log shows NO `Authorization` header
  carrying the client's token.

That last one is a MUST in the specification and the only one a person has to
look for by eye here; `t/39-mcp-spec-musts.t` asserts it against the echo
upstream, but seeing it on a real upstream is the point of a manual gate.

## 2. A real product client

The Inspector proves the protocol. These prove the product, and each has
declined to work with servers that the Inspector accepted, so they are not
redundant:

- **Claude Code** - add the endpoint as an MCP server.
- **Cursor** - same, through its MCP settings.
- **A Claude.ai connector** - the OAuth path specifically, since a connector
  runs the flow in a browser a customer owns.

For each, note the client version and whether it completed without manual
configuration beyond the URL.
