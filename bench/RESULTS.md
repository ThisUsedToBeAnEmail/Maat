# What the gateway costs

Run `perl bench/gateway.pl [iterations] [reps]` to reproduce. The numbers
below are one machine's, recorded so a change that makes the gateway
slower is visible as a change rather than as a feeling.

## The cost table

One upstream returning a fixed 2KB JSON document, 30,000 iterations,
best of 7, Perl 5.42.0, Apple M-series, 2026-08-09:

```
                                       us/req    vs bare      added
  -------------------------------- ---------- ---------- ----------
  direct to upstream                     1.35       100%
  + Reverse::Proxy                       1.51       113%
  + request validation                   2.32       173%    +0.81us
  + response validation @ 1%             2.52       188%    +1.01us
  + response validation @ 100%           3.34       248%    +1.82us
```

`added` is measured against the proxy row: what validation costs on top
of forwarding.

## Reading it

**Response validation at the product default costs 0.20us per request**
over request validation alone (2.52 against 2.32). Validating every
response costs 1.02us. So sampling at 1% removes 80% of the cost of
response validation while still weighing one response in a hundred
against its schema, per operation.

That 0.20us is almost all fixed overhead rather than validation work -
the clock read, the divisor lookup and the crossing into C. It does not
grow with the sampling rate, which is why the 1% and 100% rows differ by
so much more than the 1% row differs from no response validation at all.

**The upstream here is a coderef, not a socket.** A real round trip is
hundreds of microseconds and buries all of this. That is the point of
measuring it this way round: what is on the page is what Maat adds, not
what a request costs.

## Why it is measured at all

Per-request cost is the gross margin of a hosted proxy: it decides how
many tenants fit on one box, which is the whole unit economics of a low
monthly plan. It is also the number a customer asks for first, and the
only honest way to answer is to have measured it and to say on what.

## What the sampling design has to keep true

The gate for phase 2 was that the 1% column stays close to the
request-validation column. It did not, at first: the first working
version added 0.39us, and the cause was not validation but plumbing -
a fresh options hashref built per request (0.11us), and rebuilding the
whole coverage hash on every request to hand to a retune that runs once
a second (0.49us when it ran, and it was being built every time).

Both are now avoided: the coverage hash is not built unless the clock
says the retune will run, and the options hashref is cached per
operation and looked up by field. See `Maat::Sampler`'s hot-path
contract and `Maat::Gateway::_check_response`.

The lesson is worth keeping: at this scale the cost of *asking* whether
to do the work can exceed the work.

## Memory

Not in the table above, and measured separately by `t/12-streaming.t`:
proxying a body far larger than the worker.

| mode | worker RSS growth, 128MB body |
|---|---|
| buffered (the default) | ~510MB (~4x the body) |
| `stream: 1` | ~134MB (~1x the body) |

The response check never reads a body it has skipped - with
`responses.validate` off entirely the growth is the same, so nothing in
phase 2 is holding those bytes. What remains is the forward itself
buffering to the slower of the two sockets, in Reverse::Proxy and
Hyperman. `t/12-streaming.t` records this as a TODO rather than a
loosened threshold, so it un-TODOs the day backpressure lands.

## The fleet dispatch toll (phase 12a)

`bench/fleet.pl`, Apple M-series 10-core, 1000 mock-mode tenants,
200k iterations, warm compiled cache (a miss is capacity.pl's number,
not this one's):

| path | req/s | us/req |
|---|---|---|
| bare gateway (`mt_serve`, no fleet) | 224,201 | 4.46 |
| `Maat::Registry->resolve` alone | 1,524,855 | 0.66 |
| full fleet dispatch (Fleet + Router + resolve) | 92,920 | 10.76 |

The toll is **6.3us/req - 141% on top of the C path it guards**. The
hosted fleet serves at 93k req/s where the same compiled gateway
answers at 224k; the Perl between Hyperman and `mt_serve` costs more
than the entire matched-validated-synthesized request it dispatches.
Resolve is 0.66us of it; the rest is `_dispatch` (the per-request caps
merge, the `_header_bytes` walk over env, tmetrics, two closures) and
the two app-closure frames either side.

Phase 12's C dispatcher deletes the toll, which is a straight doubling
of tenants-per-box in the capacity model - the margin number, not a
vanity one.

## End to end, over a socket (bench/edge.pl)

Every other number here is in-process - the client is a function call,
the upstream is a coderef - because that isolates what Maat *adds*.
This one is what a client actually gets: accept, HTTP parse, fleet
dispatch, the compiled request path, response written back. Hyperman,
plain HTTP over loopback, 50 mock-mode tenants (no upstream round trip
to bury the measurement), keep-alive clients, Apple M-series 10-core:

| workers | req/s end to end | us/req |
|---|---|---|
| 1 | 52,967 | 18.9 |
| 2 | 103,999 | 9.6 |
| 4 | 111,220 | 9.0 |

**The 4-worker row is the load generator's ceiling, not the server's** -
eight forked Perl clients on the same box compete with the workers for
the same ten cores. Two workers scaling at 1.96x is the honest signal;
treat 111k as a floor.

### Where a request's 18.9us goes, single worker

| | us | what |
|---|---|---|
| server + kernel | ~8.1 | accept, HTTP parse, syscalls, write |
| **fleet dispatch (Perl)** | **~6.3** | **Fleet wrapper, Router, resolve** |
| compiled request path (C) | ~4.5 | match, validate, synthesize, stamp |

So phase 12 is worth about **45% of end-to-end throughput per worker**
(18.9us -> ~12.6us, ~53k -> ~77k req/s), not the 141% the in-process
figure suggests - the in-process number excludes the kernel, which does
not go away. That is the number to hold the phase to.

### What this does not measure

No TLS (a handshake amortised over a keep-alive connection, plus a
per-byte cost); loopback, so no real network latency; and mock mode, so
no upstream round trip - which is hundreds of microseconds and dominates
the latency of a real proxied request without touching this ceiling.

## After the port: the edge in C (phase 12)

Same `bench/edge.pl`, same machine, after `mt_fleet.h` + `mt_dispatch.h`
replaced `Maat::Router::_dispatch`:

| workers | before | after | change |
|---|---|---|---|
| 1 | 52,967 req/s (18.9us) | **84,564 req/s (11.8us)** | +60% |
| 2 | 103,999 req/s (9.6us) | **145,959 req/s (6.9us)** | +40% |

Three consecutive single-worker runs: 84,564 / 87,344 / 83,663 - about
+/-2%, so the +60% is a signal and not a fluke of one round.

With enough clients to saturate them, four workers serve **162,214 /
163,746 / 151,349 req/s** and eight serve 163,886. The site quotes
160,000/s, which three of those four runs clear; the fourth did not, so
it is the typical figure and not a floor. The ceiling belongs to the
load generator - sixteen forked Perl clients competing with the workers
for the same ten cores - rather than to the gateway.

A caution for anyone re-running this. An earlier attempt reported 4 and
6 workers as SLOWER than 2, which was the harness, not the server: zsh
does not word-split unquoted variables, so `set -- $cfg` passed the
whole string as one argument and every run silently used the default
four clients. A starved load generator looks exactly like a server that
does not scale.

### Against the prediction

The plan said this would be worth "~45% of end-to-end throughput per
worker (18.9us -> ~12.6us, ~53k -> ~77k)". Measured: 18.9us -> 11.8us,
53k -> 85k, which is **better than predicted**. The prediction assumed
the port would delete the 6.3us of Perl and change nothing else; it also
removed the per-request caps merge (resolved once per compile now) and a
Perl frame either side of the app call, which the estimate did not
count.

### The in-process figure, and why it is quoted with care

`bench/fleet.pl` now reports a dispatch toll of ~1.4us, down from 6.3us.
Both numbers are best-of-7, and they need to be: three consecutive
single-round runs of that file gave 0.66, 2.60 and 1.62us on an
otherwise identical tree, which is not a 4x change in the code. Any
in-process microbenchmark on a laptop that is also running a test suite
is a measurement of the laptop. The socket number above is the honest
one, and it is the one the capacity model should quote.

### What is left in the 11.8us

| | us | what |
|---|---|---|
| server + kernel | ~8.1 | accept, HTTP parse, syscalls, write |
| compiled request path (C) | ~4.2 | match, validate, synthesize, stamp |
| fleet dispatch (C) | ~1.4 | host lookup, caps, ceiling, stamp |

Those do not sum to 11.8 because they are measured in different harnesses
and overlap; the useful reading is that dispatch is no longer the largest
term, and the kernel now is. Further gains are in the server, not in this
distribution - which is where phase 12 was always going to end.

## The agent endpoint (bench/mcp.pl)

Two questions, and they are not the same question: whether turning MCP on
costs a customer who never uses it anything, and what a tool call costs
over the same request made directly.

One mock tenant, 30,000 iterations, best of 7, Perl 5.42.0, Apple
M-series, 2026-09-13:

```
  API path, MCP off                     213,087 req/s     4.693 us/req
  API path, MCP on                      215,339 req/s     4.644 us/req
  the same operation, as a tool         111,126 req/s     8.999 us/req
```

**Turning MCP on does not move the API path.** The flag test came out at
-1.0% on one run and +0.0% on the next, which is to say it is not
measurable here: the dispatcher gains one flag test, and a path compare
that only runs once that flag is set. The negative number is the proof
rather than a win - one branch cannot make the path faster - and it is
why the check in the script is a percentage band rather than an absolute
microsecond threshold, which would have reported ordinary noise as a
regression.

**A tool call costs about 4.4us more than the same request made
directly**, +4.35us and +4.57us on the two runs. That is the JSON-RPC
decode, validating the arguments against the tool's compiled schema,
synthesising the environment and encoding the reply: all in C, and all on
top of a request that then happens exactly as it always did.

Read it against a real forward, which is hundreds of microseconds to an
upstream over a socket. MCP framing is not where an agent's latency comes
from. The mock tenant here is deliberately the harshest backdrop it could
be measured against - with no upstream round trip in the middle, that
4.4us is the largest share of a request it will ever be.
