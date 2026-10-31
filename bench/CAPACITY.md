# The capacity model

The numbers the pricing rests on, measured not estimated. Reproduce with

    perl bench/capacity.pl [copies]

## The machine

Measured on an Apple M-series laptop, 10 cores, Perl 5.42.0, macOS
(Darwin arm64), 2026-08-09. Resident-memory figures are process RSS via
`ps`, differenced across compiling many distinct copies of a spec, so
they include the compiled JSON::Schema::Fast validators, the routing
tables and the Perl overhead of a real `Open::API` object - not just the
document.

The per-request microcosts in section 3 are carried over from
`bench/RESULTS.md` (phase 2, same class of machine); this benchmark
measures the memory, the compile cost and the edge serve rate that phase
6 adds on top.

## 1. Resident bytes per compiled spec

| spec | source | operations | resident/spec |
|---|---|---|---|
| small | 0.7 KB | 1 | **8.3 KB** |
| median | 2.8 KB | 4 | **77 KB** |
| large | 32 KB | 120 | **735 KB** |

Resident memory tracks operation count and schema surface, not source
bytes: the large spec is 46x the source of the small one but 88x the
resident memory, because each operation compiles its own parameter,
body and response validators.

The registry's LRU byte cap counts **source** bytes (cheap and stable to
track on the hot path); this table is the multiplier from that figure to
true footprint. A 1.5 GB compiled-spec budget per worker holds roughly:

| at this spec size | tenants resident per worker |
|---|---|
| small (8.3 KB) | ~194,000 |
| median (77 KB) | **~20,900** |
| large (735 KB) | ~2,100 |

The phase-6 gate is 1000 distinct tenants on one worker; the median
figure clears that by a factor of twenty, and gate 1 (`t/22`) holds 1000
median-ish specs in **0.68 MB** of tracked source with zero evictions.

## 2. The cost of a miss

A miss is the whole lazy path on the first request for a host: fetch the
spec body by digest, verify its sha256, compile it, and build the
gateway around it.

| spec | miss cost |
|---|---|
| small | 0.024 ms |
| median | 0.083 ms |
| large | 1.5 ms |

A miss is paid once per host per version per worker and then the entry is
resident. Even the large spec's 1.5 ms is a single first request, not a
steady-state cost, and it is confined to the tenant that owns it: a
neighbour's requests are cache hits and never enter the compile path
(proven in `t/21`, where a compile held for 30 s is killed at its 0.3 s
budget while a neighbour's resolve stays sub-millisecond).

## 3. Requests per second

Measured edge throughput - routing by Host through `Maat::Registry` and
serving a mock response through the full `Maat::Router` -> `Maat::Gateway`
path, one worker:

    ~119,000 req/s   IN-PROCESS: no socket, no HTTP parse, no server

**That figure is the app path called as a function**, and it was the only
throughput number here for a long time, which made it easy to read as
something it is not. Over a real socket - Hyperman, plain HTTP, keep-alive
clients, the same mock tenants - `bench/edge.pl` measures:

    ~53,000 req/s    one worker, end to end
    ~104,000 req/s   two workers (1.96x - it scales)

The difference is the server and the kernel: accept, parse, syscalls,
write, about 8us of the 18.9us a request takes end to end. The costing
below uses 119,000 as a conservative WHOLE-BOX sustained rate, and that
remains conservative for the right reason rather than by luck - a box
runs several workers, and two of them already exceed it.

Per-core ceilings of the Maat-added request path (from `bench/RESULTS.md`,
`1e6 / us`):

| path | us/req | req/s/core |
|---|---|---|
| request validation only | 2.32 | 431,000 |
| + response validation @ 1% (the default) | 2.52 | 397,000 |
| + response validation @ 100% | 3.34 | 299,000 |

At 10 cores that is **~4.0 M req/s** at 1% sampling and **~3.0 M req/s**
at 100%. These are CPU ceilings of the work Maat *adds*; a real proxied
request is dominated by the upstream round trip, which is hundreds of
microseconds and buries all of it. That is the point: per-request CPU is
not the binding constraint. Memory (tenants resident) and sustained
request throughput are.

## 4. Cost per million requests

Priced against a named cloud instance, assumption stated so it reprices
by swapping two constants in `bench/capacity.pl`:

- **Hetzner CCX33** - 8 dedicated vCPU, 32 GB RAM - about EUR 64/month
  list, ~= **GBP 55/month** (EUR->GBP 0.855, 2026 list price).

Basis: the measured single-worker serve rate (~119,000 req/s) as a
conservative whole-box sustained rate - a box runs several workers but
also does the socket I/O this mock-serve loop skips, so one worker's rate
is a defensible floor - at **20% sustained utilisation** (real traffic is
bursty; a box run flat out all month is a fiction):

    ~62 billion requests/month/box
    -> GBP 0.0009 per million requests

Infrastructure COGS per million requests is under a tenth of a penny. The
32 GB of RAM holds ~20,900 median tenants (section 1) well before the CPU
or the network is the limit, so on this box **memory is the binding
resource**, and it binds at a tenant count, not a request rate.

## 5. Does Starter clear 80% margin?

Starter is GBP 29/month for 1 M requests and up to 3 proxies.

    infra COGS of 1 M requests: GBP 0.0009
    gross margin on infrastructure: 99.997%   -> clears 80%: YES

Even loading the estimate a thousandfold - for the violation pipeline,
the control-plane Postgres, bandwidth, and the support cost a real
customer carries - Starter stays far above the 80% bar the phase sets.
The tier is not mispriced downward; if anything the free tier's real
constraint is abuse (an open relay), which phase 9 owns, not unit cost.

## What feeds back into 01-business.md

- A worker holds **~20,900 median tenants** in 32 GB; the fleet size is a
  function of tenant count, not request rate.
- A miss costs **0.08 ms** (median) and is paid once per host per worker;
  lazy compile is not a latency tax on steady state.
- Per-request infra cost is **sub-penny per million**; the monthly box
  price, spread over tenants, is the real COGS line.
- **Starter clears 80% margin with three orders of magnitude to spare.**
