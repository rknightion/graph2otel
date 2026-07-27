# Issue #289 transport research

## Verdict

The plan is **not implementation-ready as written**.

Two corrections are required before #289 starts:

1. #268 exposes exporter callback health only. `DeliverySnapshot` contains
   callback attempts/successes/failures and lifecycle failures; it has no
   transmitted-byte or retry-attempt fields. #289 must own a separate transport
   tracker and provider accessor. It cannot consume a nonexistent #268 seam.
2. `graph2otel.otlp.wire.bytes` cannot truthfully be implemented from the public
   APIs while preserving the current HTTP and gRPC exporter configuration
   behavior. The exact portable quantity available at both transports is the
   **encoded OTLP payload handed to the client transport**, after compression,
   excluding HTTP, HTTP/2, TLS, TCP, and IP framing. Rename the contract to
   `graph2otel.otlp.transmitted_payload.bytes` (or equivalently precise wording)
   and rename `wire_byte_microunits` to `payload_byte_microunits`.

gRPC needs no dependency fork. HTTP needs one small exporter observer hook in
both pinned HTTP exporter modules, or the same hook accepted upstream and
released. `WithHTTPClient` is not an acceptable shortcut because it replaces
configuration that #289 is required to preserve.

## What the current code actually provides

- `internal/telemetry/delivery.go:33-54` defines immutable callback-only
  `DeliverySignal` and `DeliverySnapshot`.
- `internal/telemetry/delivery.go:249-252` and `280-283` increment one delivery
  attempt only after the delegate exporter returns. Any internal OTLP retries
  have already happened.
- `internal/telemetry/provider.go:183-204` constructs the OTLP exporters before
  `newProvider`; `newProvider` creates the delivery tracker and wraps the
  exporters at `provider.go:227-236`.
- `internal/telemetry/provider.go:420-476` passes endpoint and Grafana auth
  options, while all other OTLP settings continue to come from exporter
  defaults and `OTEL_EXPORTER_OTLP*` environment variables.

The plan statement that “#268 adds ... transmitted-byte and retry
deltas/totals” is stale. #268 tracks SDK exporter callbacks, deliberately not
transport attempts.

## The measurement contract

Use these definitions:

| Quantity | Exact definition | Included | Excluded |
| --- | --- | --- | --- |
| transmitted payload bytes | Bytes of the encoded OTLP request payload consumed/accepted by the client transport, counted once for every actual payload send | protobuf payload after gzip when enabled; duplicate payloads sent by retries | HTTP headers/chunk markers, gRPC 5-byte message header, HTTP/2 frames, TLS records/handshake, proxy CONNECT, TCP/IP framing and kernel retransmission |
| exporter retry attempt | A second or later invocation of the pinned exporter's retry closure for one SDK `Export` callback | HTTP retry-loop `Do`; gRPC retry-loop `Export` RPC | initial attempt; redirects; connection re-establishment; gRPC transparent ClientConn retries |

The first quantity is exact at the Go client-transport boundary. It is not a
claim about NIC bytes or vendor-billed bytes. Pricing metadata must identify
that basis.

For gRPC, retaining `stats.OutPayload.WireLength` under a metric named `wire`
would still be misleading: grpc-go defines it as compressed payload plus only
the five-byte gRPC message header, explicitly excluding HTTP/2 framing. HTTP
has no corresponding public framed-length value. Use
`OutPayload.CompressedLength` so HTTP and gRPC measure the same layer.

If the maintainer instead requires socket or NIC bytes, this design must stop:

- wrapping `net.Conn.Write` can count process socket writes, but includes TLS
  handshakes, headers, HTTP/2 control traffic and proxy CONNECT, and still
  excludes kernel TCP retransmission and IP/link framing;
- a custom grpc-go dialer disables its normal proxy path
  (`grpc-go/internal/transport/proxy_ext_test.go:344-349`);
- public OTLP options do not expose the already configured HTTP/gRPC
  connection so it can be decorated below TLS;
- portable exact NIC bytes require platform capture/eBPF and cannot be
  reconciled to these exporter signals without a separate operating contract.

## Shared process tracker

Add a #289-owned `internal/telemetry/otlptransport.go`, independent of
`deliveryTracker`:

```go
type OTLPTransportSignal struct {
    PayloadBytes  uint64
    RetryAttempts uint64
}

type OTLPTransportSnapshot struct {
    Metrics OTLPTransportSignal
    Logs    OTLPTransportSignal
}
```

`Provider.Transport()` returns a cumulative immutable snapshot. The
self-observation report differences cumulative values to emit interval deltas.
Do not add these fields to `DeliverySnapshot`: callback acceptance and
transport volume are different facts with different conservation rules.

Each existing exporter wrapper attaches a private `*exportTransportState` to
the context before calling its delegate. The state contains the fixed signal
and an atomic exporter-attempt ordinal. Transport hooks update the process
tracker directly:

- payload hook: add the observed byte count;
- attempt hook: increment the ordinal, and increment `RetryAttempts` only when
  the ordinal is greater than one.

An export that is cancelled, rejected for size, or fails serialization before
the first transport attempt contributes zero retries and zero bytes. Failed
attempts contribute only the payload bytes actually consumed/accepted by the
transport hook. This avoids subtracting #268 callback totals from transport
totals, which would be wrong for pre-transport failures.

The wrapper edit may live beside #268's wrapper implementation, but the
contract remains explicit: #268 owns callback fields; #289 owns context
correlation and the transport snapshot.

## gRPC design: public APIs are sufficient

For each exporter, append both options through its existing
`WithDialOption(...)`:

```go
grpc.WithChainUnaryInterceptor(exportAttemptInterceptor(signal, tracker))
grpc.WithStatsHandler(payloadStatsHandler{signal: signal, tracker: tracker})
```

Filter the interceptor and stats handler to the exact OTLP method:

- `/opentelemetry.proto.collector.metrics.v1.MetricsService/Export`
- `/opentelemetry.proto.collector.logs.v1.LogsService/Export`

The unary interceptor reads the private export state from `ctx` and records one
exporter attempt. This is exact because the metric exporter invokes
`c.msc.Export` inside its retry closure
(`otlpmetricgrpc@v1.44.0/client.go:129-145`) and the log exporter does the same
at `otlploggrpc@v0.20.0/client.go:171-187`. grpc-go transparent retries happen
below the interceptor, so they are correctly excluded from the exporter-retry
counter.

The stats handler processes client `*stats.OutPayload` events carrying the
private export state and adds `CompressedLength`. grpc-go defines:

- `Length`: uncompressed protobuf, no framing;
- `CompressedLength`: compressed protobuf, no framing;
- `WireLength`: compressed protobuf plus the five-byte gRPC message header,
  still no HTTP/2 framing.

Those definitions are in `grpc-go@v1.82.1/stats/stats.go:155-175`; construction
of the event is at `rpc_util.go:897-905`. `OutPayload` is emitted only after
`transportStream.Write` succeeds (`stream.go:1123-1144`) and is repeated for
transparent resend attempts, so duplicated payload cost is retained even
though transparent retries are not called exporter retries.

This instrumentation preserves configuration:

- metric and log exporters append caller dial options before applying their
  resolved TLS credentials, compression and connection settings;
- `grpc.WithStatsHandler` appends rather than replaces handlers
  (`grpc-go@v1.82.1/dialoptions.go:521-532`);
- no custom connection, transport credentials or dialer is supplied;
- endpoint, headers, gzip, TLS root/client certificates, timeout, retry policy,
  proxy resolution and user agent remain exporter-owned.

`WithGRPCConn` would bypass `WithDialOption`; graph2otel does not use it today.
Add a construction test so a future supplied connection cannot silently
disable the counters.

## HTTP design: one dependency hook is required

### Why `WithHTTPClient` must not be used

The only public HTTP body-access seam is
`otlploghttp.WithHTTPClient`/`otlpmetrichttp.WithHTTPClient`. Both explicitly
take precedence over exporter proxy, timeout and TLS configuration and their
environment variables:

- metrics:
  `otlpmetrichttp@v1.44.0/config.go:236-249`;
- logs: `otlploghttp@v0.20.0/config.go:370-386`.

The clients confirm that a supplied client bypasses construction of the
configured transport and timeout:

- metrics: `otlpmetrichttp@v1.44.0/client.go:75-93`;
- logs: `otlploghttp@v0.20.0/client.go:69-87`.

That loses or requires graph2otel to duplicate signal-specific/common root CA,
client-certificate/key precedence, timeout parsing, proxy behavior, transport
defaults and error handling. The metric and log modules even use different
configuration implementations at these pinned versions. Reimplementing them
is not “preserving exporter behavior”.

`httptrace.ClientTrace` is additive and can observe `WroteRequest`, but
`WroteRequestInfo` contains only an error, not a body length
(`$GOROOT/src/net/http/httptrace/trace.go:160-171`). It therefore cannot supply
the byte measurement.

### Minimal hook

Carry a minimal patch in both pinned HTTP exporter modules, preferably upstream:

```go
type RequestObserver interface {
    Attempt(context.Context)
    PayloadBytes(context.Context, int)
}

func WithRequestObserver(RequestObserver) Option
```

The observer is applied inside the existing client, after all normal config
resolution:

1. Immediately inside each `requestFunc` closure, before `httpClient.Do`, call
   `Attempt(iCtx)`. This is the exact exporter retry-loop boundary
   (`otlpmetrichttp/client.go:173-183`,
   `otlploghttp/client.go:185-195`), so redirects are not mislabeled as retries.
2. After `request.reset(iCtx)`, wrap only that reset body in a
   `countingReadCloser`. For every successful `Read` returning `n > 0`, call
   `PayloadBytes(iCtx, n)`. Do not buffer, replace the `http.Client`, alter
   `ContentLength`, or touch `GetBody`.

The exporter already fully buffers both payload forms. For metrics the plain
body is set at `otlpmetrichttp/client.go:280-284` and gzip is materialized at
`285-308`; logs use the same resettable shape. The wrapper therefore observes
the exact encoded bytes consumed by the configured transport on every retry,
including gzip, without changing chunking or request replay.

The hook must be a no-op when nil and must not retain the request body, headers,
URL or errors. Its callback is synchronous and allocation-free after the
per-export state is attached. This patch changes neither endpoint nor request
semantics and is much smaller and safer than replacing the client.

Until both modules expose that hook, #289 may land record/point attribution but
must not claim HTTP payload bytes or cross-protocol reconciliation.

## Metrics and plan changes

Use:

| Metric | Unit | Labels | Meaning |
| --- | --- | --- | --- |
| `graph2otel.otlp.transmitted_payload.bytes` | `By` | `signal` (`metrics`, `logs`) | Exact encoded OTLP payload bytes consumed/accepted by the process client transport, after compression and excluding protocol/network framing. |
| `graph2otel.otlp.retry_attempts` | `{retry}` | `signal` (`metrics`, `logs`) | Exact second-and-later exporter retry-loop attempts within one SDK export callback. |

Keep both process-only. Do not add tenant, collector, endpoint, status code or
error labels. Collector allocation remains estimated.

Change the cost input and prose from “wire byte” to “transmitted payload byte”.
The operator-provided price source/version/effective timestamp must state
whether that rate is actually compatible with this basis. An invoice based on
uncompressed ingest, post-processing storage or full network egress is not
made exact by this counter.

## RED tests

### Shared tracker and wrapper

1. One callback with zero hooks: zero bytes, zero retries.
2. One attempt: bytes counted, retries zero.
3. Three attempts: retries two; bytes are the sum of all three payload sends.
4. Concurrent metric/log exports: independent exact totals under `-race`.
5. Serialization/size/cancel failure before transport: zero bytes/retries.
6. Snapshot reads are cumulative, immutable and non-resetting; report deltas
   conserve back to the cumulative snapshot.
7. Existing #268 callback tests remain byte-for-byte unchanged in meaning.

### HTTP exporter-hook tests, in both forked modules

1. Fake configured `RoundTripper` reads the whole uncompressed body: observer
   bytes equal the server/fake body length.
2. Gzip: observer bytes equal the compressed request body and differ from the
   uncompressed protobuf for a compressible fixture.
3. Fake transport reads only `N` bytes then errors: observer records exactly
   `N`, not intended body length.
4. `503, 503, 200` with zero test backoff: three attempts, two retries, and
   three payload bodies counted.
5. Redirect: the observer's attempt callback fires once for the exporter
   attempt; redirect round trips are not exporter retries.
6. Observer nil: request, headers, body, error and retry behavior match the
   unpatched exporter.

### Environment-preservation matrix

Run the real metric and log constructors with observer off/on and assert the
same outcome for:

- explicit graph2otel endpoint and default/per-signal endpoint environment;
- graph2otel Authorization header and common/per-signal header environment;
- `none` and `gzip` compression;
- `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`;
- common and per-signal root CA;
- common and per-signal client certificate/key, including signal precedence;
- common and per-signal timeout;
- retryable status plus `Retry-After`;
- HTTPS and mTLS test servers.

The hook-on case must use no `WithHTTPClient`.

### gRPC tests

1. OTLP test server returns `Unavailable`, then success: interceptor records
   one retry; `OutPayload.CompressedLength` is counted for both sends.
2. Repeat with gzip: count equals the sum of compressed lengths and excludes
   the five-byte gRPC headers.
3. A service config transparent retry proves duplicate `OutPayload` bytes are
   counted while exporter retries remain zero. grpc-go's own retry stats test
   demonstrates one `Begin`/`OutPayload` sequence per attempt at
   `grpc-go@v1.82.1/test/retry_test.go:683-703`.
4. Failure before `OutPayload`: attempt may exist, bytes stay zero.
5. Existing stats handler plus the graph2otel handler both receive events,
   proving append behavior.
6. Endpoint, metadata headers, gzip, proxy, TLS/mTLS and timeout tests run with
   hooks off/on and produce identical server-observed behavior.

## Dependency/source receipt

Inspected pinned source:

- OpenTelemetry metric HTTP/gRPC exporters `v1.44.0`;
- OpenTelemetry log HTTP/gRPC exporters `v0.20.0`;
- grpc-go `v1.82.1`;
- Go `net/http/httptrace` from Go `1.26.5`.

Current Context7 documentation was also checked for OpenTelemetry Go and
grpc-go. It confirms the public option surface and grpc stats-handler model;
the pinned module source above is the authority for exact behavior and line
references.

