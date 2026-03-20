---
layout: default
title: "ADR-005: Per-client HTTPClient ownership — no shared connection pool"
parent: Architecture Decision Records
nav_order: 5
---

# ADR-005: Per-client `HTTPClient` ownership — no shared connection pool

**Status:** Accepted

---

## Context

Safire needs to make HTTP requests for SMART discovery and token operations. The question is: at what scope should the HTTP client live?

**Option A — Module-level singleton:** one `HTTPClient` shared across all `Safire::Client` instances.

**Option B — Per-`Client` ownership:** each `Safire::Client` constructs and owns its `Protocols::Smart` instance, which in turn owns its own `HTTPClient`.

A shared HTTP client creates several problems:

1. **Thread safety:** Faraday connection objects are not documented as thread-safe. A shared connection used concurrently by multiple clients in a web application could produce race conditions in connection state.

2. **Configuration isolation:** if different clients need different SSL configurations, timeouts, or user-agent strings, a shared client cannot serve them all without complex multiplexing logic.

3. **Discovery cache isolation:** SMART discovery metadata is cached inside `Protocols::Smart`. If two clients point at different FHIR servers, their metadata must not bleed across — and the HTTP client that fetched the metadata is tightly coupled to the `Smart` instance that owns the cache. Sharing the HTTP client would require separating it from the cache, which defeats the clean ownership model.

---

## Decision

Each `Protocols::Smart` instance creates and owns its own `Safire::HTTPClient`:

```ruby
def initialize(config, client_type: :public)
  # ...
  @http_client = Safire::HTTPClient.new
end
```

The `HTTPClient` is not shared, not exposed publicly, and not accessible from `Safire::Client`. Its lifetime is tied to the `Protocols::Smart` instance, which is itself tied to a single `Safire::Client`.

For callers managing multiple FHIR servers, the recommended pattern is a per-server client registry (see [Advanced Examples]({{ site.baseurl }}/advanced/#multi-server-management)).

---

## Consequences

**Benefits:**
- Each client is fully isolated — different SSL configs, timeouts, or FHIR servers do not interact
- Thread-safe by design — no shared mutable state in the HTTP layer across clients
- Discovery cache and HTTP client have the same lifetime and owner — no partial invalidation

**Trade-offs:**
- No connection pooling across clients — applications with many client instances make independent TCP connections per client; for most healthcare FHIR use cases (one or a few servers) this is not a significant concern
- Each `Safire::Client.new` allocates a new Faraday connection object, even before any network call; this is a minor allocation cost mitigated by lazy protocol client construction (see [ADR-006]({% link adr/ADR-006-lazy-discovery.md %}))
