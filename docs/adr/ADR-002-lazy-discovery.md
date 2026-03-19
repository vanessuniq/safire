---
layout: default
title: "ADR-002: Lazy SMART discovery — no HTTP in constructors"
parent: Architecture Decision Records
nav_order: 2
---

# ADR-002: Lazy SMART discovery — no HTTP in constructors

**Status:** Accepted

---

## Context

SMART on FHIR clients need the authorization server's endpoints (`authorization_endpoint`, `token_endpoint`) to build authorization URLs and request tokens. These are obtained by fetching `/.well-known/smart-configuration`. There are two approaches:

**Option A — eager discovery:** fetch metadata in `Smart#initialize`.

```ruby
def initialize(config, client_type: :public)
  # ...
  @server_metadata = fetch_metadata  # HTTP call here
end
```

**Option B — lazy discovery:** defer the fetch until a method actually needs an endpoint.

```ruby
def server_metadata
  @server_metadata ||= fetch_metadata  # HTTP call deferred
end

def authorization_endpoint
  @authorization_endpoint ||= server_metadata.authorization_endpoint
end
```

Eager discovery has a significant problem: it makes `Safire::Client.new` a network operation. Construction can fail with a network error, configuration validation occurs after a potentially slow HTTP round-trip, and there is no way to instantiate a client to inspect its configuration without triggering discovery. It also makes testing harder — every `Client.new` call requires a stub.

A second concern is `client_type=` mutation. After discovery, a caller may want to switch client type based on what the server supports:

```ruby
client   = Safire::Client.new(config)
metadata = client.server_metadata

client.client_type = :confidential_symmetric if metadata.supports_symmetric_auth?
```

With eager discovery, changing `client_type` must not trigger re-discovery — the metadata is already fetched. This means decoupling the discovery result from construction is necessary regardless.

---

## Decision

Discovery is lazy and memoised at the `Protocols::Smart` instance level:

```ruby
def server_metadata
  return @server_metadata if @server_metadata

  response = @http_client.get(well_known_endpoint)
  @server_metadata = SmartMetadata.new(parse_discovery_body(response.body))
end
```

`authorization_endpoint` and `token_endpoint` are also lazy — they fall back to `server_metadata` only when not manually configured in `ClientConfig`, avoiding a discovery call for clients with pre-known endpoints.

`Safire::Client` memoises the protocol client itself (`@protocol_client ||= ...`), so changing `client_type=` reuses the existing `Protocols::Smart` instance — and thus its already-fetched `@server_metadata` — rather than constructing a new one. This is the mechanism that prevents double-discovery on `client_type=` changes.

---

## Consequences

**Benefits:**
- `Safire::Client.new` is instantaneous — no network calls, no stubs required at construction time
- Configuration errors are raised before any HTTP call
- Callers control when discovery happens — supports application-level caching patterns (see [Advanced Examples]({{ site.baseurl }}/advanced/#metadata-caching))
- `client_type=` mutation preserves cached metadata — no re-discovery

**Trade-offs:**
- Discovery errors surface at first use (e.g. `authorization_url`), not at construction — callers must handle `Errors::DiscoveryError` in their flow logic rather than at the `new` call site
- In-process metadata caching is per-instance only — across requests in a web app, callers must implement application-level caching (e.g. `Rails.cache`) to avoid repeated discovery HTTP calls
