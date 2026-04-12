---
layout: default
title: "ADR-010: client_id optional at initialization — deferred validation for the DCR temp-client pattern"
parent: Architecture Decision Records
nav_order: 10
---

# ADR-010: client_id optional at initialization — deferred validation for the DCR temp-client pattern

**Status:** Accepted

---

## Context

RFC 7591 Dynamic Client Registration requires calling the authorization server's registration endpoint before a `client_id` exists. The natural usage pattern is:

1. Create a temporary `Safire::Client` with only `base_url` (no `client_id` yet)
2. Call `register_client` to POST metadata and receive `client_id` from the server
3. Build a properly configured client with the returned `client_id` for subsequent authorization flows

Previously, `ClientConfig#validate!` required `client_id` to be present at construction time. A caller following the temp-client pattern could not even construct the initial client, so DCR was impossible without out-of-band `client_id` knowledge.

**Option A — Keep client_id required; provide a separate class:** introduce a `Safire::RegistrationClient` (or similar) that omits the `client_id` requirement, performs DCR, and returns a configured `Safire::Client`.

**Option B — Make client_id optional at initialization; validate at call time:** remove the construction-time presence check for `client_id`; each flow method that requires it validates and raises `ConfigurationError` at the point of the call.

---

## Decision

Option B — `client_id` is optional at `ClientConfig` and `Client` initialization.

Construction succeeds with only `base_url`:

```ruby
temp_client = Safire::Client.new({ base_url: 'https://fhir.example.com' })
registration = temp_client.register_client({ client_name: 'My App', ... })

client = Safire::Client.new({
  base_url:  'https://fhir.example.com',
  client_id: registration['client_id'],
  ...
})
```

Flow methods that require `client_id` (`authorization_url`, `request_access_token`, `request_backend_token`) validate its presence at call time and raise `ConfigurationError` if absent.

---

## Consequences

**Benefits:**
- The temp-client pattern works with the existing `Safire::Client` class; no new class is needed
- No proliferation of client variants; the public API surface stays small
- Consistent with how `token_endpoint` and `authorization_endpoint` are handled: both are optional at construction and resolved via lazy discovery when needed

**Trade-offs:**
- A misconfigured client (missing `client_id`) fails at call time rather than construction time; callers may see the error later than expected
- This is an intentional trade-off: `client_id` is now in the same category as other lazily-resolved attributes, so the surprise of deferred validation is mitigated by the established pattern
