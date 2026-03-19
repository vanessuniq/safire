---
layout: default
title: "ADR-001: protocol: and client_type: as orthogonal dimensions"
parent: Architecture Decision Records
nav_order: 1
---

# ADR-001: `protocol:` and `client_type:` as orthogonal dimensions

**Status:** Accepted

---

## Context

`Safire::Client` needs to support multiple healthcare authorization protocols (SMART on FHIR, UDAP) and, within SMART, multiple client authentication methods (public, confidential symmetric, confidential asymmetric). There are two ways to model this:

**Option A — flat enum:** a single parameter enumerating every combination.

```ruby
Safire::Client.new(config, auth: :smart_public)
Safire::Client.new(config, auth: :smart_confidential_symmetric)
Safire::Client.new(config, auth: :udap_b2b)
```

**Option B — two orthogonal keyword arguments:** one for the protocol, one for the client type within that protocol.

```ruby
Safire::Client.new(config, protocol: :smart, client_type: :public)
Safire::Client.new(config, protocol: :smart, client_type: :confidential_symmetric)
Safire::Client.new(config, protocol: :udap)  # client_type not applicable
```

The key structural difference: SMART has three client authentication methods; UDAP has none — UDAP always authenticates via signed JWT assertions (AnT) with an X.509 certificate chain, and this is not user-configurable. Mixing them into one flat enum would create invalid combinations (`:udap_public`, `:udap_confidential_symmetric`) and make `client_type=` mutation impossible to express cleanly.

---

## Decision

Two orthogonal keyword arguments: `protocol:` selects the protocol implementation class; `client_type:` is a SMART-specific parameter that controls the token endpoint authentication method.

```ruby
VALID_PROTOCOLS = %i[smart udap].freeze

PROTOCOL_CLIENT_TYPES = {
  smart: %i[public confidential_symmetric confidential_asymmetric],
  udap:  nil   # not user-configurable; AnT with x5c always used
}.freeze
```

- `protocol:` is validated against `VALID_PROTOCOLS`; an unknown protocol raises `ConfigurationError`
- `client_type:` is validated against `PROTOCOL_CLIENT_TYPES[@protocol]`; if `nil` (UDAP), validation is skipped and the setter logs a warning and no-ops rather than raising
- Changing `client_type=` on a SMART client updates the underlying protocol client in place — already-fetched server metadata is preserved and no re-discovery occurs

---

## Consequences

**Benefits:**
- No invalid combinations — UDAP has no client type choices at all; this is enforced at the type level, not with runtime checks
- `client_type=` mutation is clean and natural for the "discover first, then select client type" pattern
- Adding a new SMART client type requires only adding a symbol to `PROTOCOL_CLIENT_TYPES[:smart]`
- Adding a new protocol requires adding a class to `PROTOCOL_CLASSES` and an entry to `PROTOCOL_CLIENT_TYPES`

**Trade-offs:**
- Two keyword args instead of one — a caller needs to know which dimension belongs to which kwarg; mitigated by clear documentation and validation errors that name the invalid parameter
- `client_type:` defaults to `:public` even when `protocol: :udap` — the value is ignored for UDAP, but setting it is technically a no-op with a warning rather than an error; this is intentional for resilience in generic caller code
