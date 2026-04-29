---
layout: default
title: "ADR-002: Facade pattern — Client delegates to protocol implementations via Forwardable"
parent: Architecture Decision Records
nav_order: 2
---

# ADR-002: Facade pattern — `Client` delegates to protocol implementations via `Forwardable`

**Status:** Accepted

---

## Context

Safire must support multiple authorization protocols (SMART App Launch, UDAP) from a single public entry point. There are several ways to structure this:

**Option A — Monolithic `Client`:** implement all protocol logic directly inside `Safire::Client`. Simple at first, but grows unbounded as each protocol adds methods, and makes it impossible to test protocol logic in isolation.

**Option B — Inheritance:** `Safire::Client` is an abstract base class; `SmartClient` and `UdapClient` subclass it. Callers would instantiate the concrete subclass. This leaks implementation details to callers (they must know which subclass to pick) and makes the `protocol:` keyword redundant.

**Option C — Strategy pattern via instance variable:** `Client` holds a `@protocol_client` strategy object and calls it manually in every method. Works, but every delegated method requires a boilerplate wrapper with the same `def method_name(...); @protocol_client.method_name(...); end` pattern.

**Option D — Facade with `Forwardable`:** `Client` is a thin facade. It resolves configuration, validates `protocol:` and `client_type:`, constructs the appropriate protocol implementation lazily, and then delegates all public methods to it using Ruby's `Forwardable` module.

The core requirement that drives the choice is: **callers must use a single, stable class (`Safire::Client`) regardless of which protocol they need.** Adding a new protocol must not change the public API or require callers to change their code.

---

## Decision

`Safire::Client` is a facade. It owns:
- Configuration resolution (hash → `ClientConfig`)
- Protocol and client type validation
- Lazy construction of the protocol implementation (`@protocol_client`)
- Delegation of all public protocol methods via `Forwardable`

```ruby
class Client
  extend Forwardable

  def_delegators :protocol_client,
                 :server_metadata, :authorization_url,
                 :request_access_token, :refresh_token,
                 :request_backend_token,
                 :token_response_valid?, :register_client

  private

  def protocol_client
    @protocol_client ||= build_protocol_client
  end

  def build_protocol_client
    case @protocol
    when :smart then Protocols::Smart.new(config, client_type:)
    when :udap  then raise NotImplementedError, 'UDAP protocol client is not yet implemented'
    end
  end
end
```

Protocol implementations (`Protocols::Smart`, `Protocols::Udap`) include `Protocols::Behaviours` to declare the required interface. Adding a new protocol requires:
1. Implementing the `Behaviours` interface in a new class
2. Adding a `when` branch to `build_protocol_client` in `Client`
3. Adding its valid client types to `PROTOCOL_CLIENT_TYPES`

The original design aimed for "no changes to `Client` itself" when adding a protocol. That invariant was intentionally relaxed: protocols have different constructor signatures (`Smart` takes `client_type:`, `Udap` does not), and a small explicit `case` in `build_protocol_client` is preferable to forcing every protocol into a uniform constructor it does not need.

**Why `Forwardable` over `method_missing`:** `Forwardable` is explicit — the delegated method list is visible in the class body, easy to grep, and YARD-documented. `method_missing` is implicit, difficult to introspect, and catches typos silently.

**Why `Forwardable` over manual wrappers:** manual wrappers require writing the same boilerplate for every method and must be updated whenever a method signature changes. `def_delegators` is a single declaration.

---

## Consequences

**Benefits:**
- Public API (`Safire::Client`) is stable — callers never need to change when a new protocol is added
- Protocol implementations are independently testable
- `Forwardable` delegation is explicit and greppable
- The `protocol:` keyword cleanly selects the implementation class without leaking subclass names to callers
- `client_type=` mutation works naturally — the facade updates `@protocol_client` in place (see [ADR-006]({% link adr/ADR-006-lazy-discovery.md %}) for why this preserves cached discovery)

**Trade-offs:**
- `Client` itself has no runtime behaviour — all logic lives in protocol classes; contributors must know to look in `Protocols::Smart` for SMART logic, not in `Client`
- `def_delegators` does not forward keyword arguments transparently in all Ruby versions — method signatures in `Behaviours` must be compatible with delegation
- Adding a new protocol requires a one-line change to `build_protocol_client` in `Client`; this is a small, contained cost that buys protocol-specific constructor freedom
