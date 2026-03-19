---
layout: default
title: "ADR-004: ClientConfig immutability and Entity sensitive attribute masking"
parent: Architecture Decision Records
nav_order: 4
---

# ADR-004: `ClientConfig` immutability and `Entity` sensitive attribute masking

**Status:** Accepted

---

## Context

`ClientConfig` holds all credentials and endpoints for a Safire client — including `client_secret` and `private_key`. Two separate concerns need to be addressed:

**Concern 1 — Mutability:** should `ClientConfig` allow attributes to be changed after construction?

Mutable configuration creates subtle bugs in concurrent environments: a `ClientConfig` instance shared across threads could have its `client_secret` changed mid-request. It also makes it impossible to reason about the state of a client at any point after construction, because any attribute may have been changed.

**Concern 2 — Sensitive data leakage:** Ruby's default `inspect` and `to_s` output every instance variable. In a Rails application, an unhandled exception containing a `ClientConfig` would dump `client_secret` and `private_key` into error logs, exception trackers (Sentry, Datadog), and any other logging middleware.

These two concerns are related: if `ClientConfig` is mutable, masking is harder to guarantee (a new value could be assigned via a setter without going through the masking layer).

---

## Decision

**`ClientConfig` is immutable after construction.** All attributes are `attr_reader` only — no setters. Validation runs once at construction. After `initialize` returns, the object's state cannot change.

**Sensitive attributes are masked at two layers** via the `Entity` base class:

**Layer 1 — `#to_hash`:** the `sensitive_attributes` hook (overridden in `ClientConfig` to return `[:client_secret, :private_key]`) causes those values to appear as `'[FILTERED]'` in any hash serialisation.

```ruby
def to_hash
  ATTRIBUTES.each_with_object({}) do |attr, hash|
    value = send(attr)
    hash[attr] = sensitive_attributes.include?(attr) ? '[FILTERED]' : value
  end
end
```

**Layer 2 — `#inspect`:** `ClientConfig` overrides `inspect` directly, emitting `[FILTERED]` for sensitive attributes. This prevents credential leakage in exception backtraces, IRB/pry sessions, and logging middleware that calls `inspect` on objects.

---

## Consequences

**Benefits:**
- Thread-safe by default — a `ClientConfig` shared across threads has no mutable state
- Credentials cannot leak through `inspect`, `to_s`, exception trackers, or log output
- Validation at construction means invalid configs are caught early, before any network calls
- The `sensitive_attributes` hook is extensible — subclasses can add fields without modifying `Entity`

**Trade-offs:**
- Callers cannot modify a `ClientConfig` in place — they must construct a new one; this is intentional and makes state changes explicit
- `private_key` masking means the key object itself is not serialisable via `to_hash` — callers needing to inspect or store the key must access it directly via `config.private_key`
