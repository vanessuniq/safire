---
layout: default
title: "ADR-008: Warn and return false for compliance validation — raise only for configuration errors"
parent: Architecture Decision Records
nav_order: 8
---

# ADR-008: Warn and return false for compliance validation — raise only for configuration errors

**Status:** Accepted

---

## Context

Safire performs two different kinds of checks:

1. **Configuration checks** — validating that the caller has provided a usable configuration (required attributes present, URIs well-formed and HTTPS). These run at construction time and represent programming errors if they fail.

2. **Compliance checks** — validating that a remote server's response conforms to the SMART App Launch 2.2.0 specification. These run at runtime and represent server behaviour, not caller behaviour.

The question is: what should compliance checks do when they find a violation?

**Option A — Raise an exception:** `token_response_valid?` raises `TokenError`; `SmartMetadata#valid?` raises `DiscoveryError`. The caller must rescue.

**Option B — Warn and return false:** log a warning via `Safire.logger` for each violation found, then return `false`. Never raise.

Option A treats a non-compliant server as an unrecoverable error. In practice, some production FHIR servers have minor token response non-compliance (e.g. returning `token_type: "BEARER"` instead of the spec-required value) but are otherwise functional. Raising an exception would prevent Safire from working with those servers entirely, with no way for callers to override the decision.

Option B lets the caller decide what to do: they can check the return value, observe the warnings in their logs, and choose to proceed or abort. This is consistent with how Ruby standard library methods (e.g. `URI.parse`, `JSON.parse` with `rescue nil`) handle validation — surface the issue, let the caller decide.

There is also a clear boundary: **the caller controls the config** (configuration errors should raise — the caller can fix them); **the server controls the response** (compliance violations should warn — the caller cannot fix a remote server).

---

## Decision

Compliance validation methods use the **warn + return false** pattern:

```ruby
def token_response_valid?(response, flow: :app_launch)
  # ...
  Safire.logger.warn("SMART token response non-compliance: token_type is #{...}; expected 'Bearer' (SMART App Launch spec)")
  false
end

def valid?  # SmartMetadata
  # ...
  Safire.logger.warn("SMART metadata non-compliance: 'S256' not in code_challenge_methods_supported")
  false
end
```

These methods:
- Never raise an exception
- Log one warning per violation (not a single combined message) so each issue is individually observable
- Return `true` only when fully compliant; `false` as soon as any violation is found
- Are **user-callable** — they are not invoked automatically by `authorization_url` or `server_metadata`; callers opt in to compliance checking

Configuration validation (`ClientConfig#validate!`, `Smart#validate!`) raises `ConfigurationError` — these are programming errors that must be fixed before the gem can function.

---

## Consequences

**Benefits:**
- Safire can interoperate with non-compliant but functional FHIR servers; callers choose whether to enforce strict compliance
- Each violation produces a separate, actionable log line rather than a single combined error
- Callers can implement their own compliance gate: `raise unless client.token_response_valid?(response)`
- Consistent with the principle of least surprise — a compliance check method that raises on failure is not useful as a boolean check

**Trade-offs:**
- Callers who do not call `token_response_valid?` get no compliance signal at all — non-compliant responses are silently accepted; this is intentional (opt-in, not opt-out)
- The distinction between "warn + return false" and "raise" must be maintained consistently — new validation methods should follow the same rule: server behaviour → warn; caller configuration → raise
- `token_response_valid?` accepts a `flow:` keyword argument (`:app_launch` default, `:backend_services`) that adjusts which fields are required and what the warning messages say. For example, `token_type` must be `"Bearer"` (App Launch spec) or `"bearer"` (Backend Services spec), and `expires_in` is RECOMMENDED for App Launch but REQUIRED for Backend Services. Callers opt in to the stricter backend-services validation by passing `flow: :backend_services`
