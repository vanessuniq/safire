---
layout: default
title: "ADR-007: HTTPS-only redirect enforcement and localhost exception"
parent: Architecture Decision Records
nav_order: 7
---

# ADR-007: HTTPS-only redirect enforcement and localhost exception

**Status:** Accepted

---

## Context

SMART App Launch 2.2.0 requires TLS for all exchanges involving sensitive data. However, enforcing HTTPS at the URI validation layer (`ClientConfig`) is not sufficient on its own — an authorization server could respond to a legitimate HTTPS request with a redirect to an HTTP endpoint. Without enforcement at the HTTP layer, Safire would silently follow that redirect, potentially exposing tokens or authorization codes over an unencrypted connection.

This is a known attack surface: a compromised or misconfigured server can use open redirects to redirect a client to an attacker-controlled HTTP endpoint.

There is also a practical concern: developers running local FHIR servers (e.g. HAPI FHIR, Inferno test environments) use `http://localhost` or `http://127.0.0.1`. Blocking these in a development environment would make Safire unusable without a TLS termination proxy.

---

## Decision

HTTPS is enforced at **two layers**, both with the same localhost exception:

**Layer 1 — `ClientConfig` URI validation:** all URI attributes (`base_url`, `redirect_uri`, `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`) must use `https://`, except when the host is `localhost` or `127.0.0.1`.

**Layer 2 — `HttpsOnlyRedirects` Faraday middleware:** intercepts every 3xx response before `faraday-follow_redirects` follows it. If the redirect target is not HTTPS (and not localhost), a `Safire::Errors::NetworkError` is raised immediately rather than following the redirect.

```ruby
# middleware/https_only_redirects.rb
def on_complete(env)
  return unless redirect?(env)

  location = env.response_headers['location']
  uri = URI.parse(location)
  return if uri.scheme == 'https' || localhost?(uri.host)

  raise Safire::Errors::NetworkError,
        "Blocked redirect to non-HTTPS URL: #{location}"
end
```

Both layers use the same localhost exception (`localhost` and `127.0.0.1`) and must stay consistent. The middleware raises `NetworkError` (transport layer) rather than `ConfigurationError` (construction time) because redirect enforcement is a runtime concern.

---

## Consequences

**Benefits:**
- Defence-in-depth: HTTPS is enforced at both config time and at every HTTP redirect, closing the redirect-based attack vector
- Consistent localhost exception across both enforcement points — `http://localhost` works in both URI validation and redirect following
- Clear error message when a non-HTTPS redirect is blocked, pointing directly at the offending URL

**Trade-offs:**
- The localhost exception must be maintained in two places — `ClientConfig#localhost_host?` and `HttpsOnlyRedirects` — any change to the exception policy must be applied to both; this duplication is intentional (the two layers are independent defences) but must be kept in sync
- Blocking non-HTTPS redirects can cause unexpected failures if a FHIR server uses HTTP-to-HTTPS redirect chains (e.g. `http://fhir.example.com` → `https://fhir.example.com`); callers should configure `base_url` with the final HTTPS URL directly
