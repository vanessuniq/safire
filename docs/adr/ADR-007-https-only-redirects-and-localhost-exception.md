---
layout: default
title: "ADR-007: HTTPS-only enforcement and explicit localhost opt-in"
parent: Architecture Decision Records
nav_order: 7
---

# ADR-007: HTTPS-only enforcement and explicit localhost opt-in

**Status:** Accepted

---

## Context

SMART App Launch 2.2.0 requires TLS for all exchanges involving sensitive data. However, enforcing HTTPS at the URI validation layer (`ClientConfig`) is not sufficient on its own — an authorization server could respond to a legitimate HTTPS request with a redirect to an HTTP endpoint. Without enforcement at the HTTP layer, Safire would silently follow that redirect, potentially exposing tokens or authorization codes over an unencrypted connection.

This is a known attack surface: a compromised or misconfigured server can use open redirects to redirect a client to an attacker-controlled HTTP endpoint.

There is also a practical concern: developers running local FHIR servers (e.g.
HAPI FHIR, Inferno test environments) use `http://localhost` or
`http://127.0.0.1`. Blocking these entirely would make Safire awkward to use
without a TLS termination proxy, but accepting them implicitly weakens a
security boundary and can hide production misconfiguration.

---

## Decision

For SMART configuration and HTTP redirects, HTTPS is enforced at **two layers**.
Both layers use the same explicit local-development opt-in:

**Layer 1 — `ClientConfig` URI validation:** all URI attributes (`base_url`, `redirect_uri`, `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`) must use `https://`, except when `allow_insecure_localhost: true` is configured and the host is `localhost` or `127.0.0.1`.

**Layer 2 — `HttpsOnlyRedirects` Faraday middleware:** intercepts every 3xx response before `faraday-follow_redirects` follows it. If the redirect target is not HTTPS, and the local-development exception is not enabled for a loopback host, a `Safire::Errors::NetworkError` is raised immediately rather than following the redirect.

```ruby
# middleware/https_only_redirects.rb
def on_complete(env)
  return unless redirect?(env)

  location = env.response_headers['location']
  uri = URI.parse(location)
  return if uri.scheme == 'https'
  return if allow_insecure_localhost && localhost?(uri.host)

  raise Safire::Errors::NetworkError,
        "Blocked redirect to non-HTTPS URL: #{location}"
end
```

Both layers use the same loopback host set (`localhost` and `127.0.0.1`) and
must stay consistent. The middleware raises `NetworkError` (transport layer)
rather than `ConfigurationError` (construction time) because redirect
enforcement is a runtime concern.

UDAP registration metadata applies the same secure default to its registration
URI fields. The UDAP Security STU2 registration profile requires
`redirect_uris` and `logo_uri` to use HTTPS.
`URIValidation#strict_https_uri?` provides that default predicate, while
`URIValidation#localhost_http_uri?` identifies the only local HTTP shape that
can be accepted when a caller explicitly opts into development mode.

`UdapRegistrationMetadata` uses the same explicit option name for non-TLS local
redirect and logo URIs. It accepts only HTTP on `localhost` or `127.0.0.1`,
logs a development-only warning when used, and never permits remote HTTP.
Safire does not infer Rails, Rack, or another framework's environment; the host
application must opt in deliberately. Metadata produced through this exception
is non-conformant and must not be used in production.

---

## Consequences

**Benefits:**
- Defence-in-depth: HTTPS is enforced at both config time and at every HTTP redirect, closing the redirect-based attack vector
- Consistent explicit localhost opt-in across config validation, redirect following,
  and UDAP registration metadata
- UDAP registration fields remain strict by default while non-TLS local testing
  requires an explicit, narrowly scoped opt-in
- Clear error message when a non-HTTPS redirect is blocked, pointing directly at the offending URL

**Trade-offs:**
- The loopback host set must be maintained in two places —
  `URIValidation#localhost_host?` and `HttpsOnlyRedirects` — any change to the
  host policy must be applied to both; this duplication is intentional (the two
  layers are independent defences) but must be kept in sync
- Callers enabling the local-development exception are responsible for tying it
  to their application's environment and preventing production use
- Blocking non-HTTPS redirects can cause unexpected failures if a FHIR server uses HTTP-to-HTTPS redirect chains (e.g. `http://fhir.example.com` → `https://fhir.example.com`); callers should configure `base_url` with the final HTTPS URL directly
