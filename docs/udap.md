---
layout: default
title: UDAP
nav_order: 5
permalink: /udap/
description: "UDAP Security STU2 server metadata discovery in Safire, with community-scoped discovery, plus planned auth flows including dynamic client registration, JWT client authentication, and tiered OAuth."
---

# UDAP

{: .no_toc }

<div class="code-example" markdown="1">
**Discovery** (`/.well-known/udap`) is implemented, including optional community scoping. Auth flows (DCR, JWT assertion, Tiered OAuth) are planned. See [ROADMAP.md](https://github.com/vanessuniq/safire/blob/main/ROADMAP.md).
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

UDAP (Unified Data Access Profiles) is a security framework for healthcare data exchange defined by the [UDAP Security STU2 / v2.0.0 Implementation Guide](https://hl7.org/fhir/us/udap-security/STU2/index.html). It extends standard OAuth 2.0 with X.509 certificate-based identity, dynamic client registration, and trust community models, designed primarily for backend system-to-system integration and cross-organizational data access.

UDAP is a separate protocol from SMART. In Safire, select it via `protocol: :udap` rather than a `client_type:`.

---

## Discovery

UDAP server metadata discovery fetches `/.well-known/udap`, validates the `signed_metadata` JWT, and merges the authoritative signed endpoint claims into a `UdapMetadata` object. Results are cached per community and trust policy within a client instance, so repeated calls for the same community with the same trust configuration make at most one HTTP request.

### Trust anchors and revocation

Per UDAP Security STU2, `signed_metadata` JWT signature, X.509 chain verification, and certificate revocation status checking are performed on every production discovery call. Provide your trust anchors as `OpenSSL::X509::Certificate` objects and either CRLs as `OpenSSL::X509::CRL` objects or a custom `revocation_checker:`:

```ruby
ca_cert = OpenSSL::X509::Certificate.new(File.read('udap_ca.pem'))
ca_crl  = OpenSSL::X509::CRL.new(File.read('udap_ca.crl'))

client = Safire::Client.new(
  { base_url: 'https://fhir.example.com' },
  protocol: :udap
)

metadata = client.server_metadata(
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
puts metadata.token_endpoint
puts metadata.udap_versions_supported.inspect
puts metadata.udap_profiles_supported.inspect
```

{: .note }
> **Development and testing**: Pass `verify_chain: false` to skip X.509 chain and revocation validation when working with self-signed certificates or local servers that do not have a CA-issued UDAP certificate. Never use `verify_chain: false` in production.
>
> ```ruby
> metadata = client.server_metadata(verify_chain: false)
> ```

### Community-scoped discovery

Many UDAP servers host multiple trust communities at the same base URL, each scoped by a community URI. Pass `community:` to target a specific community:

```ruby
metadata = client.server_metadata(
  community:       'https://udap.example.org/community1',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
puts metadata.token_endpoint
```

Results are cached separately per community and trust policy, so calling `server_metadata` with different community, `trusted_anchors`, `crls`, or `revocation_checker` arguments each makes at most one HTTP request for that combination.

### Error handling

| Condition | Error raised |
|-----------|-------------|
| HTTP 4xx/5xx | `Safire::Errors::DiscoveryError` with `status` populated |
| Server returns HTTP 204 | `Safire::Errors::DiscoveryError` (server signals no UDAP workflows for that community) |
| `signed_metadata` JWT validation fails | `Safire::Errors::DiscoveryError` (invalid signature, chain, revocation status, endpoint claim, or missing required claim) |
| Malformed DER certificate in `x5c` header | `Safire::Errors::CertificateError` |
| Connection failure, timeout, SSL error, or redirect to a non-HTTPS URL | `Safire::Errors::NetworkError` |
| `community:` is not a valid URI string | `Safire::Errors::ConfigurationError` (raised before any HTTP call) |

---

## Planned Features

### Client Flows

- **Dynamic Client Registration (DCR)** — one-time registration using a signed software statement to obtain a `client_id`; required only when the client has not previously registered with the server and the server supports DCR
- **JWT Client Authentication** — authenticate on every request using a signed JWT assertion (Authentication Token, AnT) with an X.509 certificate chain in the `x5c` header; the registered `client_id` is reused as `iss` and `sub` in each assertion
- **Tiered OAuth** — delegated authorization for multi-system access per the UDAP Security IG
- **Pushed Authorization Requests (RFC 9126)** — PAR support for pre-registering authorization requests

### Trust Framework

- **Client certificate trust management** — apply trust anchors and community policy to future
  UDAP client authentication and registration flows
- **Trust Community Support** — integration with UDAP trust communities (e.g. Carequality, CommonWell)

---

## Comparison with SMART

| Feature | SMART | UDAP |
|---------|-------|------|
| Primary use case | User-facing apps, EHR launch | B2B, backend services, cross-org access |
| Client registration | Pre-registered per server, optional DCR (recommended) | Dynamic (DCR) or pre-registered |
| Authentication | Client secrets or `private_key_jwt` | Signed JWT assertions (AnT) with X.509 `x5c` chain |
| Trust model | Per-server registration | Certificate-based trust communities |
| Safire selection | `client_type: :public / :confidential_symmetric / :confidential_asymmetric` | `protocol: :udap` |

### When to use UDAP

| Scenario | Why UDAP |
|----------|----------|
| **Backend / B2B Integration** | Server-to-server flows without user interaction; certificate-based identity replaces pre-shared secrets |
| **Dynamic Client Registration** | Clients can register programmatically without manual server-side approval |
| **Cross-Organization Access** | Trust communities allow clients to be recognized across participant organizations without per-server registration |
| **High-Assurance Identity** | X.509 certificates provide stronger identity guarantees than client secrets |

### Resources

- [UDAP Security STU2 / v2.0.0 IG](https://hl7.org/fhir/us/udap-security/STU2/index.html) — HL7 Implementation Guide
- [UDAP JWT Client Auth](https://www.udap.org/udap-jwt-client-auth.html) — JWT assertion specification
- [UDAP Dynamic Client Registration](https://www.udap.org/udap-dynamic-client-registration.html) — DCR specification
- [RFC 9126 — Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [UDAP Tiered OAuth](https://hl7.org/fhir/us/udap-security/STU2/b2b.html) — Delegated authorization
