---
layout: default
title: UDAP
nav_order: 5
permalink: /udap/
description: "UDAP Security STU2 discovery and registration-metadata validation in Safire, with community scoping and planned signing, authentication, and authorization flows."
has_children: true
---

# UDAP

{: .no_toc }

<div class="code-example" markdown="1">
**Implemented now:** UDAP Security STU2 discovery (`/.well-known/udap`),
including signed metadata validation and optional community scoping. The
[Dynamic Client Registration guide]({% link udap/dynamic-client-registration/index.md %})
also covers the implemented registration-metadata validation foundation.
Software-statement signing, registration submission, JWT client authentication,
and Tiered OAuth remain planned. See
[ROADMAP.md](https://github.com/vanessuniq/safire/blob/main/ROADMAP.md).
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

UDAP (Unified Data Access Profiles) is a security framework for healthcare data exchange defined by the [UDAP Security STU2 / v2.0.0 Implementation Guide](https://hl7.org/fhir/us/udap-security/STU2/index.html). It extends standard OAuth 2.0 with X.509 certificate-based identity, dynamic client registration, and trust community models, designed primarily for backend system-to-system integration and cross-organizational data access.

UDAP is a separate protocol from SMART. In Safire, select it via `protocol: :udap` rather than a `client_type:`.

```ruby
client = Safire::Client.new(
  { base_url: 'https://fhir.example.com' },
  protocol: :udap
)
```

`client_type:` is not applicable to UDAP. Passing one explicitly, or assigning `client.client_type = ...` on a UDAP client, raises `Safire::Errors::ConfigurationError`.

---

## Discovery

UDAP server metadata discovery fetches `/.well-known/udap`, validates the `signed_metadata` JWT, and merges the authoritative signed endpoint claims into a `UdapMetadata` object. Results are cached per community and trust policy within a client instance. Cache hits revalidate the cached `signed_metadata` before returning; if the JWT, certificate chain, or revocation policy no longer validates, Safire discards the cached entry and refetches discovery metadata.

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

Results are cached separately per community and trust policy. Calling `server_metadata` with different community, `trusted_anchors`, `crls`, or `revocation_checker` arguments uses a separate cache entry, and each cached entry is revalidated before reuse.

### Validation helpers

`UdapMetadata#valid?` checks the structure and STU2 value rules in the discovered JSON. It verifies required fields, fixed STU2 values such as `udap_versions_supported == ["1"]`, required profile advertisements, array types, conditional fields, and endpoint URL shape. It logs warnings and returns `false` for non-conformant metadata.

```ruby
metadata = client.server_metadata(trusted_anchors: [ca_cert], crls: [ca_crl])

unless metadata.valid?
  # Safire.logger.warn has already logged each conformance violation.
  raise 'UDAP metadata is structurally non-conformant'
end
```

`server_metadata` already validates `signed_metadata` before returning. Use `signed_metadata_valid?` when you need to re-check an existing metadata object against a different trust policy:

```ruby
metadata.signed_metadata_valid?(
  base_url:         'https://fhir.example.com',
  trusted_anchors: [alternate_ca],
  crls:            [alternate_crl]
)
```

Support helpers expose advertised profiles and usable discovery capabilities.
Capability helpers combine profile or grant signals with the endpoint
preconditions Safire can verify during discovery. These describe what the
server advertises; Safire's DCR metadata validator is available, while DCR
signing/submission, JWT client authentication, and Tiered OAuth remain planned.

| Helper | Checks |
|--------|--------|
| `supports_dynamic_registration?` | `udap_dcr` profile and a valid HTTPS `registration_endpoint` |
| `supports_jwt_client_auth?` | `udap_authn` profile and a valid HTTPS `token_endpoint` |
| `supports_client_authorization?` | `udap_authz` profile, `client_credentials` grant, and a valid HTTPS `token_endpoint` |
| `supports_authorization_code?` | `authorization_code` appears in `grant_types_supported` |
| `supports_refresh_token?` | `refresh_token` appears in `grant_types_supported` |
| `supports_tiered_oauth?` | `udap_to` profile is advertised |
| `supports_signed_metadata?` | `signed_metadata` is present in compact-JWS format |

```ruby
metadata.supports_dynamic_registration?
metadata.supports_jwt_client_auth?
metadata.supports_client_authorization?
metadata.supports_authorization_code?
metadata.supports_refresh_token?
metadata.supports_tiered_oauth?
metadata.supports_signed_metadata?
```

Profile-only helpers check only whether a profile string appears in `udap_profiles_supported`; they do not check endpoints or grant types. Use these when you need to inspect the raw advertisement separately from capability readiness.

```ruby
metadata.dynamic_registration_profile?
metadata.jwt_client_auth_profile?
metadata.client_authorization_profile?
metadata.tiered_oauth_profile?
```

### Error handling

| Condition | Error raised |
|-----------|-------------|
| HTTP 404 | `Safire::Errors::DiscoveryError` with `status` set to `404`; per STU2, clients should treat this as "UDAP workflows are not supported" |
| Other HTTP 4xx/5xx | `Safire::Errors::DiscoveryError` with `status` populated |
| Server returns HTTP 204 | `Safire::Errors::DiscoveryError` (server signals no UDAP workflows for the requested community) |
| `signed_metadata` JWT validation fails | `Safire::Errors::DiscoveryError` (invalid signature, chain, revocation status, endpoint claim, or missing required claim) |
| Malformed DER certificate in `x5c` header | `Safire::Errors::CertificateError` |
| Connection failure, timeout, SSL error, or redirect to a non-HTTPS URL | `Safire::Errors::NetworkError` |
| `community:` is not a valid URI string | `Safire::Errors::ConfigurationError` (raised before any HTTP call) |

---

## Planned Features

### Client Flows

- **Dynamic Client Registration (DCR)** — metadata validation is implemented;
  software-statement signing and submission remain planned for the one-time
  registration that obtains a `client_id`
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
- [UDAP Tiered OAuth](https://hl7.org/fhir/us/udap-security/STU2/user.html) — Tiered OAuth for User Authentication
