---
layout: default
title: UDAP
nav_order: 5
permalink: /udap/
description: "UDAP Security STU2 discovery and Dynamic Client Registration in Safire."
has_children: true
---

# UDAP

{: .no_toc }

<div class="code-example" markdown="1">
Safire implements UDAP Security STU2 discovery, signed metadata validation,
community scoping, and certificate-backed Dynamic Client Registration for new
registration, modification, and cancellation. JWT client authentication and
Tiered OAuth remain planned.
</div>

## Overview

UDAP (Unified Data Access Profiles) is a security framework for healthcare data
exchange defined by the
[UDAP Security STU2 / v2.0.0 Implementation Guide](https://hl7.org/fhir/us/udap-security/STU2/index.html).
It adds X.509-based identity, signed metadata, dynamic registration, and trust
community semantics to OAuth-based workflows.

Select UDAP independently from SMART client authentication types:

```ruby
client = Safire::Client.new(
  { base_url: 'https://fhir.example.com' },
  protocol: :udap
)
```

`client_type:` is not applicable to UDAP. Passing one explicitly, or assigning
`client.client_type = ...` on a UDAP client, raises
`Safire::Errors::ConfigurationError`.

## Discovery

`server_metadata` fetches `/.well-known/udap`, validates the required
`signed_metadata` JWT, and merges authoritative signed endpoint claims over
their unsigned JSON counterparts before returning `UdapMetadata`.

### Server trust and revocation

Production discovery requires caller-supplied trust anchors plus an explicit
revocation policy. Use CRLs or a custom checker:

```ruby
ca_cert = OpenSSL::X509::Certificate.new(File.read('udap-ca.pem'))
ca_crl  = OpenSSL::X509::CRL.new(File.read('udap-ca.crl'))

metadata = client.server_metadata(
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

Safire verifies the JWT signature, certificate chain and revocation status,
issuer/SAN relationship, time claims, `jti`, and signed endpoint claims. Results
are cached per community and trust policy, but cache hits revalidate the signed
metadata before reuse. An expired or newly untrusted entry is discarded and
refetched.

{: .warning }
> `verify_chain: false` skips X.509 chain and revocation validation. Use it only
> for development and tests. Local HTTP loopback servers separately require
> `allow_insecure_localhost: true` in `ClientConfig`; this permits HTTP only on
> `localhost` and `127.0.0.1` and is not production UDAP conformance.

### Community-scoped discovery

Pass a trust-community URI when a server supports multiple communities:

```ruby
metadata = client.server_metadata(
  community:       'https://udap.example.org/community1',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

Different community, trust-anchor, CRL, revocation-checker, or chain-verification
arguments use separate cache entries.

### Structural and capability helpers

`UdapMetadata#valid?` checks required fields, exact STU2 fixed values, array and
string types, conditional fields, subset rules, and endpoint URL shape. It logs
each violation and returns `false`; it does not repeat cryptographic validation.

```ruby
unless metadata.valid?
  # Safire.logger.warn has already recorded each structural violation.
  raise 'UDAP metadata is structurally non-conformant'
end
```

Profile-only helpers inspect raw profile advertisements. Capability helpers add
the endpoint or grant preconditions Safire can verify locally:

| Capability helper | Checks |
|-------------------|--------|
| `supports_dynamic_registration?` | `udap_dcr` profile plus a valid `registration_endpoint` |
| `supports_jwt_client_auth?` | `udap_authn` profile plus a valid `token_endpoint` |
| `supports_client_authorization?` | `udap_authz`, `client_credentials`, and a valid `token_endpoint` |
| `supports_authorization_code?` | `authorization_code` grant advertisement |
| `supports_refresh_token?` | `refresh_token` grant advertisement |
| `supports_tiered_oauth?` | `udap_to` profile advertisement |
| `supports_signed_metadata?` | Compact-JWS-shaped `signed_metadata` value |

The corresponding profile helpers are `dynamic_registration_profile?`,
`jwt_client_auth_profile?`, `client_authorization_profile?`, and
`tiered_oauth_profile?`.

Use `signed_metadata_valid?(base_url:, ...)` only when explicitly revalidating
an existing metadata object against another trust policy. Metadata returned by
`server_metadata` is already cryptographically validated.

### Discovery failures

| Condition | Safire behavior |
|-----------|-----------------|
| `404 Not Found` | Raises `DiscoveryError`; clients treat the server as not supporting UDAP workflows |
| `204 No Content` | Raises `DiscoveryError` before body parsing; no UDAP workflow is available for that community |
| Invalid `signed_metadata` | Raises `DiscoveryError` after validation warnings |
| Malformed DER in JOSE `x5c` | Raises `CertificateError` |
| Invalid `community:` | Raises `ConfigurationError` before HTTP |
| Connection, TLS, timeout, or blocked redirect failure | Raises `NetworkError` |

## Dynamic Client Registration

UDAP DCR is discovery-bound. Safire validates discovery metadata, signs
caller-controlled registration metadata into a short-lived X.509-backed
`software_statement`, and POSTs the fixed UDAP envelope to the authoritative
signed `registration_endpoint`.

```ruby
client = Safire::Client.new(
  {
    base_url: 'https://fhir.example.com',
    private_key: File.read('client-key.pem'),
    certificate_chain: [File.read('client-cert.pem')]
  },
  protocol: :udap
)

registration = client.register_client(
  {
    client_name: 'Example Backend Service',
    contacts: ['mailto:security@example.com'],
    grant_types: ['client_credentials'],
    scope: 'system/Patient.rs'
  },
  client_uri:      'https://client.example.com',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

Use `register_client` again with the same client URI and community to request a
modification. Use `cancel_registration` to send a fresh software statement with
an empty `grant_types` array. Safire accepts cancellation only when a successful
response contains a non-blank `client_id` and an empty `grant_types` array.

Pass `certifications:` when required by community policy. Certification and
endorsement JWTs may be signed by the client operator or a third party. Safire
validates their compact-JWS shape but leaves issuer, signature, claims, and
policy evaluation to the authorization server.

See [Dynamic Client Registration]({% link udap/dynamic-client-registration/index.md %})
for prerequisites and public API usage, [Registration Metadata]({% link udap/dynamic-client-registration/registration-metadata.md %})
for input rules, [Software Statements]({% link udap/dynamic-client-registration/software-statement.md %})
for signing behavior, and [Registration Lifecycle]({% link udap/dynamic-client-registration/lifecycle.md %})
for modification and cancellation semantics.

## Scope and Protocol Choice

Safire does not yet implement UDAP JWT client authentication, token acquisition,
authorization-code handling, or Tiered OAuth. Those methods continue to raise
`NotImplementedError` on a UDAP client. Dynamic registration obtains a
`client_id`, but the later UDAP authentication and authorization flows remain
separate roadmap work.

| Feature | SMART App Launch in Safire | UDAP Security in Safire |
|---------|----------------------------|--------------------------|
| Discovery | SMART configuration JSON | Signed UDAP metadata with X.509 trust validation |
| Dynamic registration | RFC 7591 metadata request | STU2 X.509-backed software statement |
| Implemented client flows | App Launch and Backend Services | Registration lifecycle only |
| Client selection | `client_type:` | `protocol: :udap`; no `client_type:` |
| Trust model | Per-server client registration and registered keys/secrets | Certificate trust communities and signed metadata |

Resources:

- [UDAP Security STU2 / v2.0.0 IG](https://hl7.org/fhir/us/udap-security/STU2/index.html)
- [UDAP Dynamic Client Registration STU1](https://www.udap.org/udap-dynamic-client-registration-stu1.html)
- [UDAP Certifications and Endorsements STU1](https://www.udap.org/udap-certifications-and-endorsements-stu1.html)
- [Safire roadmap](https://github.com/vanessuniq/safire/blob/main/ROADMAP.md)
