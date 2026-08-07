---
layout: default
title: Dynamic Client Registration
parent: UDAP
nav_order: 1
permalink: /udap/dynamic-client-registration/
description: "Register UDAP Security STU2 clients with certificate-backed software statements."
has_children: true
---

# Dynamic Client Registration

{: .no_toc }

Safire implements the UDAP Security STU2 registration lifecycle for
certificate-backed clients that can protect a private key. Use
`Safire::Client#register_client` for new registrations and modifications, and
`Safire::Client#cancel_registration` for cancellation.

## Prerequisites

A registration combines two separate trust directions:

- **Server trust:** Safire validates the authorization server's
  `signed_metadata` using `trusted_anchors:` plus `crls:` or a
  `revocation_checker:`.
- **Client identity:** Safire signs the registration `software_statement` using
  the client's private key and leaf-first X.509 certificate chain.

The client certificate's URI Subject Alternative Name must exactly match the
`client_uri:` supplied to the registration call. Safire does not derive this
identifier from the FHIR server URL or canonicalize it before comparison.

Configure reusable client credentials when constructing the UDAP client:

```ruby
client = Safire::Client.new(
  {
    base_url: 'https://fhir.example.com',
    private_key: File.read('client-key.pem'),
    certificate_chain: [
      File.read('client-cert.pem'),
      File.read('issuing-ca.pem')
    ]
  },
  protocol: :udap
)
```

Applications that select signing identities dynamically may instead pass
`private_key:`, `certificate_chain:`, and `jwt_algorithm:` to each
`register_client` or `cancel_registration` call. Per-call values override the
configured defaults without mutating the client.

Before posting, Safire requires structurally conformant discovery metadata,
the `udap_dcr` profile, a usable signed `registration_endpoint`, and mandatory
`RS256` support in
`registration_endpoint_jwt_signing_alg_values_supported`. See
[Registration Metadata]({% link udap/dynamic-client-registration/registration-metadata.md %})
for caller input and grant rules.

## Register or Modify

Register a client-credentials application:

```ruby
registration = client.register_client(
  {
    client_name: 'Example Backend Service',
    contacts: ['mailto:security@example.com'],
    grant_types: ['client_credentials'],
    scope: 'system/Patient.rs system/Observation.rs'
  },
  client_uri:      'https://client.example.com',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)

client_id = registration.fetch('client_id')
```

Authorization-code clients also supply redirect and logo metadata. Safire
generates `response_types: ["code"]` and
`token_endpoint_auth_method: "private_key_jwt"` inside the signed software
statement.

```ruby
registration = client.register_client(
  {
    client_name: 'Example Provider App',
    contacts: ['mailto:security@example.com'],
    grant_types: %w[authorization_code refresh_token],
    scope: 'openid fhirUser patient/*.rs',
    redirect_uris: ['https://client.example.com/callback'],
    logo_uri: 'https://client.example.com/logo.png'
  },
  client_uri:      'https://client.example.com',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

Calling `register_client` again against the same registration endpoint with the
same `client_uri` and trust community requests modification. The authorization
server may preserve the existing `client_id` or issue a replacement; use the
identifier returned by the latest accepted response.

## Communities and Certifications

Pass `community:` when the authorization server participates in multiple UDAP
trust communities:

```ruby
registration = client.register_client(
  metadata,
  client_uri:      'https://client.example.com',
  community:       'https://udap.example.org/community1',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

`trusted_anchors:`, `crls:`, `revocation_checker:`, and `verify_chain:` apply
only to server `signed_metadata` validation. They are not the client signing
certificate chain. Passing `verify_chain: false` skips server chain and
revocation checks and is suitable only for development and tests.

UDAP certifications and endorsements may be signed by the client application
operator or by a third party, depending on the trust community's certification
definition. Supply the resulting compact JWS values through `certifications:`:

```ruby
registration = client.register_client(
  metadata,
  client_uri:      'https://client.example.com',
  certifications: [certification_jwt],
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

`certifications: nil` omits the request member. An explicit `[]` sends an empty
array and can remove optional certifications during modification. When
discovery advertises non-empty `udap_certifications_required`, Safire rejects
both forms before signing unless at least one compact JWS is supplied.

Safire checks only collection and compact-JWS shape. It does not create,
interpret, or cryptographically validate certification or endorsement JWTs;
the authorization server decides whether they satisfy the advertised policy
URIs.

## Request, Response, and Errors

Safire performs the following sequence for every registration lifecycle call:

1. Discovers and cryptographically validates community-scoped UDAP metadata.
2. Runs `UdapMetadata#valid?` because DCR is about to act on the discovered
   registration endpoint.
3. Verifies the DCR profile and mandatory registration algorithm advertisement.
4. Validates caller metadata and certification shape.
5. Signs a fresh five-minute software statement with a fresh `jti`.
6. POSTs the fixed UDAP request envelope to the authoritative signed endpoint.
7. Parses the RFC 7591-shaped response into a string-keyed `Hash`.

The request body contains only:

```json
{
  "software_statement": "<compact JWS>",
  "certifications": ["<compact JWS>"],
  "udap": "1"
}
```

The `certifications` member is omitted when its argument is `nil`. Registration
accepts `201 Created` for a new registration and `200 OK` for an update-style
response. Both require a non-blank string `client_id`. The authorization server
may reject or replace requested registration metadata; treat the returned
response as the effective server registration rather than assuming it echoes
the software statement.

| Error | When raised |
|-------|-------------|
| `Safire::Errors::DiscoveryError` | Discovery or `signed_metadata` validation fails, metadata is structurally non-conformant for DCR, or required DCR capability is absent |
| `Safire::Errors::ValidationError` | Caller metadata or certification input is invalid before signing |
| `Safire::Errors::ConfigurationError` | Signing configuration or algorithm selection is missing or incompatible |
| `Safire::Errors::CertificateError` | The client key, certificate chain, validity period, ordering, or URI SAN cannot support signing |
| `Safire::Errors::RegistrationError` | The server rejects the request or returns a malformed lifecycle response |
| `Safire::Errors::NetworkError` | The request fails at the transport layer |

Continue with [Software Statements]({% link udap/dynamic-client-registration/software-statement.md %})
for signing details and [Registration Lifecycle]({% link udap/dynamic-client-registration/lifecycle.md %})
for modification, replacement, logical groups, and cancellation. See
[Client and Registration Errors]({% link troubleshooting/client-errors.md %})
for remediation guidance.

The [UDAP Security STU2 registration profile](https://hl7.org/fhir/us/udap-security/STU2/registration.html)
is the normative source for these requirements.
