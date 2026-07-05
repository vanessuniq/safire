---
layout: default
title: Registration Lifecycle
parent: Dynamic Client Registration
grand_parent: UDAP
nav_order: 3
permalink: /udap/dynamic-client-registration/lifecycle/
description: "How Safire handles UDAP registration creation, modification, and cancellation."
---

# Registration Lifecycle

{: .no_toc }

UDAP Dynamic Client Registration uses one registration endpoint for new
registration, modification, and cancellation. Safire keeps those lifecycle
operations on the `Safire::Client` facade while preserving their different
response rules.

## Create or Modify

Call `register_client` for both new registration and modification. A repeated
call with the same `client_uri` and community requests modification of the
existing registration.

```ruby
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

Safire accepts new-registration `201 Created` responses and update-style `200`
responses. Either response must be a JSON object with a non-blank string
`client_id`.

## Cancel

Call `cancel_registration` to cancel an existing registration. Provide the
metadata that identifies the registration, but omit `grant_types`; Safire signs
a cancellation software statement that contains `grant_types: []`.

```ruby
cancellation = client.cancel_registration(
  {
    client_name: 'Example Backend Service',
    contacts: ['mailto:security@example.com'],
    scope: 'system/Patient.rs'
  },
  client_uri:      'https://client.example.com',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)

cancellation['client_id']
cancellation['grant_types'] # => []
```

Cancellation uses the same discovery-bound registration endpoint, community
scoping, trust policy, `certifications:`, and X.509 signing configuration as
`register_client`.

Unlike registration, Safire does not require a specific 2xx status code for
cancellation. UDAP Security STU2 confirms cancellation through the response
body: the response must contain a non-blank string `client_id` and an empty
`grant_types` array. A non-empty, missing, or non-array `grant_types` value
raises `Safire::Errors::RegistrationError`.

## Error Boundaries

Both lifecycle methods raise the same Safire error families:

| Error | Meaning |
|-------|---------|
| `Safire::Errors::DiscoveryError` | UDAP discovery failed, signed metadata was not trusted, metadata was structurally non-conformant for DCR, or the server did not advertise usable UDAP DCR capability |
| `Safire::Errors::ValidationError` | Caller metadata or `certifications:` failed local validation before signing |
| `Safire::Errors::ConfigurationError` | Signing configuration is missing or incompatible |
| `Safire::Errors::CertificateError` | The private key, certificate chain, validity period, or `client_uri` SAN check failed |
| `Safire::Errors::RegistrationError` | The registration endpoint returned an OAuth error response or a malformed success response |
| `Safire::Errors::NetworkError` | The request failed at the transport layer |

OAuth-style server errors preserve the server's `error` and
`error_description`, including UDAP-specific codes such as
`invalid_software_statement` and `unapproved_software_statement`.
