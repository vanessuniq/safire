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
call against the same registration endpoint with the same `client_uri` and
community requests modification of the existing registration.

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

UDAP defines `201 Created` for completed new registration and an update-style
`200 OK` response for modification. Safire returns registration metadata only
for those completed outcomes, and either response must be a JSON object with a
non-blank string `client_id`.

Safire submits each registration or modification request once. It does not
automatically retry after an unusable `200` or `201` response because the
authorization server may already have committed the operation even though
Safire cannot safely consume its response. Use the server's registration
management mechanism or operator portal before submitting another request. A
`202 Accepted` response represents pending processing under HTTP semantics,
even when its body contains a valid-looking `client_id`. Safire reports that
unconfirmed outcome through `RegistrationError` with `status == 202`; the
application decides whether and how to use a server-specific status or
management mechanism. Safire does not claim that STU2 requires clients to
reject `202` responses.

The authorization server identifies the registration from the software
statement's client URI (`iss`) and certificate trust-community context, not from
a caller-supplied `client_id`. A modification replaces the prior registration
metadata and may also replace optional certifications. Pass
`certifications: []` to explicitly clear optional certifications.

The server should preserve the previous `client_id`. If it returns a different
one, STU2 requires the server to cancel the old registration and the client to
use only the replacement identifier. Safire returns the response without
assuming that the identifier is unchanged.

FHIR servers that advertise the same `registration_endpoint` belong to one
logical registration group. Registering against one server in that group may
therefore register the client for every endpoint in the group. Safire does not
attempt to infer these groups from different FHIR base URLs; use the discovered
registration endpoint and server documentation when managing registrations.

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

The cancellation request does not send a `client_id`. The authorization server
identifies the existing registration from the same client URI and
trust-community identity used for registration. Applications should still
compare the response `client_id` with the identifier they currently store before
discarding local registration state.

Unlike registration, Safire does not require a specific success status such as
`200` or `201` for cancellation, but the final HTTP response must still be a
successful `2xx`. UDAP Security STU2 confirms cancellation through the response
body: the response must contain a non-blank string `client_id` and an empty
`grant_types` array. A final non-`2xx` status raises
`Safire::Errors::RegistrationError` and preserves any OAuth error returned by
the server. A final `2xx` response with a non-empty, missing, or non-array
`grant_types` value also raises `RegistrationError`, but in that case the
cancellation outcome is unconfirmed rather than rejected. Applications should
preserve their local registration state and inspect the authorization server
before retrying or discarding the stored `client_id`.

## Error Boundaries

Both lifecycle methods raise the same Safire error families:

| Error | Meaning |
|-------|---------|
| `Safire::Errors::DiscoveryError` | UDAP discovery or signed-metadata trust failed, or a DCR profile, endpoint, algorithm, or certification-requirement value could not be used safely |
| `Safire::Errors::ValidationError` | Caller metadata or `certifications:` failed local validation before signing |
| `Safire::Errors::ConfigurationError` | Signing configuration is missing or incompatible |
| `Safire::Errors::CertificateError` | The private key, certificate chain, validity period, or `client_uri` SAN check failed |
| `Safire::Errors::RegistrationError` | The registration endpoint returned an OAuth error, an unconfirmed pending outcome, or a malformed completed response |
| `Safire::Errors::NetworkError` | The request failed at the transport layer |

OAuth-style server errors preserve the server's `error` and
`error_description`, including UDAP-specific codes such as
`invalid_software_statement` and `unapproved_software_statement`.
