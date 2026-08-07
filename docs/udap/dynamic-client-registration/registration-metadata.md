---
layout: default
title: Registration Metadata
parent: Dynamic Client Registration
grand_parent: UDAP
nav_order: 1
permalink: /udap/dynamic-client-registration/registration-metadata/
description: "UDAP Security STU2 registration metadata, grant profiles, URI rules, and local validation."
---

# Registration Metadata

{: .no_toc }

`register_client` validates caller-controlled metadata before signing it into a
software statement. Invalid input raises `Safire::Errors::ValidationError` and
no registration request is sent.

## Validate Input

Applications normally pass a `Hash` to `register_client`. To validate and
normalize metadata independently, construct
`Safire::Protocols::UdapRegistrationMetadata` directly:

```ruby
metadata = Safire::Protocols::UdapRegistrationMetadata.new(
  {
    client_name: 'Example Health App',
    contacts: ['mailto:security@example.com'],
    grant_types: %w[authorization_code refresh_token],
    scope: 'openid fhirUser patient/*.rs',
    redirect_uris: ['https://app.example.com/callback'],
    logo_uri: 'https://app.example.com/logo.png',
    software_id: 'example-health-app'
  }
)

normalized = metadata.to_h
normalized['response_types']             # => ["code"]
normalized['token_endpoint_auth_method'] # => "private_key_jwt"
```

Top-level symbol keys are normalized to strings. Conflicting symbol and string
forms of one key are rejected. The validated representation is deeply frozen,
and `to_h` returns a defensive copy.

## Field Requirements

| Field | Requirement |
|-------|-------------|
| `client_name` | Required non-blank string |
| `contacts` | Required non-empty array of absolute URI strings, including at least one valid `mailto:` email address |
| `grant_types` | Required for registration; must match one supported grant profile |
| `scope` | Required non-blank, space-delimited OAuth scope string |
| `redirect_uris` | Required only with `authorization_code`; every value uses HTTPS by default |
| `logo_uri` | Required only with `authorization_code`; uses HTTPS by default and references PNG, JPEG/JPG, or GIF content by path |
| `response_types` | Generated as `["code"]` for `authorization_code` |
| `token_endpoint_auth_method` | Generated as `"private_key_jwt"` |

Contact entries may use absolute URI schemes such as `mailto:`, `tel:`, or
`sip:`, but the collection must contain at least one syntactically valid email
address in a `mailto:` URI.

Safire preserves unknown RFC 7591 extension fields when their values are valid
JSON data. It rejects Ruby-specific objects, non-finite numbers, recursive
collections, and nested objects with non-string keys.

## Grant Profiles

Registration accepts exactly one primary grant:

| Client flow | `grant_types` | Conditional metadata |
|-------------|---------------|----------------------|
| Authorization code | `["authorization_code"]` | `redirect_uris`, `logo_uri`; Safire adds `response_types: ["code"]` |
| Authorization code with refresh | `["authorization_code", "refresh_token"]` | Same authorization metadata |
| Client credentials | `["client_credentials"]` | `redirect_uris`, `logo_uri`, and `response_types` are absent |

Unknown or duplicate grant values, `refresh_token` without
`authorization_code`, and combining `authorization_code` with
`client_credentials` are rejected.

Cancellation uses the same value object with `operation: :cancel`. Callers omit
`grant_types`; Safire injects an empty array and excludes authorization-only
metadata:

```ruby
cancellation = Safire::Protocols::UdapRegistrationMetadata.new(
  {
    client_name: 'Example Health App',
    contacts: ['mailto:security@example.com'],
    scope: 'system/Patient.rs'
  },
  operation: :cancel
)

cancellation.to_h['grant_types'] # => []
```

## URI and Ownership Rules

UDAP Security STU2 requires HTTPS for `redirect_uris` and `logo_uri`. Safire
enforces that requirement by default. For an HTTP loopback service used only in
local development, applications may explicitly enable the narrow exception:

```ruby
metadata = Safire::Protocols::UdapRegistrationMetadata.new(
  {
    client_name: 'Local Health App',
    contacts: ['mailto:developer@example.com'],
    grant_types: ['authorization_code'],
    scope: 'openid',
    redirect_uris: ['http://localhost:4567/callback'],
    logo_uri: 'http://localhost:4567/logo.png'
  },
  allow_insecure_localhost: ENV['APP_ENV'] == 'development'
)
```

This option permits HTTP only on `localhost` and `127.0.0.1`, logs a warning
when exercised, and produces non-conformant metadata that must not be used in
production. Safire does not infer the application environment.

Callers cannot supply protocol-owned values:

- generated fields: `response_types`, `token_endpoint_auth_method`
- registered JWT claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`
- request-envelope fields: `software_statement`, `certifications`, `udap`

These values are generated at the layer that owns them, preventing caller
metadata from overriding security claims or creating ambiguous request values.

See [Software Statements]({% link udap/dynamic-client-registration/software-statement.md %})
for the claims added after metadata validation.
