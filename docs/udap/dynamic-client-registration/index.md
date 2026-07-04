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

<div class="code-example" markdown="1">
**Current status:** Safire implements UDAP Security STU2 new registration and
registration modification through `Safire::Client#register_client`.
Registration cancellation is planned separately.
</div>

## Register a Client

Create a temporary UDAP client with the FHIR server base URL plus the client
signing identity. Then call `register_client` with registration metadata and
the exact `client_uri` that appears as a URI Subject Alternative Name in the
leaf certificate.

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

client_id = registration['client_id']
```

Safire performs these steps:

1. Discovers UDAP metadata from `/.well-known/udap`, optionally scoped by
   `community:`.
2. Validates `signed_metadata` using the supplied server trust policy.
3. Runs `UdapMetadata#valid?` because registration is about to trust and act on
   the discovered registration endpoint.
4. Verifies that the server advertises the `udap_dcr` profile and a usable
   `registration_endpoint`.
5. Validates caller registration metadata.
6. Signs a fresh `software_statement` JWT using the configured or per-call
   client signing identity.
7. POSTs the UDAP request envelope and returns the parsed registration response.

Calling `register_client` again with the same `client_uri` and community
requests modification of the existing registration. Safire returns the server
response without assuming the `client_id` is unchanged.

### Authorization-code registration

Authorization-code clients include redirect and logo metadata. Safire generates
`response_types: ["code"]` and `token_endpoint_auth_method: "private_key_jwt"`
inside the signed software statement.

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

### Community, trust policy, and certifications

Use `community:` when registering against a specific UDAP trust community:

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
to server `signed_metadata` validation during discovery. They are not the
client signing certificate chain.

Pass `certifications:` when the discovered community requires or accepts
third-party certification JWTs:

```ruby
registration = client.register_client(
  metadata,
  client_uri:      'https://client.example.com',
  certifications: [certification_jwt],
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

`certifications: nil` omits the envelope field. `certifications: []` sends an
explicit empty array, which is useful for modification requests that clear
optional certifications. If discovery advertises required certifications,
Safire rejects `nil` and `[]` locally. Safire shape-checks certification values
as compact JWS strings but does not create, decode, verify, or interpret their
contents.

### Errors

| Error | When raised |
|-------|-------------|
| `Safire::Errors::DiscoveryError` | Discovery fails, `signed_metadata` cannot be validated, discovered metadata is structurally non-conformant, or the server does not advertise usable UDAP DCR capability |
| `Safire::Errors::ValidationError` | Caller metadata or the `certifications:` collection is invalid before signing |
| `Safire::Errors::ConfigurationError` | Signing configuration is missing or incompatible, such as an unsupported explicit `jwt_algorithm` |
| `Safire::Errors::CertificateError` | The configured client certificate chain cannot support signing or does not match `client_uri:` |
| `Safire::Errors::RegistrationError` | The registration server returns an OAuth error response or a 2xx response without a non-blank string `client_id` |
| `Safire::Errors::NetworkError` | Connection failure, timeout, SSL error, or blocked non-HTTPS redirect |

## Validate Metadata

`register_client` builds `UdapRegistrationMetadata` internally. You can also
construct it directly when you want to validate metadata before invoking the
network flow:

```ruby
metadata = Safire::Protocols::UdapRegistrationMetadata.new(
  {
    client_name: 'Example Health App',
    contacts: ['mailto:security@example.com'],
    grant_types: %w[authorization_code refresh_token],
    scope: 'openid system/Patient.rs',
    redirect_uris: ['https://app.example.com/callback'],
    logo_uri: 'https://app.example.com/logo.png',
    software_id: 'example-health-app'
  }
)

normalized = metadata.to_h
normalized['response_types']              # => ["code"]
normalized['token_endpoint_auth_method']  # => "private_key_jwt"
```

Top-level symbol keys are normalized to strings. `to_h` returns a defensive
copy, so changing it cannot alter the validated metadata held by the object.
Invalid input raises `Safire::Errors::ValidationError`; the error identifies the
attribute without including its value.

## Metadata Rules

| Field | Requirement |
|-------|-------------|
| `client_name` | Required nonblank string |
| `contacts` | Required nonempty array of absolute URI strings, including at least one valid `mailto:` email address |
| `grant_types` | Required for registration; exact permitted combinations are listed below |
| `scope` | Required nonblank, space-delimited OAuth scope string |
| `redirect_uris` | Required only for `authorization_code`; every value must use HTTPS by default |
| `logo_uri` | Required only for `authorization_code`; must use HTTPS by default and reference a PNG, JPEG/JPG, or GIF |
| `response_types` | Generated by Safire as `["code"]` for `authorization_code` |
| `token_endpoint_auth_method` | Generated by Safire as `"private_key_jwt"` |

### Local development

UDAP Security STU2 requires HTTPS for redirect and logo URIs. Safire enforces
that requirement by default, including on localhost.

For a local server that does not terminate TLS, explicitly enable the narrow
development exception:

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

`allow_insecure_localhost: true` permits HTTP only for `localhost` and
`127.0.0.1`, with an optional port. Remote HTTP hosts remain rejected. Safire
logs a warning when the exception is actually used because the resulting
registration metadata is non-conformant and may be rejected by a conformant
UDAP server.

Safire does not infer the application environment. The host application must
connect the option to its own development setting, and production should leave
the default `false` unchanged.

Safire preserves unknown RFC 7591 extension fields when their values are valid
JSON data. It rejects Ruby-specific values, non-finite numbers, nested objects
with non-string keys, and recursive collections.

## Grant Profiles

Registration accepts these grant combinations:

| Client flow | `grant_types` | Conditional metadata |
|-------------|---------------|----------------------|
| Authorization code | `["authorization_code"]` | `redirect_uris`, `logo_uri`; Safire adds `response_types: ["code"]` |
| Authorization code with refresh | `["authorization_code", "refresh_token"]` | Same authorization metadata |
| Client credentials | `["client_credentials"]` | `redirect_uris`, `logo_uri`, and `response_types` must be absent |

Exactly one primary grant is allowed. Unknown grant types, duplicate values,
`refresh_token` without `authorization_code`, and combining
`authorization_code` with `client_credentials` raise `ValidationError`.

The metadata value object also has `operation: :cancel` as a foundation for the
future cancellation workflow. Omit `grant_types`; Safire injects an empty array
and excludes authorization-only metadata. The public `cancel_registration`
method is not implemented yet.

```ruby
cancellation = Safire::Protocols::UdapRegistrationMetadata.new(
  {
    client_name: 'Example Health App',
    contacts: ['mailto:security@example.com'],
    scope: 'openid system/Patient.rs'
  },
  operation: :cancel
)

cancellation.to_h['grant_types'] # => []
```

## Protocol-Owned Fields

Callers cannot override the generated fields above or supply registered JWT
claims (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`) and request-envelope fields
(`software_statement`, `certifications`, `udap`). Those values belong to the
software-statement and registration request builders.

See [Software Statements]({% link udap/dynamic-client-registration/software-statement.md %})
for the implemented signing foundation, including `x5c`, exact URI comparison,
algorithm selection, and certificate/key checks.

See the
[UDAP Security STU2 registration profile](https://hl7.org/fhir/us/udap-security/STU2/registration.html)
for the normative requirements.
