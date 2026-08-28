---
layout: default
title: Confidential Client and Network Errors
parent: Troubleshooting
nav_order: 3
---

# Confidential Client and Network Errors

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Dynamic Client Registration Errors

### `DiscoveryError`: Server does not advertise a registration endpoint

```
Safire::Errors::DiscoveryError: Failed to discover SMART configuration from https://...: server does not advertise a 'registration_endpoint'
```

The server either does not support Dynamic Client Registration or its registration endpoint is not published in `/.well-known/smart-configuration`. Pass the endpoint explicitly or register manually through the server's developer portal:

```ruby
registration = client.register_client(
  metadata,
  registration_endpoint: 'https://auth.example.com/register'
)
```

For UDAP, the registration endpoint is always discovery-bound. Safire raises
`DiscoveryError` before POSTing when discovery fails, `signed_metadata` cannot
be validated, the server does not advertise usable `udap_dcr` capability, or
the registration algorithm and certification-requirement fields cannot be used
safely. Full structural conformance remains an explicit
`UdapMetadata#valid?` diagnostic and is not an automatic DCR gate:

```ruby
registration = udap_client.register_client(
  metadata,
  client_uri:      'https://client.example.com',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

A missing `RS256` advertisement produces a warning because STU2 requires that
server baseline, but Safire can proceed with another advertised, supported,
key-compatible algorithm. Missing, malformed, or insufficient
`scopes_supported` also warns in v0.4.1 instead of blocking DCR. Requested
wildcards are checked by exact membership; narrower non-wildcard SMART FHIR
scopes may be covered by broader advertised scopes. Registration and
modification will reject unadvertised wildcard requests in v0.5.0, while
cancellation remains warning-only.

### `ValidationError`: UDAP registration metadata or certifications are invalid

```
Safire::Errors::ValidationError: Validation failed for certifications: must be nil or an array of compact JWS strings
```

UDAP registration signs caller-controlled metadata before sending it. Safire
therefore validates the metadata and certification collection locally and raises
`ValidationError` before building a software statement when input is malformed.

Common causes:

- missing required metadata such as `client_name`, `contacts`, `grant_types`, or `scope`
- unsupported grant combinations
- non-HTTPS redirect or logo URIs, except HTTP localhost when explicitly enabled for development
- reserved claims such as `iss`, `sub`, `aud`, `exp`, `jti`, `software_statement`, `certifications`, or `udap`
- `certifications:` is not `nil` or an array of compact JWS strings
- discovery declares required certification policy URIs, but `certifications:`
  is omitted or empty; the server still decides whether supplied JWTs satisfy
  those policies

### `CertificateError`: UDAP client signing identity cannot support registration

```
Safire::Errors::CertificateError: Certificate error — client_uri does not match any URI SAN in the leaf certificate
```

UDAP registration requires a private key and leaf-first certificate chain. The
private key must match the leaf certificate, every certificate must be currently
valid, and the `client_uri:` must exactly match a URI Subject Alternative Name
in the leaf certificate. Case, port, and trailing slash differences are
significant.

### `RegistrationError`: Server rejected the registration request

```
Safire::Errors::RegistrationError: Client registration failed — HTTP 400 — invalid_redirect_uri — Redirect URI must use HTTPS
```

The server returned an OAuth 2.0 error response. Check `e.error_code` and `e.error_description` for the specific reason, correct the metadata, and retry:

```ruby
rescue Safire::Errors::RegistrationError => e
  puts e.status            # 400
  puts e.error_code        # "invalid_redirect_uri"
  puts e.error_description # "Redirect URI must use HTTPS"
```

UDAP servers may return UDAP-specific error codes such as
`invalid_software_statement` or `unapproved_software_statement`; Safire
preserves them in `e.error_code`.

### `RegistrationError`: 2xx response has a missing or invalid `client_id`

```
Safire::Errors::RegistrationError: Registration response missing client_id; received fields: error, error_description
```

The server returned a successful HTTP status without a valid `client_id`. A
successful registration response must contain a non-blank string `client_id`.

If the response omitted the key, check `e.received_fields` to see what the
server returned:

```ruby
rescue Safire::Errors::RegistrationError => e
  puts e.received_fields # ["error", "error_description"]
end
```

If the key was present but its value was `nil`, blank, or not a string,
`e.error_description` reports the validation failure and `e.received_fields`
is `nil`:

```ruby
rescue Safire::Errors::RegistrationError => e
  puts e.error_description # "response client_id must be a non-blank string"
end
```

Either response is unusable as a confirmed registration. Safire does not retry
automatically: the authorization server may already have committed a
registration or modification before returning a response Safire cannot safely
consume. Use the server's registration-management mechanism or operator portal
before submitting another request.

UDAP assigns completed registration meanings to `201 Created` and the
update-style `200 OK` response. Safire returns registration metadata only for
those outcomes. A `202 Accepted` response means processing is pending under
HTTP semantics and does not establish completion, even when its body contains a
valid-looking `client_id`. Safire raises `RegistrationError` with
`e.status == 202`; callers remain responsible for any server-specific status or
management workflow.

### `RegistrationError`: UDAP cancellation response does not confirm cancellation

```
Safire::Errors::RegistrationError: Client registration failed — HTTP 202 — cancellation response did not confirm cancellation: expected an empty grant_types array
```

UDAP registration cancellation is confirmed by the response body, not by a
specific success status such as `200` or `201`. Safire accepts a cancellation
response only when the final status is `2xx` and the body contains a non-blank
string `client_id` plus an empty `grant_types` array:

```ruby
cancellation = udap_client.cancel_registration(
  metadata,
  client_uri:      'https://client.example.com',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)

cancellation['grant_types'] # => []
```

A non-`2xx` response does not confirm cancellation; inspect any preserved OAuth
error code and description to determine whether the server explicitly rejected
the request. If a final `2xx` response omits `grant_types`, returns a non-array
value, or returns a non-empty array, the outcome is unconfirmed rather than
rejected. Safire does not retry automatically; preserve the stored registration
state and inspect the authorization server before retrying or discarding the
`client_id`.

---

## Confidential Symmetric Client Errors

### `ConfigurationError`: Missing `client_secret`

```
Safire::Errors::ConfigurationError: Configuration missing: client_secret
```

`client_secret` must be present when using `:confidential_symmetric`:

```ruby
config = Safire::ClientConfig.new(
  client_secret: ENV.fetch('SMART_CLIENT_SECRET'),
  # ...
)
client = Safire::Client.new(config, client_type: :confidential_symmetric)
```

You can also pass it as an override directly to the token call — useful when rotating secrets:

```ruby
tokens = client.request_access_token(
  code: code, code_verifier: verifier,
  client_secret: ENV.fetch('SMART_CLIENT_SECRET')
)
```

### `401 Unauthorized` with Basic Auth

**Causes:** incorrect credentials, or the server does not support `client_secret_basic`.

Verify the server supports Basic Auth before debugging credentials:

```ruby
metadata = client.server_metadata
unless metadata.token_endpoint_auth_methods_supported.include?('client_secret_basic')
  raise 'Server does not support client_secret_basic'
end
```

Safire encodes credentials with `Base64.strict_encode64` — special characters in secrets are handled automatically.

---

## Confidential Asymmetric Client Errors

### `ConfigurationError`: Missing `private_key` or `kid`

```
Safire::Errors::ConfigurationError: Configuration missing: private_key, kid
```

Both are required for `:confidential_asymmetric`:

```ruby
config = Safire::ClientConfig.new(
  private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
  kid:         ENV.fetch('SMART_KEY_ID'),
  # ...
)
client = Safire::Client.new(config, client_type: :confidential_asymmetric)
```

### `401 Unauthorized` with JWT assertion

**Causes:** key mismatch, wrong `kid`, clock skew, or server does not support `private_key_jwt`.

Verify `private_key_jwt` is supported:

```ruby
metadata = client.server_metadata
unless metadata.token_endpoint_auth_methods_supported.include?('private_key_jwt')
  raise 'Server does not support private_key_jwt'
end
```

Verify the public key registered with the server matches the private key you are using, and that the `kid` value matches the key ID the server expects. Safire sets JWT `exp` to 5 minutes from `iat` — if your system clock is significantly skewed from the server, assertions will be rejected.

---

## Backend Services Errors

### `ConfigurationError`: Missing `private_key` or `kid`

```
Safire::Errors::ConfigurationError: Configuration missing: private_key, kid
```

`request_backend_token` validates `private_key` and `kid` when building the JWT assertion. Ensure both are in config or passed as overrides:

```ruby
# In config (preferred)
config = Safire::ClientConfig.new(
  private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
  kid:         ENV.fetch('SMART_KEY_ID'),
  # ...
)
client = Safire::Client.new(config)

# Or override per call
client.request_backend_token(
  private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
  kid:         ENV.fetch('SMART_KEY_ID')
)
```

See [Backend Services — Prerequisites]({% link smart-on-fhir/backend-services/index.md %}#prerequisites-registration-keys-and-jwks) for key generation steps.

---

## Network Errors

### `NetworkError`: Connection refused or timeout

```
Safire::Errors::NetworkError: HTTP request failed: Connection refused
```

Verify server connectivity before debugging Safire configuration:

```bash
curl -v https://fhir.example.com/.well-known/smart-configuration
```

For transient network failures, implement retry with exponential backoff in your application — see [Advanced Examples]({{ site.baseurl }}/advanced/#token-management) for a reusable pattern.

### `NetworkError`: Blocked redirect to non-HTTPS URL

```
Safire::Errors::NetworkError: Blocked redirect to non-HTTPS URL: http://fhir.example.com/...
```

Safire blocks redirects to non-HTTPS URLs (except `localhost`). Configure `base_url` with the final HTTPS URL directly, bypassing any HTTP-to-HTTPS redirect the server may use:

```ruby
# ✅ Use the final HTTPS URL directly
base_url: 'https://fhir.example.com/r4'

# ❌ Will fail if the server redirects HTTP → HTTPS
base_url: 'http://fhir.example.com/r4'
```
