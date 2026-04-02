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
