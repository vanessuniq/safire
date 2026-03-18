---
layout: default
title: Configuration
nav_order: 3
---

# Configuration

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Quick Reference

All parameters at a glance. `protocol:` and `client_type:` are keyword arguments to `Safire::Client.new`; all others are keys in the configuration hash (or `ClientConfig` attributes).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `base_url` | String | Yes | — | FHIR server base URL |
| `client_id` | String | Yes | — | OAuth2 client identifier |
| `redirect_uri` | String | Yes | — | Registered callback URL |
| `protocol:` | Symbol | No | `:smart` | Authorization protocol — `:smart` or `:udap` |
| `client_type:` | Symbol | No | `:public` | SMART client type — `:public`, `:confidential_symmetric`, or `:confidential_asymmetric` |
| `client_secret` | String | No | — | Required for `:confidential_symmetric` |
| `private_key` | OpenSSL::PKey / String | No | — | RSA/EC private key; required for `:confidential_asymmetric` |
| `kid` | String | No | — | Key ID matching the public key registered with the server |
| `jwt_algorithm` | String | No | auto | JWT signing algorithm — `RS384` or `ES384`; auto-detected from key type |
| `jwks_uri` | String | No | — | URL to client's public JWKS, included as `jku` in JWT header |
| `scopes` | Array | No | — | Default scopes for authorization requests |
| `authorization_endpoint` | String | No | — | Override the discovered authorization endpoint |
| `token_endpoint` | String | No | — | Override the discovered token endpoint |

---

## Client Configuration

Safire accepts configuration either as a Hash or a `Safire::ClientConfig` object. When you pass a Hash, Safire automatically wraps it in a `ClientConfig`.

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `base_url` | String | FHIR server base URL |
| `client_id` | String | OAuth2 client identifier |
| `redirect_uri` | String | Registered callback URL |

### Optional Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_secret` | String | Required for confidential symmetric clients |
| `scopes` | Array | Default scopes for authorization requests |
| `authorization_endpoint` | String | Override discovered endpoint |
| `token_endpoint` | String | Override discovered endpoint |
| `private_key` | OpenSSL::PKey, String | RSA/EC private key for asymmetric clients (PEM string also accepted) |
| `kid` | String | Key ID matching the public key registered with the server |
| `jwt_algorithm` | String | JWT signing algorithm: RS384 or ES384 (auto-detected from key type) |
| `jwks_uri` | String | URL to client's JWKS, included as `jku` in JWT header |

---

## URI Validation and HTTPS Enforcement

`ClientConfig` validates all URI parameters at initialization time and raises a `Safire::Errors::ConfigurationError` for any violation.

### Rules

- All URI attributes must be well-formed (scheme + host required)
- All URIs must use `https` — enforced per SMART App Launch 2.2.0, which requires TLS for all exchanges involving sensitive data
- **Exception:** `http` is permitted when the host is `localhost` or `127.0.0.1`, to support local development without a TLS termination proxy

### Validated Attributes

| Attribute | Required? |
|-----------|-----------|
| `base_url` | Always |
| `redirect_uri` | Always |
| `issuer` | When provided (defaults to `base_url`) |
| `authorization_endpoint` | When provided |
| `token_endpoint` | When provided |
| `jwks_uri` | When provided |

### Examples

```ruby
# Valid — HTTPS on production host
Safire::ClientConfig.new(
  base_url: 'https://fhir.example.com',
  client_id: 'my_client',
  redirect_uri: 'https://myapp.example.com/callback'
)

# Valid — HTTP allowed for localhost
Safire::ClientConfig.new(
  base_url: 'http://localhost:3000/fhir',
  client_id: 'my_client',
  redirect_uri: 'http://localhost:3000/callback'
)

# Raises ConfigurationError — HTTP on non-localhost host
Safire::ClientConfig.new(
  base_url: 'http://fhir.example.com',  # => ConfigurationError
  client_id: 'my_client',
  redirect_uri: 'https://myapp.example.com/callback'
)
```

---

## Sensitive Attribute Protection

`ClientConfig` protects `client_secret` and `private_key` from accidental exposure in two ways:

### `#to_hash` masking

Sensitive fields are replaced with `'[FILTERED]'` when present; `nil` values remain `nil`.

```ruby
config = Safire::ClientConfig.new(
  base_url: 'https://fhir.example.com',
  client_id: 'my_client',
  redirect_uri: 'https://myapp.example.com/callback',
  client_secret: 'my_secret'
)

config.to_hash[:client_secret]  # => "[FILTERED]"
config.to_hash[:base_url]       # => "https://fhir.example.com"
```

### `#inspect` override

Ruby's default `inspect` exposes all instance variables. `ClientConfig` overrides it to mask sensitive fields and omit `nil` attributes, making REPL sessions and error messages safe.

```ruby
config.inspect
# => "#<Safire::ClientConfig base_url: \"https://fhir.example.com\", client_id: \"my_client\", ...>"
# client_secret is shown as [FILTERED], never as the real value
```

---

## Creating a Client

### Using a Hash (Recommended)

The simplest approach is to pass configuration directly as a Hash:

```ruby
client = Safire::Client.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)
```

### Using ClientConfig

You can also explicitly create a `ClientConfig` first:

```ruby
config = Safire::ClientConfig.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

client = Safire::Client.new(config)
```

This approach is useful when you need to reuse the same configuration for multiple clients or inspect the configuration before creating a client.

---

## Protocol Selection

The `protocol:` keyword argument to `Safire::Client.new` selects the authorization protocol to use. It is independent of `client_type:` — the two parameters are orthogonal.

```ruby
client = Safire::Client.new(config, protocol: :smart, client_type: :confidential_symmetric)
```

| Value | Status | Description |
|-------|--------|-------------|
| `:smart` | Implemented | SMART App Launch 2.2.0 — the default. Use `client_type:` to select the authentication method. |
| `:udap` | Planned | UDAP Security 1.0. Accepted by the validator but raises `NotImplementedError` until implemented. |

### SMART (`protocol: :smart`)

The default protocol. All three `client_type:` values are supported: `:public`, `:confidential_symmetric`, and `:confidential_asymmetric`. See [Client Types](#client-types) below for details.

```ruby
# Equivalent — protocol: :smart is the default
client = Safire::Client.new(config)
client = Safire::Client.new(config, protocol: :smart)
client = Safire::Client.new(config, protocol: :smart, client_type: :public)
```

### UDAP (`protocol: :udap`) — Planned

UDAP is a separate protocol from SMART — it is not a client type within SMART App Launch. When `protocol: :udap` is specified, `client_type:` is ignored entirely: UDAP clients always authenticate using a JWT signed by their private key.

```ruby
# Accepted by Safire, but raises NotImplementedError until UDAP support is complete
client = Safire::Client.new(config, protocol: :udap)
```

See the [UDAP guide]({{ site.baseurl }}/udap/) for an overview of planned UDAP support.

---

## Client Types

### Public Client (Default)

```ruby
# client_type defaults to :public when not specified
client = Safire::Client.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

# Explicit:
client = Safire::Client.new(config, client_type: :public)
```

### Confidential Symmetric Client

```ruby
client = Safire::Client.new(
  {
    base_url: 'https://fhir.example.com/r4',
    client_id: 'my_client_id',
    client_secret: ENV.fetch('SMART_CLIENT_SECRET'),
    redirect_uri: 'https://myapp.com/callback',
    scopes: ['openid', 'profile', 'patient/*.read']
  },
  client_type: :confidential_symmetric
)
```

### Confidential Asymmetric Client

```ruby
client = Safire::Client.new(
  {
    base_url: 'https://fhir.example.com/r4',
    client_id: 'my_client_id',
    redirect_uri: 'https://myapp.com/callback',
    scopes: ['openid', 'profile', 'patient/*.read'],
    private_key: OpenSSL::PKey::RSA.new(File.read(ENV.fetch('SMART_PRIVATE_KEY_PATH'))),
    kid: ENV.fetch('SMART_KEY_ID'),
    jwks_uri: ENV.fetch('SMART_JWKS_URI')  # Optional
  },
  client_type: :confidential_asymmetric
)
```

### Changing Client Type

You can change the client type after initialization:

```ruby
# Start with default :public for discovery
client = Safire::Client.new(config)
metadata = client.server_metadata

# Switch based on server capabilities
if metadata.supports_asymmetric_auth?
  client.client_type = :confidential_asymmetric
elsif metadata.supports_symmetric_auth?
  client.client_type = :confidential_symmetric
end
```

---

## Supported Client Types

| Client Type | Description | Authentication Method |
|-----------|-------------|----------------------|
| `:public` | Public client using PKCE | `client_id` in request body |
| `:confidential_symmetric` | Confidential client with secret | HTTP Basic auth header |
| `:confidential_asymmetric` | Confidential client with key pair | JWT assertion (RS384/ES384) |

---

## Manual Endpoints

If you need to bypass discovery or provide custom endpoints:

```ruby
client = Safire::Client.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile'],
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/token'
)
```

When endpoints are provided, Safire uses them directly instead of fetching from `/.well-known/smart-configuration`.

---

## Token Response Validation

After a successful token exchange, use `client.token_response_valid?` to verify the server's
response meets SMART App Launch 2.2.0 requirements. This is a caller-invoked helper — token
exchange methods return the raw response without checking compliance.

Logs a warning per violation and returns `false`. Never raises.

```ruby
token_data = client.request_access_token(code: code, code_verifier: verifier)

unless client.token_response_valid?(token_data)
  # Safire has already logged each violation, e.g.:
  # WARN: SMART token response non-compliance: required field 'scope' is missing
  # WARN: SMART token response non-compliance: token_type is "bearer"; expected 'Bearer'
  raise "Server token response does not meet SMART App Launch 2.2.0 requirements"
end
```

**Checks performed (SMART App Launch 2.2.0 §Token Response):**

| Field | Requirement |
|-------|-------------|
| `access_token` | SHALL be present |
| `token_type` | SHALL be present and exactly `"Bearer"` (case-sensitive) |
| `scope` | SHALL be present |

---

## Logging Configuration

Configure Safire's logger and HTTP request logging via `Safire.configure`:

```ruby
# config/initializers/safire.rb
Safire.configure do |config|
  config.logger    = Rails.logger
  config.log_level = Logger::DEBUG  # In development
  config.log_http  = true           # Default — log HTTP requests with sensitive data filtered
end
```

### `log_http` — HTTP Request Logging

| Value | Behaviour |
|-------|-----------|
| `true` (default) | HTTP requests and responses are logged. The `Authorization` header is replaced with `[FILTERED]`. Request and response bodies are **never** logged to prevent credential or token leakage. |
| `false` | No HTTP request or response logging. |

```ruby
# Disable HTTP logging in production if not needed
Safire.configure do |config|
  config.log_http = false
end
```

### Log Levels

| Level | Description |
|-------|-------------|
| `Logger::DEBUG` | Verbose Safire operation logging |
| `Logger::INFO` | Standard operation logging (default) |
| `Logger::WARN` | Compliance warnings and non-critical issues only |
| `Logger::ERROR` | Errors only |

---

## Environment-Based Configuration

### Rails Example

```ruby
# config/initializers/safire.rb
Safire.configure do |config|
  config.logger = Rails.logger
  config.log_level = Rails.env.development? ? Logger::DEBUG : Logger::INFO
end

# app/services/smart_client_service.rb
class SmartClientService
  def self.build_client(client_type: :public)
    Safire::Client.new(
      {
        base_url: ENV.fetch('FHIR_BASE_URL'),
        client_id: ENV.fetch('SMART_CLIENT_ID'),
        client_secret: ENV.fetch('SMART_CLIENT_SECRET'),
        redirect_uri: Rails.application.routes.url_helpers.smart_callback_url,
        scopes: ENV.fetch('SMART_SCOPES', 'openid profile patient/*.read').split
      },
      client_type: client_type
    )
  end
end
```

### Environment Variables

```bash
# .env
FHIR_BASE_URL=https://fhir.example.com/r4
SMART_CLIENT_ID=my_client_id
SMART_CLIENT_SECRET=my_client_secret  # For confidential clients
SMART_SCOPES="openid profile patient/*.read"
```

### `SAFIRE_LOGGER` — Redirect Log Output to a File

By default Safire logs to `$stdout`. Set `SAFIRE_LOGGER` to a file path to redirect the default logger's output to a file instead.

```bash
SAFIRE_LOGGER=/var/log/safire.log
```

This only affects the **default logger**. If you supply your own logger via `Safire.configure { |c| c.logger = MyLogger }`, `SAFIRE_LOGGER` is ignored entirely.

| `SAFIRE_LOGGER` set? | `config.logger` set? | Log destination |
|----------------------|----------------------|-----------------|
| No | No | `$stdout` |
| Yes (file path) | No | file at that path |
| Either | Yes | your custom logger |

---

## Next Steps

- [SMART on FHIR Workflows]({{ site.baseurl }}/smart-on-fhir/) - Implementation guides
- [Troubleshooting]({{ site.baseurl }}/troubleshooting/) - Common issues and solutions
- [API Reference]({{ site.baseurl }}/api/) - Complete YARD documentation
