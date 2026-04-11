---
layout: default
title: Client Setup
parent: Configuration
nav_order: 1
---

# Client Setup

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Creating a Client

Pass configuration as a Hash — Safire wraps it in a `ClientConfig` automatically:

```ruby
client = Safire::Client.new(
  {
    base_url:     'https://fhir.example.com/r4',
    client_id:    'my_client_id',
    redirect_uri: 'https://myapp.com/callback',
    scopes:       ['openid', 'profile', 'patient/*.read']
  }
)
```

If you need to reuse the same configuration across multiple clients or inspect it before use, create a `ClientConfig` explicitly:

```ruby
config = Safire::ClientConfig.new(
  base_url:     'https://fhir.example.com/r4',
  client_id:    'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes:       ['openid', 'profile', 'patient/*.read']
)

client = Safire::Client.new(config)
```

{: .note }
> `client_id` is the only authorization parameter validated at call time rather than at construction. `authorization_url`, `request_access_token`, `refresh_token`, and `request_backend_token` each raise `Safire::Errors::ConfigurationError` if `client_id` is absent when called. This means you can build a client without a `client_id` and call `register_client` to obtain one at runtime. See [Dynamic Client Registration]({{ site.baseurl }}/smart-on-fhir/dynamic-client-registration/) for details.

---

## Protocol and Client Type

`protocol:` and `client_type:` are keyword arguments to `Safire::Client.new`. They are independent of each other.

```ruby
client = Safire::Client.new(config, protocol: :smart, client_type: :confidential_symmetric)
```

### Protocol

Selects the authorization protocol. Defaults to `:smart`.

| Value | Status | Description |
|-------|--------|-------------|
| `:smart` | Implemented | SMART App Launch 2.2.0 |
| `:udap` | Planned | UDAP Security 1.0 — accepted by the validator, raises `NotImplementedError` until implemented |

For UDAP, `client_type:` is ignored — UDAP clients always authenticate with a JWT signed by their private key.

### Client Type

Selects the SMART authentication method. Applies only when `protocol: :smart`. Defaults to `:public`.

| Value | Extra config required | Authentication |
|-------|-----------------------|----------------|
| `:public` | None | PKCE; `client_id` in request body |
| `:confidential_symmetric` | `client_secret` | HTTP Basic auth |
| `:confidential_asymmetric` | `private_key`, `kid` | JWT assertion (RS384/ES384) |

```ruby
# Public (default)
client = Safire::Client.new(config)

# Confidential symmetric
client = Safire::Client.new(
  { **base_config, client_secret: ENV.fetch('SMART_CLIENT_SECRET') },
  client_type: :confidential_symmetric
)

# Confidential asymmetric
client = Safire::Client.new(
  {
    **base_config,
    private_key: OpenSSL::PKey::RSA.new(File.read(ENV.fetch('SMART_PRIVATE_KEY_PATH'))),
    kid:         ENV.fetch('SMART_KEY_ID'),
    jwks_uri:    ENV.fetch('SMART_JWKS_URI')  # optional
  },
  client_type: :confidential_asymmetric
)
```

You can also change `client_type` after initialization — useful when selecting a type based on server capabilities discovered at runtime:

```ruby
client = Safire::Client.new(config)
metadata = client.server_metadata

client.client_type = :confidential_asymmetric if metadata.supports_asymmetric_auth?
```

For a decision guide on which workflow to use, see [SMART App Launch — Choosing a Workflow]({{ site.baseurl }}/smart-on-fhir/).

---

## URI Validation

All URI parameters are validated at initialization. Safire raises `Safire::Errors::ConfigurationError` for any violation:

- URIs must be well-formed (scheme + host required)
- URIs must use `https` — required by SMART App Launch 2.2.0
- **Exception:** `http` is permitted for `localhost` and `127.0.0.1` (local development only)

The following attributes are validated:

| Attribute | Validated when |
|-----------|----------------|
| `base_url` | Always |
| `redirect_uri` | When provided (required for App Launch; not used in Backend Services) |
| `issuer` | When provided (defaults to `base_url`) |
| `authorization_endpoint` | When provided |
| `token_endpoint` | When provided |
| `jwks_uri` | When provided |

If you need to bypass discovery and provide endpoints directly, set `authorization_endpoint` and `token_endpoint` in your config. Safire will use them as-is instead of fetching `/.well-known/smart-configuration`.

---

## Credential Protection

`ClientConfig` prevents `client_secret` and `private_key` from leaking in logs or REPL output.

`#to_hash` replaces sensitive fields with `'[FILTERED]'`:

```ruby
config.to_hash[:client_secret]  # => "[FILTERED]"
config.to_hash[:base_url]       # => "https://fhir.example.com"
```

`#inspect` is overridden to mask sensitive fields and omit `nil` attributes, so REPL sessions and error messages never expose credentials:

```ruby
config.inspect
# => "#<Safire::ClientConfig base_url: \"https://fhir.example.com\", client_id: \"my_client_id\", client_secret: \"[FILTERED]\", ...>"
```

---

## Next Steps

- [Logging]({{ site.baseurl }}/configuration/logging/) — configure Safire's logger and HTTP request logging
- [Dynamic Client Registration]({{ site.baseurl }}/smart-on-fhir/dynamic-client-registration/) — obtain a `client_id` at runtime using RFC 7591
- [SMART App Launch Workflows]({{ site.baseurl }}/smart-on-fhir/) — step-by-step authorization flow guides