---
layout: default
title: Calling register_client
parent: Dynamic Client Registration
grand_parent: SMART
nav_order: 1
permalink: /smart-on-fhir/dynamic-client-registration/registration/
description: "How to call Client#register_client: assembling client metadata, choosing grant types and authentication methods, endpoint discovery, and passing an initial access token."
---

# Calling register_client
{: .no_toc }

<div class="code-example" markdown="1">
Call `Client#register_client` to POST your application's metadata to the authorization server's registration endpoint and receive a `client_id` in response.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Quick Start

Create a `Safire::Client` without a `client_id`, call `register_client` with your application's metadata, and then build a fully configured client using the credentials the server returns.

```ruby
# Step 1 — temporary client for registration only (no client_id needed)
temp_client = Safire::Client.new({ base_url: 'https://fhir.example.com' })

# Step 2 — register and receive credentials
registration = temp_client.register_client(
  {
    client_name:                'My FHIR App',
    redirect_uris:              ['https://myapp.example.com/callback'],
    grant_types:                ['authorization_code'],
    token_endpoint_auth_method: 'none',
    scope:                      'openid profile patient/*.read'
  }
)
# => { "client_id" => "dyn_abc123", "client_name" => "My FHIR App", ... }

# Step 3 — persist credentials durably (database, secrets manager, etc.)
client_id = registration['client_id']     # always present
secret    = registration['client_secret'] # present for confidential_symmetric only

# Step 4 — build a properly configured client for authorization flows
client = Safire::Client.new(
  {
    base_url:     'https://fhir.example.com',
    client_id:    client_id,
    redirect_uri: 'https://myapp.example.com/callback',
    scopes:       ['openid', 'profile', 'patient/*.read']
  }
)
```

---

## Client Metadata

The `metadata` argument is a Hash of RFC 7591 §2 client metadata fields. Keys may be symbols or strings. Any field the server does not recognize is silently ignored; any field the server requires but you omit will produce a `RegistrationError`.

### Common fields

| Field | Type | When required | Notes |
|-------|------|--------------|-------|
| `client_name` | String | Recommended | Human-readable application name displayed in authorization prompts |
| `redirect_uris` | Array\<String\> | Required for `authorization_code` | Exact URIs the server will redirect to after authorization |
| `grant_types` | Array\<String\> | Recommended | See [Grant types](#grant-types) below |
| `token_endpoint_auth_method` | String | Recommended | See [Authentication methods](#authentication-methods) below |
| `scope` | String | Optional | Space-separated default scopes; may be narrowed per-request at runtime |
| `jwks_uri` | String | Required for `private_key_jwt` | URL of the client's JWKS endpoint; the server fetches public keys for JWT verification |
| `jwks` | Hash | Alternative to `jwks_uri` | Inline JWKS containing the client's public key(s) |
| `client_uri` | String | Optional | URL of the client's home page |

### Grant types

Pass an array containing each grant type the client intends to use.

| Value | Use |
|-------|-----|
| `authorization_code` | SMART App Launch — user-facing authorization with redirect and PKCE |
| `client_credentials` | Backend Services — system-to-system access with no user interaction |
| `refresh_token` | Token refresh; include alongside `authorization_code` when the server should issue refresh tokens |

### Authentication methods

The `token_endpoint_auth_method` value tells the server how the client will authenticate at the token endpoint. Safire supports the following methods.

| Value | Safire `client_type` | How it works |
|-------|----------------------|-------------|
| `none` | `:public` | No client authentication; `client_id` sent in the POST body |
| `client_secret_basic` | `:confidential_symmetric` | HTTP Basic auth using the `client_secret` the server issues |
| `private_key_jwt` | `:confidential_asymmetric` | Signed JWT assertion; requires `jwks_uri` or inline `jwks` in metadata |

{: .note }
If your client will use `private_key_jwt`, you must include `jwks_uri` or `jwks` in the registration metadata so the server can obtain your public key for JWT verification.

---

## Registration Endpoint

### Discovery (default)

When you do not supply `registration_endpoint:`, Safire fetches the server's SMART configuration from `/.well-known/smart-configuration` and reads the `registration_endpoint` field. Discovery is cached after the first call, so repeated calls on the same `Safire::Client` instance do not issue another network request.

```ruby
# Safire discovers the registration endpoint automatically
registration = client.register_client({ client_name: 'My App', ... })
```

If the server does not advertise a `registration_endpoint`, Safire raises `Safire::Errors::DiscoveryError`. The error message explains that you must supply the endpoint explicitly or that the server may not support DCR.

### Explicit endpoint

Pass `registration_endpoint:` to bypass discovery entirely. This is useful when the server advertises the endpoint out-of-band, when you want to skip the discovery request, or when the server does not expose `/.well-known/smart-configuration`.

```ruby
registration = client.register_client(
  { client_name: 'My App', ... },
  registration_endpoint: 'https://auth.example.com/register'
)
```

---

## Initial Access Token

Some authorization servers protect their registration endpoint with a bearer token to prevent unauthorized registrations (RFC 7591 §3.1). If the server requires one, obtain it out-of-band from the server operator and pass the full `Authorization` header value to `authorization:`.

```ruby
registration = client.register_client(
  { client_name: 'My App', ... },
  authorization: 'Bearer eyJhbGciOiJSUzI1NiJ9...'
)
```

The `authorization:` parameter accepts any valid header value. Safire passes it verbatim as the `Authorization` header, so the token type prefix (`Bearer`, `MAC`, etc.) must be included.

---

## What's Next

[Registration Response]({% link smart-on-fhir/dynamic-client-registration/response.md %}) covers what the server returns, how to persist credentials, how to build a runtime client from the response, and error handling.
