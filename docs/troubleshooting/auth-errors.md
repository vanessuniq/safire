---
layout: default
title: Discovery and Authorization Errors
parent: Troubleshooting
nav_order: 1
---

# Discovery and Authorization Errors

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Discovery Errors

### `DiscoveryError`: Failed to discover SMART configuration

```
Safire::Errors::DiscoveryError: Failed to discover SMART configuration from
https://fhir.example.com/.well-known/smart-configuration (HTTP 404)
```

**Causes:** the server does not support SMART on FHIR, `base_url` includes an extra path segment, or the server uses a non-standard discovery path.

Verify the endpoint manually:

```bash
curl -I https://fhir.example.com/.well-known/smart-configuration
```

Ensure `base_url` points to the FHIR root, not a resource path:

```ruby
# ✅ Correct
base_url: 'https://fhir.example.com/r4'

# ❌ Too specific — strip the resource type
base_url: 'https://fhir.example.com/r4/Patient'
```

If the server does not support discovery, provide endpoints manually in `ClientConfig`:

```ruby
config = Safire::ClientConfig.new(
  base_url:               'https://fhir.example.com',
  client_id:              'my_client',
  redirect_uri:           'https://myapp.com/callback',
  scopes:                 ['openid', 'profile'],
  authorization_endpoint: 'https://fhir.example.com/authorize',
  token_endpoint:         'https://fhir.example.com/token'
)
```

### `DiscoveryError`: Invalid SMART configuration format

```
Safire::Errors::DiscoveryError: ... response is not a JSON object
```

The server returned an HTML error page, a JSON array, or malformed JSON. Inspect the raw response:

```bash
curl https://fhir.example.com/.well-known/smart-configuration
```

The response must be a JSON object (`{...}`) with at least `authorization_endpoint` and `token_endpoint`.

---

## Authorization Errors

### `ConfigurationError`: Missing scopes

```
Safire::Errors::ConfigurationError: Configuration missing: scopes
```

Scopes must be provided either in `ClientConfig` or when calling `authorization_url`:

```ruby
# Option 1 — in config
config = Safire::ClientConfig.new(
  scopes: ['openid', 'profile', 'patient/*.read'],
  # ...
)

# Option 2 — per request
auth_data = client.authorization_url(
  custom_scopes: ['openid', 'profile', 'patient/Patient.read']
)
```

{: .note }
> **Backend Services:** `request_backend_token` does not raise this error — it defaults to `["system/*.rs"]` when no scopes are configured. Pass `scopes:` to override: `client.request_backend_token(scopes: ['system/Patient.rs'])`.

### State mismatch on callback

**Symptom:** authorization callback fails or state validation raises an error.

**Causes:** state not stored in session before redirect, session expired, or multiple tabs in flight.

Always store both `state` and `code_verifier` before redirecting, and validate `state` immediately on callback:

```ruby
# On launch
auth_data = client.authorization_url
session[:oauth_state]   = auth_data[:state]
session[:code_verifier] = auth_data[:code_verifier]
redirect_to auth_data[:auth_url], allow_other_host: true

# On callback
unless params[:state] == session[:oauth_state]
  render plain: 'Invalid state', status: :unauthorized
  return
end

# Delete immediately after use
session.delete(:oauth_state)
```

If the session has expired by the time the user returns, redirect them back to the launch endpoint with a user-friendly message rather than showing a raw error.
