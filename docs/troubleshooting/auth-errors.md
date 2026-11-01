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

**Causes:** the server does not support SMART App Launch, `base_url` includes an extra path segment, or the server uses a non-standard discovery path.

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
Safire::Errors::DiscoveryError: ... response is not a usable JSON object
```

The server returned an HTML error page, a JSON array, or malformed JSON. Inspect the raw response:

```bash
curl https://fhir.example.com/.well-known/smart-configuration
```

The response body must be a JSON object (`{...}`). Safire can parse a valid raw
JSON-object string when an incorrect or missing response content type leaves it
undecoded, but that HTTP response is still non-conformant.

Missing metadata fields are handled separately from body parsing.
`server_metadata` returns a `SmartMetadata` object, and `metadata.valid?` is the
explicit structural diagnostic. An authorization or token operation raises only
when an endpoint or capability required by that operation is unavailable.

A discovered `authorization_endpoint` or `token_endpoint` must also be an
absolute HTTPS URI without a fragment component before Safire uses it. An
invalid or insecure discovered endpoint raises `DiscoveryError`; HTTP loopback
endpoints are accepted only with the explicit `allow_insecure_localhost: true`
development policy.

---

## Authorization Errors

### `ConfigurationError`: Missing `client_id`

```
Safire::Errors::ConfigurationError: Configuration missing: client_id
```

`client_id` is optional at construction but required by every authorization method. It is validated at call time, not when the client is created. Ensure `client_id` is set in `ClientConfig` before calling any flow method:

```ruby
config = Safire::ClientConfig.new(
  base_url:  'https://fhir.example.com',
  client_id: ENV.fetch('SMART_CLIENT_ID'),
  # ...
)
```

This error is raised by `authorization_url`, `request_access_token`, `refresh_token`, and `request_backend_token`.

---

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
> **Backend Services:** Since v0.6.0, `request_backend_token` raises
> `ConfigurationError` (`missing_attributes == [:scopes]`) when scopes are
> absent; the earlier `system/*.rs` fallback has been removed. Configure
> `scopes:` on `ClientConfig` or pass `scopes:` per request.

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

### `invalid_idp` on a UDAP callback

**Symptom:** the callback for a UDAP request made with `authorization_url(idp: ...)`
carries `error=invalid_idp` instead of a `code`.

**Cause:** the data holder will not use the IdP you named in `idp`. UDAP
Security STU2 §6.2: it "**MAY** reject the client app's authorization request
... using the extension error code of `invalid_idp`" when it does not trust the
IdP or cannot obtain a `client_id` with it.

**Fix:** check `state` as usual, then start a new authorization request. A
client "**MAY** attempt to obtain authorization again by specifying a different
IdP base URL in the `idp` authorization request parameter, or by making a new
authorization request without using the Tiered OAuth workflow":

```ruby
if params[:error] == 'invalid_idp'
  auth = client.authorization_url(idp: other_idp)   # or omit idp:
  session[:udap_state]         = auth[:state]
  session[:udap_code_verifier] = auth[:code_verifier]
  redirect_to auth[:auth_url]
end
```

Related failures raised by `authorization_url` itself: `ValidationError` with
`attribute == :idp` when `idp` is not an absolute HTTPS URL without a fragment,
and `DiscoveryError` when the server does not advertise `udap_to` in
`udap_profiles_supported` or `"udap"` in `scopes_supported`. See
[Tiered OAuth]({% link udap/tiered-oauth.md %}).
