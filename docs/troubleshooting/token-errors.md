---
layout: default
title: Token and PKCE Errors
parent: Troubleshooting
nav_order: 2
---

# Token and PKCE Errors

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Token Exchange Errors

### `TokenError`: Token request failed

```
Safire::Errors::TokenError: Token request failed — HTTP 400 — invalid_grant — Authorization code has expired
```

Common OAuth error codes and their meaning:

| `error_code` | Cause | Action |
|--------------|-------|--------|
| `invalid_grant` | Code expired or already used | Codes are single-use; the user must re-authorize |
| `invalid_client` | Client ID or credentials not recognized | Verify registration and credentials |
| `invalid_request` | Missing required parameter | Check `redirect_uri` matches exactly what was registered |
| `unauthorized_client` | Client not authorized for this grant type | Verify server-side client configuration |

The `redirect_uri` in the token request must exactly match the one used in the authorization request and the one registered with the server — including trailing slashes.

### `TokenError`: Missing access token

```
Safire::Errors::TokenError: Missing access token in response; received fields: token_type, expires_in
```

The server returned a 200 response without an `access_token`. This usually means the server returned an OAuth error body with a 200 status (non-standard behaviour). Inspect the received field names in the error message to diagnose what the server actually returned.

---

## Refresh Token Errors

### `TokenError`: Refresh token invalid or expired

```
Safire::Errors::TokenError: Token request failed — HTTP 400 — invalid_grant — Refresh token expired
```

Refresh tokens expire, get revoked, or may be single-use on some servers. When a refresh fails with `invalid_grant`, re-authenticate rather than retrying:

```ruby
def refresh_access_token
  new_tokens = client.refresh_token(refresh_token: session[:refresh_token])
  session[:access_token]  = new_tokens['access_token']
  session[:refresh_token] = new_tokens['refresh_token'] if new_tokens['refresh_token']
rescue Safire::Errors::TokenError => e
  raise unless e.error_code == 'invalid_grant'

  clear_session
  redirect_to launch_path, alert: 'Session expired. Please sign in again.'
end
```

Some servers issue a new refresh token on each refresh (rotating tokens). Always update both `access_token` and `refresh_token` from the response.

---

## PKCE Errors

### Invalid `code_challenge` at the server

**Symptom:** authorization fails at the server with a PKCE-related error.

**Cause:** the `code_verifier` used in the token exchange does not match the `code_challenge` sent in the authorization request. This almost always means the verifier was regenerated rather than stored and retrieved.

Store the verifier from `authorization_url` and use it unchanged in the token exchange:

```ruby
# On launch — store the verifier
auth_data = client.authorization_url
session[:code_verifier] = auth_data[:code_verifier]

# On callback — use exactly what was stored
tokens = client.request_access_token(
  code:           params[:code],
  code_verifier:  session[:code_verifier]
)
session.delete(:code_verifier) # discard after use
```

Never call `Safire::PKCE.generate_code_verifier` in the callback — a new verifier will not match the challenge already sent to the server.
