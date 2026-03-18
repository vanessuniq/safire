---
layout: default
title: Authorization
parent: Public Client Workflow
grand_parent: SMART on FHIR
nav_order: 1
---

# Authorization

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Step 1: SMART Discovery

Before generating an authorization URL, Safire fetches the server's SMART configuration from `/.well-known/smart-configuration`. This happens lazily on first use.

```ruby
def show_capabilities
  metadata = @client.server_metadata

  render json: {
    authorization_endpoint:  metadata.authorization_endpoint,
    token_endpoint:          metadata.token_endpoint,
    capabilities:            metadata.capabilities,
    supports_public_clients: metadata.supports_public_auth?,
    supports_pkce:           metadata.code_challenge_methods_supported.include?('S256')
  }
end
```

Safire parses and validates the response and caches the metadata in the client instance. See [SMART Discovery]({% link smart-on-fhir/discovery.md %}) for full metadata reference.

---

## Step 2: Authorization Request

Generate the authorization URL and redirect the user to the SMART authorization server.

```ruby
def launch
  auth_data = @client.authorization_url

  # Store state and code_verifier server-side (never expose to client)
  session[:oauth_state]   = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

`authorization_url` returns:

```ruby
auth_data
# => {
#   auth_url:      "https://fhir.example.com/authorize?response_type=code&client_id=...",
#   state:         "5b03ee70c3ff6b00e7fcd78227fb4bff",   # 32 hex chars (128 bits)
#   code_verifier: "nioBARPNwPA8JvVQdZUPxTk6f..."        # 128 characters
# }
```

{: .important }
> Each call to `authorization_url` generates a fresh `state` and `code_verifier`. Never reuse values across authorization attempts.

The generated URL includes these parameters:

| Parameter | Value |
|-----------|-------|
| `response_type` | `code` |
| `client_id` | Your registered client identifier |
| `redirect_uri` | Your callback URL |
| `scope` | Requested permissions (space-separated) |
| `state` | CSRF protection token (32 hex chars) |
| `aud` | FHIR server being accessed |
| `code_challenge_method` | `S256` |
| `code_challenge` | `Base64URL(SHA256(code_verifier))` |

{: .note }
> **POST-Based Authorization** — If the server advertises the `authorize-post` capability, pass `method: :post` to submit the request as a form POST instead of a GET redirect. See [POST-Based Authorization]({% link smart-on-fhir/post-based-authorization.md %}) for details.

---

## EHR-Initiated Launch

When a launch is initiated from within an EHR (rather than standalone), the EHR provides a `launch` token as a query parameter. Pass it to `authorization_url`:

```ruby
def ehr_launch
  launch_token = params[:launch]

  auth_data = @client.authorization_url(launch: launch_token)

  session[:oauth_state]   = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

The `launch` parameter is included in the authorization URL. The EHR uses it to convey context (patient, encounter) that the authorization server will include in the token response.

---

**Next:** [Token Exchange & Refresh]({% link smart-on-fhir/public-client/token-exchange.md %})
