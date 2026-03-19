---
layout: default
title: Authorization
parent: Confidential Symmetric Client Workflow
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

Before generating an authorization URL, Safire fetches the server's SMART configuration from `/.well-known/smart-configuration`. You can check server capabilities to confirm confidential symmetric support before proceeding.

```ruby
def check_server_capabilities
  metadata = @client.server_metadata

  unless metadata.supports_symmetric_auth?
    raise 'Server does not support confidential symmetric clients'
  end

  auth_methods = metadata.token_endpoint_auth_methods_supported
  unless auth_methods.include?('client_secret_basic')
    raise 'Server does not support client_secret_basic'
  end

  render json: {
    supports_confidential_symmetric: true,
    auth_methods:                    auth_methods,
    supports_offline_access:         metadata.scopes_supported&.include?('offline_access')
  }
end
```

See [SMART Discovery]({% link smart-on-fhir/discovery/metadata.md %}) for the full field reference and validation rules.

---

## Step 2: Authorization Request

Authorization URL generation is identical to the public client flow — Safire handles PKCE automatically.

```ruby
def launch
  auth_data = @client.authorization_url

  session[:oauth_state]   = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

The generated URL parameters are identical to the public client. The only difference surfaces at token exchange, where Safire adds the `Authorization: Basic` header.

{: .note }
> **Offline Access** — Include `offline_access` in your scopes to obtain a refresh token for long-lived sessions.

{: .note }
> **POST-Based Authorization** — If the server advertises `authorize-post`, pass `method: :post` to `authorization_url`. See [POST-Based Authorization]({% link smart-on-fhir/post-based-authorization.md %}) for details.

---

**Next:** [Token Exchange & Refresh]({% link smart-on-fhir/confidential-symmetric/token-exchange.md %})
