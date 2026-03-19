---
layout: default
title: Authorization
parent: Confidential Asymmetric Client Workflow
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

Before generating an authorization URL, Safire fetches the server's SMART configuration. Check that the server supports `private_key_jwt` and your preferred signing algorithm.

```ruby
def check_server_capabilities
  metadata = @client.server_metadata

  unless metadata.supports_asymmetric_auth?
    raise 'Server does not support confidential asymmetric clients'
  end

  auth_methods = metadata.token_endpoint_auth_methods_supported
  algorithms   = metadata.asymmetric_signing_algorithms_supported

  render json: {
    supports_asymmetric:     true,
    auth_methods:            auth_methods,
    signing_algorithms:      algorithms,
    supports_private_key_jwt: auth_methods&.include?('private_key_jwt'),
    supports_offline_access: metadata.scopes_supported&.include?('offline_access')
  }
end
```

See [SMART Discovery]({% link smart-on-fhir/discovery/metadata.md %}) for the full field reference, including `asymmetric_signing_algorithms_supported`.

---

## Step 2: Authorization Request

Authorization URL generation is identical to other client types — Safire handles PKCE automatically.

```ruby
def launch
  auth_data = @client.authorization_url

  session[:oauth_state]   = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

The generated URL parameters are identical to other client types. The difference surfaces at token exchange, where Safire replaces the authorization header with a signed JWT assertion in the request body.

{: .note }
> **POST-Based Authorization** — If the server advertises `authorize-post`, pass `method: :post` to `authorization_url`. See [POST-Based Authorization]({% link smart-on-fhir/post-based-authorization.md %}) for details.

---

**Next:** [Token Exchange & Refresh]({% link smart-on-fhir/confidential-asymmetric/token-exchange.md %})
