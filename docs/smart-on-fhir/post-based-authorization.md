---
layout: default
title: POST-Based Authorization
parent: SMART on FHIR
nav_order: 5
has_toc: true
---

# POST-Based Authorization

{: .no_toc }

<div class="code-example" markdown="1">
SMART App Launch 2.2.0 introduces the `authorize-post` capability, allowing servers to accept the authorization request as an HTTP form POST instead of a GET redirect. This page explains when and how to use it with Safire.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

By default, SMART authorization uses a GET redirect — the user's browser is sent to the authorization server with all parameters in the query string. Servers that advertise the `authorize-post` capability also accept the authorization request as an HTTP POST with parameters in the request body.

POST-based authorization can be useful when:
- Authorization parameters are too large for a URL (e.g. rich `state` or `launch` values)
- The client prefers to avoid sensitive parameters appearing in browser history or server logs

---

## Detecting Server Support

Check whether the authorization server advertises the `authorize-post` capability before using POST mode:

```ruby
client = Safire::Client.new(config, client_type: :public)
metadata = client.server_metadata

if metadata.supports_post_based_authorization?
  puts "Server supports POST-based authorization"
end
```

---

## Generating a POST Authorization Request

Pass `method: :post` (or `method: 'post'`) to `authorization_url`:

```ruby
auth_data = client.authorization_url(method: :post)

auth_data[:auth_url]      # The bare authorization endpoint URL
auth_data[:params]        # Hash of parameters to POST as the request body
auth_data[:state]         # Store in session for CSRF verification
auth_data[:code_verifier] # Store in session for token exchange
```

The `:get` method returns `auth_url` as a fully-formed URL with query parameters. The `:post` method returns the endpoint separately from the parameters so your application can submit a form POST.

---

## Rails Example

```ruby
# app/controllers/smart_auth_controller.rb
def launch
  # Check server support (optional but recommended)
  metadata = @client.server_metadata
  use_post = metadata.supports_post_based_authorization?

  auth_data = @client.authorization_url(method: use_post ? :post : :get)

  session[:oauth_state] = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  if use_post
    # Render a form that auto-submits to the authorization endpoint
    @auth_url = auth_data[:auth_url]
    @auth_params = auth_data[:params]
    render :authorize_post
  else
    redirect_to auth_data[:auth_url], allow_other_host: true
  end
end
```

```erb
<%# app/views/smart_auth/authorize_post.html.erb %>
<form id="auth-form" method="POST" action="<%= @auth_url %>">
  <% @auth_params.each do |key, value| %>
    <input type="hidden" name="<%= key %>" value="<%= value %>">
  <% end %>
</form>

<script>
  // Auto-submit after the page loads
  document.getElementById('auth-form').submit();
</script>
```

### Response Hash Comparison

| Key           | GET (`method: :get`)                          | POST (`method: :post`)         |
|---------------|-----------------------------------------------|--------------------------------|
| `:auth_url`   | Full URL with query string parameters         | Bare authorization endpoint URL |
| `:state`      | State value (also embedded in query string)   | State value                    |
| `:code_verifier` | PKCE code verifier                         | PKCE code verifier             |
| `:params`     | Not present                                   | Hash of all authorization parameters |

The callback handling (token exchange) is identical for both methods — the authorization server always redirects back to your `redirect_uri` with an authorization code.

---

## Sinatra Example

```ruby
get '/launch' do
  auth_data = @client.authorization_url(method: :post)

  session[:state] = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  @auth_url = auth_data[:auth_url]
  @auth_params = auth_data[:params]
  erb :authorize_post
end
```

```erb
<%# views/authorize_post.erb %>
<form id="auth-form" method="POST" action="<%= @auth_url %>">
  <% @auth_params.each do |key, value| %>
    <input type="hidden" name="<%= key %>" value="<%= value %>">
  <% end %>
</form>
<script>document.getElementById('auth-form').submit();</script>
```

---

## String and Symbol Forms

Both string and symbol values are accepted:

```ruby
client.authorization_url(method: :post)   # symbol
client.authorization_url(method: 'post')  # string — also accepted
client.authorization_url(method: :get)    # default
client.authorization_url(method: 'get')   # also accepted
```

Passing any other value raises a `Safire::Errors::ConfigurationError`:

```ruby
client.authorization_url(method: :put)
# => Safire::Errors::ConfigurationError:
#      Invalid authorization method: :put. Supported methods are :get and :post
```

---

## Authorization Parameters

The parameters included in `:params` (POST) are identical to those embedded in the query string for GET:

| Parameter | Description |
|---|---|
| `response_type` | `"code"` — OAuth 2.0 authorization code flow |
| `client_id` | Your registered client identifier |
| `redirect_uri` | Callback URL for your application |
| `scope` | Requested permissions (space-separated) |
| `state` | CSRF protection token (32 hex chars, randomly generated) |
| `aud` | FHIR server being accessed |
| `code_challenge_method` | `"S256"` — PKCE using SHA-256 |
| `code_challenge` | SHA-256 hash of the code verifier |
| `launch` | EHR launch token (if provided via `launch:` argument) |

---

## Next Steps

- [Public Client Workflow]({% link smart-on-fhir/public-client.md %})
- [Confidential Symmetric Client Workflow]({% link smart-on-fhir/confidential-symmetric.md %})
- [Confidential Asymmetric Client Workflow]({% link smart-on-fhir/confidential-asymmetric.md %})
- [SMART Discovery Details]({% link smart-on-fhir/discovery.md %})
