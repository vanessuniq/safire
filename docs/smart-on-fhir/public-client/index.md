---
layout: default
title: Public Client Workflow
parent: SMART
nav_order: 2
has_children: true
permalink: /smart-on-fhir/public-client/
---

# Public Client Workflow

{: .no_toc }

<div class="code-example" markdown="1">
This guide demonstrates SMART on FHIR public client integration in a **Rails application**. The patterns shown here can be adapted for Sinatra or other Ruby web frameworks.
</div>

---

## Overview

Public clients are applications that cannot securely store a client secret, such as:
- Browser-based single-page applications (SPAs)
- Native mobile applications
- Desktop applications distributed to end users

Because there is no shared secret, public clients use **PKCE (Proof Key for Code Exchange)** to prove that the party exchanging an authorization code is the same party that initiated the request. This protects against authorization code interception attacks.

---

## PKCE at a Glance

PKCE is built into Safire — you do not implement it yourself. Here is how it works:

1. **Code Verifier** — Safire generates a cryptographically random 128-character string on each launch
2. **Code Challenge** — Safire computes `Base64URL(SHA256(verifier))` and sends it with the authorization request
3. **Verification** — When you exchange the authorization code for tokens, you send the original verifier; the server re-computes the hash and confirms it matches

Store the code verifier server-side only and delete it immediately after the token exchange. See the [Security Guide]({{ site.baseurl }}/security/#pkce-code-verifier) for handling rules.

---

## Client Setup

```ruby
# config/routes.rb
Rails.application.routes.draw do
  get '/auth/launch',    to: 'smart_auth#launch'
  get '/auth/callback',  to: 'smart_auth#callback'
end

# app/controllers/smart_auth_controller.rb
class SmartAuthController < ApplicationController
  before_action :initialize_client

  private

  def initialize_client
    config = Safire::ClientConfig.new(
      base_url:      ENV['FHIR_BASE_URL'],
      client_id:     ENV['SMART_CLIENT_ID'],
      redirect_uri:  callback_url,
      scopes:        ['openid', 'profile', 'patient/*.read']
    )

    @client = Safire::Client.new(config, client_type: :public) # :public is the default client_type, so can omit to pass this.
  end
end
```

No `client_secret` is configured — public clients authenticate using PKCE only.

---

## What's Next

- [Authorization]({% link smart-on-fhir/public-client/authorization.md %}) — Discovery and generating the authorization URL
- [Token Exchange & Refresh]({% link smart-on-fhir/public-client/token-exchange.md %}) — Exchanging the code, refreshing tokens, and error handling
- [Security Guide]({{ site.baseurl }}/security/) — Token storage, CSRF protection, scope minimization
- [Advanced Examples]({{ site.baseurl }}/advanced/) — Complete Rails controller, caching, multi-server, and retry patterns