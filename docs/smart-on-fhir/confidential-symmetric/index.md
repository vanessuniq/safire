---
layout: default
title: Confidential Symmetric Client Workflow
parent: SMART on FHIR
nav_order: 3
has_children: true
permalink: /smart-on-fhir/confidential-symmetric/
---

# Confidential Symmetric Client Workflow

{: .no_toc }

<div class="code-example" markdown="1">
This guide demonstrates SMART on FHIR confidential symmetric client integration in a **Rails application**. The patterns shown here can be adapted for Sinatra or other Ruby web frameworks.
</div>

---

## Overview

Confidential symmetric clients are server-side applications that can securely store a shared `client_secret`. The secret is sent with every token request using **HTTP Basic Authentication**, providing an additional authentication layer on top of PKCE.

Suitable for:
- Traditional server-side web applications
- Backend services with secure credential storage
- Enterprise applications behind firewalls

---

## Key Differences from Public Clients

| Aspect | Public Client | Confidential Symmetric |
|--------|---------------|------------------------|
| **Credential** | None | Shared `client_secret` |
| **Token Request Auth** | `client_id` in body | `Authorization: Basic` header |
| **Security Layer** | PKCE only | PKCE + client secret |
| **Typical Use Case** | SPAs, mobile apps | Server-side apps |
| **Offline Access** | Limited | Full support |

{: .important }
> **PKCE is still required.** The client secret provides an additional authentication layer, not a replacement for PKCE.

---

## Client Setup

```ruby
config = Safire::ClientConfig.new(
  base_url:      ENV.fetch('FHIR_BASE_URL'),
  client_id:     ENV.fetch('SMART_CLIENT_ID'),
  client_secret: ENV.fetch('SMART_CLIENT_SECRET'),
  redirect_uri:  callback_url,
  scopes:        ['openid', 'profile', 'patient/*.read', 'offline_access']
)

@client = Safire::Client.new(config, client_type: :confidential_symmetric)
```

Load `client_secret` from an environment variable, Rails credentials, or a secrets manager — never hard-code it. See the [Security Guide]({{ site.baseurl }}/security/#credential-protection) for loading patterns and rotation.

---

## What's Next

- [Authorization]({% link smart-on-fhir/confidential-symmetric/authorization.md %}) — Discovery and generating the authorization URL
- [Token Exchange & Refresh]({% link smart-on-fhir/confidential-symmetric/token-exchange.md %}) — Basic auth token requests, refresh, and error handling
- [Security Guide]({{ site.baseurl }}/security/) — Secret management and rotation
