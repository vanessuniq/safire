---
layout: default
title: Backend Services Workflow
parent: SMART
nav_order: 6
has_children: true
permalink: /smart-on-fhir/backend-services/
---

# Backend Services Workflow

{: .no_toc }

<div class="code-example" markdown="1">
System-to-system access token requests using the OAuth 2.0 `client_credentials` grant and mandatory JWT assertion authentication — no user interaction, redirect URI, or PKCE required.
</div>

---

## Overview

SMART Backend Services enables autonomous server-to-server FHIR access without involving a user. It is defined in the [SMART App Launch Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html) specification.

Instead of a redirect flow, the client:

1. Registers with the authorization server following the [confidential asymmetric registration steps](https://hl7.org/fhir/smart-app-launch/client-confidential-asymmetric.html#registering-a-client-communicating-public-keys) (required by the spec)
2. Builds a signed JWT assertion using its registered private key
3. Posts the assertion to the token endpoint with `grant_type=client_credentials`
4. Receives an access token directly — no authorization code, no callback, no PKCE

Suitable for:

- Scheduled data pipelines and batch jobs
- System integrations that run without a logged-in user
- Clinical quality reporting and analytics platforms
- Any server-to-server FHIR workflow

---

## Key Differences from App Launch

| Aspect | App Launch | Backend Services |
|--------|------------|-----------------|
| **Grant type** | `authorization_code` | `client_credentials` |
| **User interaction** | Required | None |
| **Redirect URI** | Required | Not used |
| **PKCE** | Required | Not used |
| **Client auth** | Varies by `client_type:` | JWT assertion always |
| **Scopes** | `patient/`, `user/`, `openid` | `system/` |
| **Refresh token** | Usually issued | Not issued |
| **`expires_in`** | Recommended | Required |

---

## Prerequisites: Registration, Keys, and JWKS

### Client Registration

Before making any token requests, the client **SHALL** register with the authorization server following the [confidential asymmetric client registration](https://hl7.org/fhir/smart-app-launch/client-confidential-asymmetric.html#registering-a-client-communicating-public-keys) steps defined in the SMART App Launch specification. Registration communicates the client's public key(s) to the server, either via a JWKS URI or by uploading the JWKS directly.

### Key Pair and JWKS

Backend services use the same RSA or EC key pair infrastructure as the confidential asymmetric app launch flow — key generation, JWKS publishing, and algorithm selection are identical. See the [Confidential Asymmetric Client — Prerequisites]({% link smart-on-fhir/confidential-asymmetric/index.md %}#prerequisites-keys-jwks-and-algorithm) guide for full details.

---

## Client Setup

`redirect_uri` and `scopes` are optional for backend services clients. If `scopes` is omitted, Safire defaults to `["system/*.rs"]` when `request_backend_token` is called.

```ruby
config = Safire::ClientConfig.new(
  base_url:    ENV['FHIR_BASE_URL'],
  client_id:   ENV['SMART_CLIENT_ID'],
  private_key: OpenSSL::PKey::RSA.new(ENV['SMART_PRIVATE_KEY_PEM']),
  kid:         ENV['SMART_KEY_ID'],
  scopes:      ['system/Patient.rs', 'system/Observation.rs']  # optional
)

client = Safire::Client.new(config)
```

{: .note }
> `client_type:` is not used for backend services — `request_backend_token` always authenticates via JWT assertion regardless of `client_type`.

---

## What's Next

- [Token Request]({% link smart-on-fhir/backend-services/token-request.md %}) — Requesting a token, scope/credential overrides, flow diagram, validation, error handling, and proactive renewal
- [Security Guide]({{ site.baseurl }}/security/) — Private key management and rotation
- [Confidential Asymmetric Client]({% link smart-on-fhir/confidential-asymmetric/index.md %}) — The app launch counterpart that shares the same key infrastructure
