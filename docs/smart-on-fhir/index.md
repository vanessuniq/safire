---
layout: default
title: SMART on FHIR
nav_order: 4
has_children: true
permalink: /smart-on-fhir/
---

# SMART on FHIR

This section provides step-by-step guides for implementing SMART on FHIR authorization flows with Safire.

## Available Workflows

| Workflow | Description |
|----------|-------------|
| [SMART Discovery]({% link smart-on-fhir/discovery/index.md %}) | Fetching and using SMART configuration metadata |
| [Public Client]({% link smart-on-fhir/public-client/index.md %}) | Authorization flow for browser-based and mobile applications |
| [Confidential Symmetric Client]({% link smart-on-fhir/confidential-symmetric/index.md %}) | Authorization flow for server-side applications with client secrets |
| [Confidential Asymmetric Client]({% link smart-on-fhir/confidential-asymmetric/index.md %}) | Authorization flow using private_key_jwt (RSA/EC key pair) |
| [POST-Based Authorization]({% link smart-on-fhir/post-based-authorization.md %}) | Sending the authorization request as a form POST (`authorize-post` capability) |

## Choosing a Client Type

```
Is your application a server-side web application
that can securely store credentials?
        │
        ├── YES → Can you use asymmetric key pairs (RSA/EC)?
        │         │
        │         ├── YES → Confidential Asymmetric Client
        │         │         (Uses private_key_jwt with signed JWT assertions)
        │         │
        │         └── NO  → Confidential Symmetric Client
        │                   (Uses client_secret with HTTP Basic auth)
        │
        └── NO  → Public Client
                  (Uses PKCE only, no client secret)
```

## Common Flow

All SMART authorization flows follow this general pattern:

1. **Discovery** - Fetch server metadata from `/.well-known/smart-configuration`
2. **Authorization** - Generate authorization URL and redirect user
3. **Callback** - Exchange authorization code for tokens
4. **Refresh** - Refresh expired access tokens

The key differences between client types are in how they authenticate during token exchange and refresh.
