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
| [Public Client]({{ site.baseurl }}{% link smart-on-fhir/public-client.md %}) | Authorization flow for browser-based and mobile applications |
| [Confidential Symmetric Client]({{ site.baseurl }}{% link smart-on-fhir/confidential-symmetric.md %}) | Authorization flow for server-side applications with client secrets |
| [SMART Discovery]({{ site.baseurl }}{% link smart-on-fhir/discovery.md %}) | Fetching and using SMART configuration metadata |

## Choosing a Client Type

```
Is your application a server-side web application
that can securely store a client secret?
        │
        ├── YES → Confidential Symmetric Client
        │         (Uses client_secret with HTTP Basic auth)
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
