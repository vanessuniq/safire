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

All SMART authorization flows follow this general pattern. The key differences between client types are in how they authenticate during token exchange and refresh.

```mermaid
sequenceDiagram
    participant App
    participant Safire
    participant FHIR as FHIR Server

    App->>Safire: Client.new(config)
    Note over Safire: No network call yet

    App->>Safire: authorization_url()
    Safire->>FHIR: GET /.well-known/smart-configuration
    FHIR-->>Safire: SmartMetadata (endpoints, capabilities)
    Safire-->>App: { auth_url, state, code_verifier }

    App->>FHIR: Redirect user to auth_url
    FHIR-->>App: Callback with ?code=...&state=...

    App->>Safire: request_access_token(code:, code_verifier:)
    Note over Safire: Auth method varies by client_type:<br/>public → client_id in body<br/>confidential_symmetric → Basic auth header<br/>confidential_asymmetric → JWT assertion in body
    Safire->>FHIR: POST /token
    FHIR-->>Safire: { access_token, refresh_token, expires_in, ... }
    Safire-->>App: token response Hash

    App->>Safire: refresh_token(refresh_token:)
    Safire->>FHIR: POST /token (grant_type=refresh_token)
    FHIR-->>Safire: { access_token, ... }
    Safire-->>App: new token response Hash
```
