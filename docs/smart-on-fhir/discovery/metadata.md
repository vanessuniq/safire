---
layout: default
title: Metadata Fields and Validation
parent: SMART Discovery
grand_parent: SMART on FHIR
nav_order: 1
---

# Metadata Fields and Validation

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Field Reference

`server_metadata` returns a `Safire::Protocols::SmartMetadata` object. All fields are accessible as typed readers.

### Always Required

| Field | Type | Description |
|-------|------|-------------|
| `token_endpoint` | String | OAuth2 token endpoint URL |
| `grant_types_supported` | Array | Supported OAuth2 grant types |
| `capabilities` | Array | SMART capabilities list |
| `code_challenge_methods_supported` | Array | Must include `"S256"`, must not include `"plain"` |

### Conditionally Required

| Field | Type | Required when |
|-------|------|--------------|
| `authorization_endpoint` | String | capabilities include `launch-ehr` or `launch-standalone` |
| `issuer` | String | capabilities include `sso-openid-connect` |
| `jwks_uri` | String | capabilities include `sso-openid-connect` |

### Optional

| Field | Type | Description |
|-------|------|-------------|
| `registration_endpoint` | String | Dynamic client registration URL |
| `scopes_supported` | Array | Available OAuth2 scopes |
| `response_types_supported` | Array | Supported response types |
| `token_endpoint_auth_methods_supported` | Array | Token endpoint auth methods (e.g. `client_secret_basic`, `private_key_jwt`) |
| `token_endpoint_auth_signing_alg_values_supported` | Array | JWT signing algorithms (e.g. `RS384`, `ES384`) — used by `asymmetric_signing_algorithms_supported` |
| `introspection_endpoint` | String | Token introspection URL |
| `revocation_endpoint` | String | Token revocation URL |
| `management_endpoint` | String | User access management URL |
| `associated_endpoints` | Array | Endpoints sharing this auth server |
| `user_access_brand_bundle` | String | Brand bundle URL for user-facing apps |
| `user_access_brand_identifier` | String | Primary brand identifier |

### Example Usage

```ruby
metadata.token_endpoint                    # => "https://fhir.example.com/token"
metadata.grant_types_supported             # => ["authorization_code", "refresh_token"]
metadata.capabilities                      # => ["launch-ehr", "client-public", ...]
metadata.code_challenge_methods_supported  # => ["S256"]

# Conditionally present
metadata.authorization_endpoint            # => "https://fhir.example.com/authorize"
metadata.issuer                            # => "https://fhir.example.com"
metadata.jwks_uri                          # => "https://fhir.example.com/.well-known/jwks.json"

# Optional
metadata.registration_endpoint             # => "https://fhir.example.com/register"
metadata.scopes_supported                  # => ["openid", "profile", "patient/*.read", ...]
metadata.token_endpoint_auth_methods_supported         # => ["client_secret_basic", "private_key_jwt"]
metadata.token_endpoint_auth_signing_alg_values_supported # => ["RS384", "ES384"]
metadata.introspection_endpoint            # => "https://fhir.example.com/introspect"
metadata.revocation_endpoint               # => "https://fhir.example.com/revoke"
metadata.management_endpoint              # => "https://fhir.example.com/manage"
metadata.associated_endpoints              # => [{"url" => "...", "capabilities" => [...]}]
metadata.user_access_brand_bundle          # => "https://fhir.example.com/brands"
metadata.user_access_brand_identifier      # => "example-brand"
```

---

## Validation

`valid?` checks conformance with SMART App Launch 2.2.0 and logs a warning for each violation. It never raises — deciding whether to block on non-compliant metadata is the caller's responsibility.

```ruby
if metadata.valid?
  # All required fields present, PKCE compliant
else
  # Safire has already logged warnings for each violation
  raise 'Server metadata does not meet SMART App Launch 2.2.0 requirements'
end
```

**What `valid?` checks:**
- All always-required fields are present
- Conditional fields present when their capability is advertised
- `code_challenge_methods_supported` includes `'S256'` (SHALL per SMART 2.2.0)
- `code_challenge_methods_supported` does not include `'plain'` (SHALL NOT per SMART 2.2.0)

Example warning output:

```
WARN: SMART metadata non-compliance: required field 'authorization_endpoint' is missing
WARN: SMART metadata non-compliance: 'S256' is missing from code_challenge_methods_supported (SMART App Launch 2.2.0 requires S256)
WARN: SMART metadata non-compliance: 'plain' is present in code_challenge_methods_supported (SMART App Launch 2.2.0 prohibits plain)
```

---

## Example Server Response (SMART App Launch 2.2.0)

```json
{
  "issuer": "https://fhir.example.com",
  "authorization_endpoint": "https://fhir.example.com/authorize",
  "token_endpoint": "https://fhir.example.com/token",
  "jwks_uri": "https://fhir.example.com/.well-known/jwks.json",
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "scopes_supported": ["openid", "profile", "launch", "patient/*.read", "offline_access"],
  "response_types_supported": ["code"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "private_key_jwt"
  ],
  "token_endpoint_auth_signing_alg_values_supported": ["RS384", "ES384"],
  "code_challenge_methods_supported": ["S256"],
  "capabilities": [
    "launch-ehr",
    "launch-standalone",
    "client-public",
    "client-confidential-symmetric",
    "client-confidential-asymmetric",
    "sso-openid-connect",
    "context-ehr-patient",
    "context-ehr-encounter",
    "context-standalone-patient",
    "permission-offline",
    "permission-patient",
    "permission-user"
  ]
}
```
