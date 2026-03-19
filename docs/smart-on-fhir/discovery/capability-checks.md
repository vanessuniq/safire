---
layout: default
title: Capability Checks and Client Selection
parent: SMART Discovery
grand_parent: SMART on FHIR
nav_order: 2
---

# Capability Checks and Client Selection

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Full Checks (`supports_*?`)

These methods verify both the capability flag **and** any required associated fields. Use them to confirm the server is fully ready for a given mode.

```ruby
# Launch modes — requires capability flag AND authorization_endpoint present
metadata.supports_ehr_launch?         # launch-ehr + authorization_endpoint
metadata.supports_standalone_launch?  # launch-standalone + authorization_endpoint

# Public clients
metadata.supports_public_auth?
# => true if capabilities include "client-public"

# Confidential symmetric — checks capability AND auth method compatibility
metadata.supports_symmetric_auth?
# => true if:
#    capabilities include "client-confidential-symmetric"
#    AND (token_endpoint_auth_methods_supported is blank
#         OR includes "client_secret_basic")

# Confidential asymmetric — checks capability, auth method, AND algorithm support
metadata.supports_asymmetric_auth?
# => true if:
#    capabilities include "client-confidential-asymmetric"
#    AND (token_endpoint_auth_methods_supported is blank
#         OR includes "private_key_jwt")
#    AND asymmetric_signing_algorithms_supported.any?

# OpenID Connect — requires capability flag, issuer, AND jwks_uri present
metadata.supports_openid_connect?

# POST-based authorization
metadata.supports_post_based_authorization?
# => true if capabilities include "authorize-post"
```

---

## Flag-Only Checks (`*_capability?`)

These check only the capability string — they do **not** verify that required fields are present. Use them for lightweight checks or when you plan to validate fields separately.

```ruby
metadata.ehr_launch_capability?        # capabilities include "launch-ehr"
metadata.standalone_launch_capability? # capabilities include "launch-standalone"
metadata.openid_connect_capability?    # capabilities include "sso-openid-connect"
```

{: .important }
> **`supports_*?` vs `*_capability?`** — `supports_ehr_launch?` returns `false` if `authorization_endpoint` is missing even when the capability flag is set. `ehr_launch_capability?` returns `true` based on the flag alone. Prefer `supports_*?` unless you have a specific reason to check the flag independently.

---

## Asymmetric Signing Algorithms

```ruby
metadata.asymmetric_signing_algorithms_supported
# Returns the intersection of server-advertised signing algorithms and
# Safire's supported set [RS384, ES384].
# If the server does not advertise algorithms, both RS384 and ES384 are assumed.
# => ["RS384", "ES384"]
```

This method powers `supports_asymmetric_auth?` internally and is also useful when selecting a signing algorithm explicitly for a confidential asymmetric client.

---

## Client Selection Based on Discovery

**Manual client type switch** — discover first, then update the client type. Already-fetched metadata is preserved; no re-discovery occurs.

```ruby
client = Safire::Client.new(config) # defaults to :public
metadata = client.server_metadata

if metadata.supports_symmetric_auth?
  client.client_type = :confidential_symmetric
end

tokens = client.request_access_token(code: code, code_verifier: verifier)
```

**Automatic selection** based on server capabilities:

```ruby
def configure_client_type(client)
  metadata = client.server_metadata

  if metadata.supports_asymmetric_auth?
    client.client_type = :confidential_asymmetric
  elsif metadata.supports_symmetric_auth?
    client.client_type = :confidential_symmetric
  elsif metadata.supports_public_auth?
    client.client_type = :public
  else
    raise 'Server does not support any known client types'
  end
end
```

---

## SMART Capabilities Reference

| Capability | Description |
|------------|-------------|
| `launch-ehr` | Supports EHR-initiated launch |
| `launch-standalone` | Supports standalone launch |
| `authorize-post` | Supports POST-based authorization |
| `client-public` | Supports public clients |
| `client-confidential-symmetric` | Supports `client_secret_basic` |
| `client-confidential-asymmetric` | Supports `private_key_jwt` |
| `sso-openid-connect` | Supports OpenID Connect |
| `context-ehr-patient` | EHR launch provides patient context |
| `context-ehr-encounter` | EHR launch provides encounter context |
| `context-standalone-patient` | Standalone launch can request patient context |
| `context-standalone-encounter` | Standalone launch can request encounter context |
| `permission-offline` | Supports `offline_access` scope |
| `permission-patient` | Supports patient-level scopes |
| `permission-user` | Supports user-level scopes |
| `permission-v1` | Supports SMART v1 scopes |
| `permission-v2` | Supports SMART v2 scopes |
