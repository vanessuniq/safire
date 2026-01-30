---
layout: default
title: SMART Discovery
parent: SMART on FHIR
nav_order: 3
has_toc: true
---

# SMART Discovery

{: .no_toc }

<div class="code-example" markdown="1">
SMART on FHIR discovery allows clients to dynamically learn about a FHIR server's authorization capabilities before initiating the OAuth flow.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

SMART discovery fetches server metadata from the `/.well-known/smart-configuration` endpoint. This metadata includes:

- Token endpoint URL
- Authorization endpoint URL (when launch flows are supported)
- Supported grant types
- PKCE code challenge methods
- Server capabilities
- Supported scopes and authentication methods

---

## Fetching SMART Metadata

### Basic Usage

```ruby
config = Safire::ClientConfig.new(
  base_url: 'https://fhir.example.com',
  client_id: 'my_client',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile']
)

# auth_type defaults to :public when not specified
client = Safire::Client.new(config)
metadata = client.smart_metadata

# Equivalent to:
client = Safire::Client.new(config, auth_type: :public)
```

{: .note }
> **Default Auth Type**
>
> Safire defaults to `:public` when `auth_type` is not specified. This is appropriate for discovery since fetching metadata does not require authentication.

### SmartMetadata Object

The `smart_metadata` method returns a `Safire::Protocols::SmartMetadata` object:

```ruby
metadata.class
# => Safire::Protocols::SmartMetadata

# Required fields (always present for valid metadata)
metadata.token_endpoint                    # => "https://fhir.example.com/token"
metadata.grant_types_supported             # => ["authorization_code", "refresh_token"]
metadata.capabilities                      # => ["launch-ehr", "client-public", ...]
metadata.code_challenge_methods_supported  # => ["S256"]

# Conditionally required fields
metadata.authorization_endpoint            # => "https://fhir.example.com/authorize"
# Required when capabilities include "launch-ehr" or "launch-standalone"

metadata.issuer                            # => "https://fhir.example.com"
metadata.jwks_uri                          # => "https://fhir.example.com/.well-known/jwks.json"
# Required when capabilities include "sso-openid-connect"

# Optional fields
metadata.registration_endpoint             # => "https://fhir.example.com/register"
metadata.scopes_supported                  # => ["openid", "profile", "patient/*.read", ...]
metadata.response_types_supported          # => ["code"]
metadata.token_endpoint_auth_methods_supported # => ["client_secret_basic", ...]
metadata.management_endpoint               # => "https://fhir.example.com/manage"
metadata.introspection_endpoint            # => "https://fhir.example.com/introspect"
metadata.revocation_endpoint               # => "https://fhir.example.com/revoke"
metadata.associated_endpoints              # => [{"url" => "...", "capabilities" => [...]}]
metadata.user_access_brand_bundle          # => "https://fhir.example.com/brands"
metadata.user_access_brand_identifier      # => "example-brand"
```

---

## Validation

### Checking Metadata Validity

The `valid?` method performs intelligent validation based on the server's declared capabilities:

```ruby
metadata = client.smart_metadata

if metadata.valid?
  puts "Metadata is valid"
else
  puts "Missing required fields"
end
```

### Validation Rules

`valid?` checks for the presence of:

**Always Required:**
- `token_endpoint`
- `grant_types_supported`
- `capabilities`
- `code_challenge_methods_supported`

**Conditionally Required:**
- `authorization_endpoint` - when capabilities include `launch-ehr` or `launch-standalone`
- `issuer` and `jwks_uri` - when capabilities include `sso-openid-connect`

```ruby
# Example: A backend service with no launch capabilities
metadata = Safire::Protocols::SmartMetadata.new({
  'token_endpoint' => 'https://fhir.example.com/token',
  'grant_types_supported' => ['client_credentials'],
  'capabilities' => ['client-confidential-symmetric'],
  'code_challenge_methods_supported' => ['S256']
})

metadata.valid?
# => true (authorization_endpoint not required since no launch capabilities)

# Example: A server supporting standalone launch
metadata = Safire::Protocols::SmartMetadata.new({
  'token_endpoint' => 'https://fhir.example.com/token',
  'grant_types_supported' => ['authorization_code'],
  'capabilities' => ['launch-standalone', 'client-public'],
  'code_challenge_methods_supported' => ['S256']
  # Missing authorization_endpoint!
})

metadata.valid?
# => false (authorization_endpoint required for launch-standalone)
```

---

## Capability Checks

Safire provides convenience methods to check server capabilities. These methods verify both the capability flag and any required associated fields.

### Launch Modes

```ruby
# EHR-initiated launch
metadata.supports_ehr_launch?
# => true when:
#    - capabilities include "launch-ehr"
#    - AND authorization_endpoint is present

# Standalone launch
metadata.supports_standalone_launch?
# => true when:
#    - capabilities include "launch-standalone"
#    - AND authorization_endpoint is present

# POST-based authorization
metadata.supports_post_based_authorization?
# => true (if capabilities include "authorize-post")
```

### Client Types

```ruby
# Public clients (browser apps, mobile)
metadata.supports_public_clients?
# => true (if capabilities include "client-public")

# Confidential symmetric clients (server-side with client_secret)
metadata.supports_confidential_symmetric_clients?
# => true (if capabilities include "client-confidential-symmetric")

# Confidential asymmetric clients (JWT assertion)
metadata.supports_confidential_asymmetric_clients?
# => true (if capabilities include "client-confidential-asymmetric")
```

### OpenID Connect

```ruby
metadata.supports_openid_connect?
# => true when:
#    - capabilities include "sso-openid-connect"
#    - AND issuer is present
#    - AND jwks_uri is present
```

---

## Using Discovery for Client Selection

### Changing Auth Type After Discovery

Use the `auth_type=` setter to change the client's auth type based on discovered capabilities:

```ruby
# Start with default :public auth type for discovery
client = Safire::Client.new(config)
metadata = client.smart_metadata

# Switch to confidential_symmetric based on server capabilities
if metadata.supports_confidential_symmetric_clients?
  client.auth_type = :confidential_symmetric
end

# Now token requests will use Basic auth
tokens = client.request_access_token(code: code, code_verifier: verifier)
```

{: .important }
> **Auth Type Setter**
>
> The `auth_type=` setter resets the internal protocol client, ensuring subsequent token operations use the new authentication method.

### Automatic Client Type Selection

```ruby
def configure_auth_type(client)
  metadata = client.smart_metadata

  if metadata.supports_confidential_asymmetric_clients?
    client.auth_type = :confidential_asymmetric
  elsif metadata.supports_confidential_symmetric_clients?
    client.auth_type = :confidential_symmetric
  elsif metadata.supports_public_clients?
    client.auth_type = :public
  else
    raise "Server does not support any known client types"
  end
end

client = Safire::Client.new(config)  # defaults to :public
configure_auth_type(client)
```

### Validating PKCE Support

```ruby
def validate_pkce_support(metadata)
  methods = metadata.code_challenge_methods_supported || []

  unless methods.include?('S256')
    raise "Server does not support S256 PKCE (required for security)"
  end

  # Per spec, servers MUST support S256 and MUST NOT support "plain"
  if methods.include?('plain')
    Rails.logger.warn("Server advertises 'plain' PKCE - this is non-compliant")
  end
end

validate_pkce_support(client.smart_metadata)
```

### Checking Authentication Methods

```ruby
def validate_auth_methods(metadata, auth_type)
  auth_methods = metadata.token_endpoint_auth_methods_supported || []

  case auth_type
  when :confidential_symmetric
    unless auth_methods.include?('client_secret_basic')
      raise "Server does not support client_secret_basic"
    end
  when :confidential_asymmetric
    unless auth_methods.include?('private_key_jwt')
      raise "Server does not support private_key_jwt"
    end
  end
end
```

---

## Discovery Endpoint Details

### Well-Known URL Construction

Safire constructs the discovery URL by appending `/.well-known/smart-configuration` to the base URL:

```ruby
base_url = "https://fhir.example.com/r4"
# Discovery URL: https://fhir.example.com/r4/.well-known/smart-configuration

base_url = "https://fhir.example.com/r4/"  # Trailing slash
# Discovery URL: https://fhir.example.com/r4/.well-known/smart-configuration
```

### Example Response (SMART App Launch v2.2.0)

```json
{
  "issuer": "https://fhir.example.com",
  "authorization_endpoint": "https://fhir.example.com/authorize",
  "token_endpoint": "https://fhir.example.com/token",
  "jwks_uri": "https://fhir.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://fhir.example.com/register",
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "scopes_supported": [
    "openid",
    "profile",
    "launch",
    "launch/patient",
    "patient/*.read",
    "patient/*.write",
    "offline_access"
  ],
  "response_types_supported": ["code"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt"
  ],
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

---

## Error Handling

### Discovery Errors

```ruby
begin
  metadata = client.smart_metadata
rescue Safire::Errors::DiscoveryError => e
  case e.message
  when /404/
    # Server doesn't have SMART configuration
    puts "FHIR server does not support SMART on FHIR"
  when /timeout/i
    # Network timeout
    puts "Discovery request timed out"
  when /expected JSON object/
    # Invalid response format
    puts "Server returned invalid SMART configuration"
  else
    puts "Discovery failed: #{e.message}"
  end
end
```

### Graceful Fallback

```ruby
def discover_with_fallback(base_url)
  config = Safire::ClientConfig.new(
    base_url: base_url,
    client_id: ENV['SMART_CLIENT_ID'],
    redirect_uri: callback_url,
    scopes: ['openid', 'profile']
  )

  # Use default :public auth type for discovery
  client = Safire::Client.new(config)

  begin
    metadata = client.smart_metadata
    {
      authorization_endpoint: metadata.authorization_endpoint,
      token_endpoint: metadata.token_endpoint,
      source: :discovery
    }
  rescue Safire::Errors::DiscoveryError => e
    Rails.logger.warn("Discovery failed, using fallback: #{e.message}")

    # Fallback to known endpoints (if configured)
    {
      authorization_endpoint: ENV['FALLBACK_AUTH_ENDPOINT'],
      token_endpoint: ENV['FALLBACK_TOKEN_ENDPOINT'],
      source: :fallback
    }
  end
end
```

---

## Caching Metadata

Safire caches metadata within the client instance. For application-level caching:

### Rails Cache Example

```ruby
class SmartMetadataService
  CACHE_KEY = "smart_metadata"
  CACHE_DURATION = 1.hour

  def self.fetch(base_url)
    Rails.cache.fetch("#{CACHE_KEY}:#{base_url}", expires_in: CACHE_DURATION) do
      config = Safire::ClientConfig.new(
        base_url: base_url,
        client_id: ENV['SMART_CLIENT_ID'],
        redirect_uri: 'https://app.example.com/callback',
        scopes: []
      )

      # Default :public auth type for discovery
      client = Safire::Client.new(config)
      metadata = client.smart_metadata

      {
        token_endpoint: metadata.token_endpoint,
        authorization_endpoint: metadata.authorization_endpoint,
        grant_types_supported: metadata.grant_types_supported,
        capabilities: metadata.capabilities,
        code_challenge_methods_supported: metadata.code_challenge_methods_supported,
        scopes_supported: metadata.scopes_supported,
        fetched_at: Time.current
      }
    end
  end

  def self.invalidate(base_url)
    Rails.cache.delete("#{CACHE_KEY}:#{base_url}")
  end
end

# Usage
metadata = SmartMetadataService.fetch(ENV['FHIR_BASE_URL'])
```

---

## Multi-Server Support

### Discovering Multiple Servers

```ruby
class FhirServerRegistry
  def initialize
    @servers = {}
  end

  def register(name, base_url)
    config = Safire::ClientConfig.new(
      base_url: base_url,
      client_id: ENV["#{name.upcase}_CLIENT_ID"],
      redirect_uri: "https://app.example.com/callback/#{name}",
      scopes: ['openid', 'profile', 'patient/*.read']
    )

    # Default :public auth type for discovery
    client = Safire::Client.new(config)
    metadata = client.smart_metadata

    @servers[name] = {
      base_url: base_url,
      client: client,
      metadata: metadata,
      capabilities: metadata.capabilities,
      valid: metadata.valid?
    }
  rescue Safire::Errors::DiscoveryError => e
    Rails.logger.error("Failed to register #{name}: #{e.message}")
    nil
  end

  def get(name)
    @servers[name]
  end

  def all_capable_of(capability)
    @servers.select do |_, server|
      server[:capabilities].include?(capability)
    end
  end
end

# Usage
registry = FhirServerRegistry.new
registry.register(:epic, 'https://epic.example.com/fhir/r4')
registry.register(:cerner, 'https://cerner.example.com/fhir/r4')

# Find all servers supporting standalone launch
standalone_servers = registry.all_capable_of('launch-standalone')
```

---

## Reference: SMART Capabilities

| Capability | Description |
|------------|-------------|
| `launch-ehr` | Supports EHR-initiated launch |
| `launch-standalone` | Supports standalone launch |
| `authorize-post` | Supports POST-based authorization |
| `client-public` | Supports public clients |
| `client-confidential-symmetric` | Supports clients with client_secret |
| `client-confidential-asymmetric` | Supports clients with JWT assertion |
| `sso-openid-connect` | Supports OpenID Connect |
| `context-ehr-patient` | EHR launch provides patient context |
| `context-ehr-encounter` | EHR launch provides encounter context |
| `context-standalone-patient` | Standalone launch can request patient |
| `context-standalone-encounter` | Standalone launch can request encounter |
| `permission-offline` | Supports offline_access scope |
| `permission-patient` | Supports patient-level scopes |
| `permission-user` | Supports user-level scopes |
| `permission-v1` | Supports SMART v1 scopes |
| `permission-v2` | Supports SMART v2 scopes |

---

## Reference: Required vs Optional Fields

### Always Required

| Field | Type | Description |
|-------|------|-------------|
| `token_endpoint` | String | URL of OAuth2 token endpoint |
| `grant_types_supported` | Array | Supported OAuth2 grant types |
| `capabilities` | Array | SMART capabilities supported |
| `code_challenge_methods_supported` | Array | Must include "S256" |

### Conditionally Required

| Field | Type | Condition |
|-------|------|-----------|
| `authorization_endpoint` | String | When `launch-ehr` or `launch-standalone` in capabilities |
| `issuer` | String | When `sso-openid-connect` in capabilities |
| `jwks_uri` | String | When `sso-openid-connect` in capabilities |

### Optional

| Field | Type | Description |
|-------|------|-------------|
| `registration_endpoint` | String | Dynamic client registration URL |
| `scopes_supported` | Array | Available OAuth2 scopes |
| `response_types_supported` | Array | Supported response types |
| `token_endpoint_auth_methods_supported` | Array | Token endpoint auth methods |
| `introspection_endpoint` | String | Token introspection URL |
| `revocation_endpoint` | String | Token revocation URL |
| `management_endpoint` | String | User access management URL |
| `associated_endpoints` | Array | Endpoints sharing this auth |
| `user_access_brand_bundle` | String | Brand bundle URL |
| `user_access_brand_identifier` | String | Primary brand identifier |

---

## Next Steps

- [Public Client Workflow]({{ site.baseurl }}{% link smart-on-fhir/public-client.md %})
- [Confidential Symmetric Client Workflow]({{ site.baseurl }}{% link smart-on-fhir/confidential-symmetric.md %})
- [Troubleshooting Guide]({{ site.baseurl }}{% link troubleshooting.md %})
