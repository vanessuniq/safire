---
layout: default
title: Configuration
nav_order: 3
---

# Configuration

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Client Configuration

Safire accepts configuration either as a Hash or a `Safire::ClientConfig` object. When you pass a Hash, Safire automatically wraps it in a `ClientConfig`.

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `base_url` | String | FHIR server base URL |
| `client_id` | String | OAuth2 client identifier |
| `redirect_uri` | String | Registered callback URL |

### Optional Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_secret` | String | Required for confidential symmetric clients |
| `scopes` | Array | Default scopes for authorization requests |
| `authorization_endpoint` | String | Override discovered endpoint |
| `token_endpoint` | String | Override discovered endpoint |

---

## Creating a Client

### Using a Hash (Recommended)

The simplest approach is to pass configuration directly as a Hash:

```ruby
client = Safire::Client.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)
```

### Using ClientConfig

You can also explicitly create a `ClientConfig` first:

```ruby
config = Safire::ClientConfig.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

client = Safire::Client.new(config)
```

This approach is useful when you need to reuse the same configuration for multiple clients or inspect the configuration before creating a client.

---

## Auth Types

### Public Client (Default)

```ruby
# auth_type defaults to :public when not specified
client = Safire::Client.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

# Explicit:
client = Safire::Client.new(config, auth_type: :public)
```

### Confidential Symmetric Client

```ruby
client = Safire::Client.new(
  {
    base_url: 'https://fhir.example.com/r4',
    client_id: 'my_client_id',
    client_secret: ENV['SMART_CLIENT_SECRET'],
    redirect_uri: 'https://myapp.com/callback',
    scopes: ['openid', 'profile', 'patient/*.read']
  },
  auth_type: :confidential_symmetric
)
```

### Changing Auth Type

You can change the auth type after initialization:

```ruby
# Start with default :public for discovery
client = Safire::Client.new(config)
metadata = client.smart_metadata

# Switch to confidential_symmetric based on server capabilities
if metadata.supports_confidential_symmetric_clients?
  client.auth_type = :confidential_symmetric
end
```

---

## Supported Auth Types

| Auth Type | Description | Authentication Method |
|-----------|-------------|----------------------|
| `:public` | Public client using PKCE | `client_id` in request body |
| `:confidential_symmetric` | Confidential client with secret | HTTP Basic auth header |
| `:confidential_asymmetric` | Confidential client with JWT | JWT assertion (planned) |

---

## Manual Endpoints

If you need to bypass discovery or provide custom endpoints:

```ruby
client = Safire::Client.new(
  base_url: 'https://fhir.example.com/r4',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile'],
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/token'
)
```

When endpoints are provided, Safire uses them directly instead of fetching from `/.well-known/smart-configuration`.

---

## Logging Configuration

Configure Safire's logger for debugging:

```ruby
# config/initializers/safire.rb
Safire.configure do |config|
  config.logger = Rails.logger
  config.log_level = Logger::DEBUG  # In development
end
```

### Log Levels

| Level | Description |
|-------|-------------|
| `Logger::DEBUG` | Detailed request/response logging |
| `Logger::INFO` | Standard operation logging |
| `Logger::WARN` | Warnings only |
| `Logger::ERROR` | Errors only |

---

## Environment-Based Configuration

### Rails Example

```ruby
# config/initializers/safire.rb
Safire.configure do |config|
  config.logger = Rails.logger
  config.log_level = Rails.env.development? ? Logger::DEBUG : Logger::INFO
end

# app/services/smart_client_service.rb
class SmartClientService
  def self.build_client(auth_type: :public)
    Safire::Client.new(
      {
        base_url: ENV.fetch('FHIR_BASE_URL'),
        client_id: ENV.fetch('SMART_CLIENT_ID'),
        client_secret: ENV['SMART_CLIENT_SECRET'],
        redirect_uri: Rails.application.routes.url_helpers.smart_callback_url,
        scopes: ENV.fetch('SMART_SCOPES', 'openid profile patient/*.read').split
      },
      auth_type: auth_type
    )
  end
end
```

### Environment Variables

```bash
# .env
FHIR_BASE_URL=https://fhir.example.com/r4
SMART_CLIENT_ID=my_client_id
SMART_CLIENT_SECRET=my_client_secret  # For confidential clients
SMART_SCOPES="openid profile patient/*.read"
```

---

## Next Steps

- [SMART on FHIR Workflows]({{ site.baseurl }}/smart-on-fhir/) - Implementation guides
- [Troubleshooting]({{ site.baseurl }}/troubleshooting/) - Common issues and solutions
- [API Reference]({{ site.baseurl }}/api/) - Complete YARD documentation
