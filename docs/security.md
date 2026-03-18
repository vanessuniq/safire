---
layout: default
title: Security Guide
nav_order: 6
permalink: /security/
---

# Security Guide

{: .no_toc }

This guide covers security requirements and best practices for every Safire integration, regardless of client type. Apply these rules in all production deployments.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## HTTPS and Redirect URI Rules

All production FHIR integrations must use HTTPS. Safire enforces this at configuration time — HTTP redirect URIs are rejected in non-localhost environments.

```ruby
# config/environments/production.rb
config.force_ssl = true
```

```ruby
# ✅ Always use HTTPS in production
config = Safire::ClientConfig.new(
  redirect_uri: 'https://myapp.example.com/auth/callback',
  # ...
)

# ❌ Raises Safire::Errors::ConfigurationError
config = Safire::ClientConfig.new(
  redirect_uri: 'http://myapp.example.com/auth/callback',
  # ...
)
```

Localhost is permitted during development:

```ruby
# ✅ Allowed for local development only
redirect_uri: 'http://localhost:3000/auth/callback'
```

---

## Credential Protection

Never expose client secrets or private keys in logs, responses, or version control.

### Client Secrets (Confidential Symmetric)

```ruby
# ❌ NEVER: log the secret
Rails.logger.info("Using secret: #{client_secret}")

# ❌ NEVER: render in a response
render json: { client_secret: ENV['SMART_CLIENT_SECRET'] }

# ❌ NEVER: commit .env to version control
# Add to .gitignore: .env
```

Load secrets from a secure source:

```ruby
# Environment variable
config = Safire::ClientConfig.new(
  client_secret: ENV.fetch('SMART_CLIENT_SECRET'),
  # ...
)

# Rails credentials
config = Safire::ClientConfig.new(
  client_secret: Rails.application.credentials.smart[:client_secret],
  # ...
)

# AWS Secrets Manager
require 'aws-sdk-secretsmanager'

def fetch_client_secret
  client = Aws::SecretsManager::Client.new
  secret = client.get_secret_value(secret_id: 'smart/credentials')
  JSON.parse(secret.secret_string)['client_secret']
end
```

### Private Keys (Confidential Asymmetric)

```ruby
# ❌ NEVER: render or log the key
render json: { private_key: @private_key.to_pem }

# Add to .gitignore: *.pem, *.key
```

Load private keys securely:

```ruby
# From a file path
private_key = OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH']))

# From a PEM string in an env var
private_key = OpenSSL::PKey::RSA.new(ENV['SMART_PRIVATE_KEY_PEM'])

# From Rails credentials
private_key = OpenSSL::PKey::RSA.new(
  Rails.application.credentials.smart[:private_key_pem]
)

# From AWS Secrets Manager
def fetch_private_key
  client = Aws::SecretsManager::Client.new
  secret = client.get_secret_value(secret_id: 'smart/private-key')
  OpenSSL::PKey::RSA.new(secret.secret_string)
end
```

Use strong keys:

```ruby
# RSA: minimum 2048-bit, 4096-bit recommended
key = OpenSSL::PKey::RSA.generate(4096)

# EC: must use P-384 curve (required by SMART spec for ES384)
key = OpenSSL::PKey::EC.generate('secp384r1')
```

{: .note }
> Safire automatically masks `client_secret` and `private_key` in `inspect` output and error messages, so they will not appear in Rails logs even if a `ClientConfig` object is accidentally logged.

---

## Token and Session Security

### Token Storage

Always store tokens server-side. Never expose them to client-side code.

```ruby
# ✅ DO: Server-side session
session[:access_token] = tokens['access_token']

# ✅ DO: Encrypted database column
user.update(encrypted_access_token: cipher.encrypt(tokens['access_token']))

# ❌ DON'T: Plain cookie
cookies[:access_token] = tokens['access_token']

# ❌ DON'T: JSON response to the browser
render json: { access_token: tokens['access_token'] }
```

### CSRF State Parameter

Safire generates a 32-character hex state value (128 bits of entropy) automatically. Always verify it on callback and delete it immediately after:

```ruby
def callback
  unless params[:state] == session[:oauth_state]
    render plain: 'Invalid state', status: :unauthorized
    return
  end

  # ... exchange code for tokens ...

  session.delete(:oauth_state)   # ✅ Delete after validation
  session.delete(:code_verifier) # ✅ Delete after token exchange
end
```

### PKCE Code Verifier

Safire generates the code verifier automatically. Store it server-side only and discard it immediately after the token exchange — never send it to the client or include it in a URL.

```ruby
# Store on launch
session[:code_verifier] = auth_data[:code_verifier]

# Delete immediately after exchange
session.delete(:code_verifier)
```

---

## Key Rotation and Scope Minimization

### Symmetric Secret Rotation

Support two secrets during rotation to allow a zero-downtime rollover:

```ruby
module SmartSecretRotation
  def build_smart_client
    create_client(primary_secret)
  rescue Safire::Errors::TokenError => e
    raise unless e.error_code == 'invalid_client'
    create_client(secondary_secret) # Fall back during rotation
  end

  def primary_secret   = ENV['SMART_CLIENT_SECRET']
  def secondary_secret = ENV['SMART_CLIENT_SECRET_PREVIOUS']
end
```

### Asymmetric Key Rotation

Publish both old and new public keys simultaneously in your JWKS endpoint during rotation:

```json
{
  "keys": [
    { "kid": "key-v1", "kty": "RSA", "use": "sig", ... },
    { "kid": "key-v2", "kty": "RSA", "use": "sig", ... }
  ]
}
```

Rotation steps:
1. Generate a new key pair with a new `kid`
2. Add the new public key to your JWKS endpoint
3. Update your application to use the new private key
4. Remove the old public key from JWKS after a grace period (allow in-flight tokens to expire)

### Scope Minimization

Request only the scopes your application needs. Broad wildcard scopes increase the impact of a compromised token.

```ruby
# ✅ Request specific resource types
scopes: ['patient/Patient.read', 'patient/Observation.read']

# ❌ Avoid unless truly necessary
scopes: ['patient/*.*']
```

You can also reduce scopes at refresh time:

```ruby
client.refresh_token(
  refresh_token: session[:refresh_token],
  scopes: ['patient/Patient.read'] # Must be a subset of the original grant
)
```

---

*See also: [Configuration Guide]({{ site.baseurl }}/configuration/) for `ssl_options` and `log_http` settings that affect security behaviour.*
