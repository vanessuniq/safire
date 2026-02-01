---
layout: default
title: Confidential Symmetric Client Workflow
parent: SMART on FHIR
nav_order: 3
has_toc: true
---

# Confidential Symmetric Client Workflow

{: .no_toc }

<div class="code-example" markdown="1">
This guide demonstrates SMART on FHIR confidential symmetric client integration in a **Rails application**. The patterns shown here can be adapted for Sinatra or other Ruby web frameworks.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Confidential symmetric clients are applications that can securely store a client secret, such as:
- Traditional server-side web applications
- Backend services with secure credential storage
- Enterprise applications behind firewalls

Confidential symmetric clients authenticate using **HTTP Basic Authentication** with their `client_id` and `client_secret`.

---

## Key Differences from Public Clients

| Aspect | Public Client | Confidential Symmetric |
|--------|---------------|------------------------|
| **Secret Storage** | Cannot store secrets | Can securely store secrets |
| **Token Request Auth** | `client_id` in body | Basic auth header |
| **Security Layer** | PKCE only | PKCE + client secret |
| **Typical Use Case** | SPAs, mobile apps | Server-side apps |
| **Offline Access** | Limited | Full support |

{: .important }
> **PKCE Still Used**
>
> Confidential symmetric clients still use PKCE. The client secret provides an additional layer of security, not a replacement for PKCE.

---

## Authorization Flow Steps

The flow is identical to public clients, but token requests include Basic authentication:

1. **Discovery** - Fetch SMART server configuration
2. **Authorization** - Generate authorization URL with PKCE
3. **Token Exchange** - Exchange code for tokens (with Basic auth)
4. **Token Refresh** - Refresh tokens (with Basic auth)

---

## Step 1: SMART Discovery

### Code Example

```ruby
# config/routes.rb
Rails.application.routes.draw do
  get '/auth/launch', to: 'smart_auth#launch'
  get '/auth/callback', to: 'smart_auth#callback'
end

# app/controllers/smart_auth_controller.rb
class SmartAuthController < ApplicationController
  before_action :initialize_client

  private

  def initialize_client
    config = Safire::ClientConfig.new(
      base_url: ENV['FHIR_BASE_URL'],
      client_id: ENV['SMART_CLIENT_ID'],
      client_secret: ENV['SMART_CLIENT_SECRET'],  # Required for confidential
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read', 'offline_access']
    )

    @client = Safire::Client.new(config, auth_type: :confidential_symmetric)
  end
end
```

### Verifying Server Support

```ruby
def check_server_capabilities
  metadata = @client.smart_metadata

  unless metadata.supports_confidential_symmetric_clients?
    raise "Server does not support confidential symmetric clients"
  end

  # Check supported auth methods
  auth_methods = metadata.token_endpoint_auth_methods_supported
  unless auth_methods.include?('client_secret_basic')
    raise "Server does not support client_secret_basic"
  end

  render json: {
    supports_confidential_symmetric: true,
    auth_methods: auth_methods,
    supports_offline_access: metadata.scopes_supported&.include?('offline_access')
  }
end
```

---

## Step 2: Authorization Request

Authorization URL generation is identical to public clients.

### Code Example

```ruby
# app/controllers/smart_auth_controller.rb
def launch
  # Generate authorization URL with PKCE
  auth_data = @client.authorize_url

  # Store state and code_verifier in session
  session[:oauth_state] = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  # Redirect user to authorization server
  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

### Authorization URL Parameters

The URL is identical to public clients:

| Parameter | Description |
|---|---|
| `response_type=code` | OAuth 2.0 authorization code flow |
| `client_id` | Your registered client identifier |
| `redirect_uri` | Callback URL for your application |
| `scope` | Requested permissions (space-separated) |
| `state` | CSRF protection token (32 hex chars) |
| `aud` | FHIR server being accessed |
| `code_challenge_method=S256` | PKCE using SHA256 |
| `code_challenge` | SHA256 hash of code_verifier |

{: .note }
> **Offline Access**
>
> Confidential clients typically request `offline_access` scope to obtain refresh tokens for long-lived sessions.

---

## Step 3: Token Exchange

This is where confidential symmetric clients differ from public clients.

### Code Example

```ruby
# app/controllers/smart_auth_controller.rb
def callback
  # Verify state parameter (CSRF protection)
  unless params[:state] == session[:oauth_state]
    Rails.logger.error("State mismatch: expected #{session[:oauth_state]}, got #{params[:state]}")
    render plain: 'Invalid state parameter', status: :unauthorized
    return
  end

  # Exchange authorization code for tokens
  # Safire automatically uses Basic auth for confidential_symmetric clients
  tokens = @client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )

  # Store tokens securely
  session[:access_token] = tokens['access_token']
  session[:refresh_token] = tokens['refresh_token']
  session[:token_expires_at] = Time.current + tokens['expires_in'].seconds

  # Store SMART context parameters
  session[:patient_id] = tokens['patient'] if tokens['patient']
  session[:encounter_id] = tokens['encounter'] if tokens['encounter']

  # Clean up authorization state
  session.delete(:oauth_state)
  session.delete(:code_verifier)

  redirect_to patient_path(session[:patient_id])
rescue Safire::Errors::AuthError => e
  Rails.logger.error("Token exchange failed: #{e.message}")
  render plain: 'Authorization failed', status: :unauthorized
end
```

### Token Request Details

Safire sends a POST request with Basic authentication:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=authorization_code&
code=AUTH_CODE_FROM_CALLBACK&
redirect_uri=https://myapp.example.com/callback&
code_verifier=nioBARPNwPA8JvVQdZUPxTk6f...
```

{: .important }
> **Basic Auth vs Request Body**
>
> - **Confidential Symmetric**: Credentials in `Authorization: Basic` header
> - **Public**: `client_id` in request body, no Authorization header
>
> The Basic auth value is `Base64(client_id:client_secret)`.

### What Safire Does Automatically

When `auth_type: :confidential_symmetric`:

1. Constructs Basic auth header from `client_id` and `client_secret`
2. Adds `Authorization: Basic <encoded>` to token requests
3. Excludes `client_id` from the request body
4. Applies this to both token exchange and refresh

---

## Step 4: Automatic Token Refresh

### Code Example

```ruby
# app/controllers/concerns/smart_authentication.rb
module SmartAuthentication
  extend ActiveSupport::Concern

  included do
    before_action :ensure_authenticated
    before_action :ensure_valid_token
  end

  private

  def ensure_authenticated
    unless session[:access_token]
      redirect_to launch_path, alert: 'Please sign in to continue.'
    end
  end

  def ensure_valid_token
    return unless session[:access_token]
    return unless session[:token_expires_at]

    # Refresh if token expired or will expire soon (5 minute buffer)
    refresh_access_token if session[:token_expires_at] < 5.minutes.from_now
  end

  def refresh_access_token
    return unless session[:refresh_token]

    client = build_smart_client
    # Basic auth is automatically used for confidential_symmetric
    new_tokens = client.refresh_token(refresh_token: session[:refresh_token])

    # Update stored tokens
    session[:access_token] = new_tokens['access_token']
    session[:token_expires_at] = Time.current + new_tokens['expires_in'].seconds

    # Some servers issue new refresh tokens
    session[:refresh_token] = new_tokens['refresh_token'] if new_tokens['refresh_token']

    Rails.logger.info("Access token refreshed successfully")
  rescue Safire::Errors::AuthError => e
    Rails.logger.error("Token refresh failed: #{e.message}")

    # Clear invalid tokens
    clear_auth_session

    redirect_to launch_path, alert: 'Your session has expired. Please sign in again.'
  end

  def clear_auth_session
    session.delete(:access_token)
    session.delete(:refresh_token)
    session.delete(:token_expires_at)
    session.delete(:patient_id)
    session.delete(:encounter_id)
  end

  def build_smart_client
    config = Safire::ClientConfig.new(
      base_url: ENV['FHIR_BASE_URL'],
      client_id: ENV['SMART_CLIENT_ID'],
      client_secret: ENV['SMART_CLIENT_SECRET'],
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read', 'offline_access']
    )
    Safire::Client.new(config, auth_type: :confidential_symmetric)
  end
end
```

### Refresh Request Details

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=refresh_token&
refresh_token=eyJhbGciOiJub25lIn0...
```

{: .note }
> No `client_id` in the body - it's in the Basic auth header.

---

## Client Secret Management

### Environment Variables

```ruby
# config/application.rb
config.smart_credentials = {
  client_id: ENV.fetch('SMART_CLIENT_ID'),
  client_secret: ENV.fetch('SMART_CLIENT_SECRET')
}

# .env (NEVER commit this file)
SMART_CLIENT_ID=your_client_id
SMART_CLIENT_SECRET=your_secret_key
```

### Rails Credentials

```bash
# Edit credentials
EDITOR="code --wait" rails credentials:edit

# config/credentials.yml.enc
smart:
  client_id: your_client_id
  client_secret: your_secret_key
```

```ruby
# Usage
config = Safire::ClientConfig.new(
  base_url: ENV['FHIR_BASE_URL'],
  client_id: Rails.application.credentials.smart[:client_id],
  client_secret: Rails.application.credentials.smart[:client_secret],
  redirect_uri: callback_url,
  scopes: ['openid', 'profile', 'patient/*.read']
)
```

### Vault or AWS Secrets Manager

```ruby
# Using AWS Secrets Manager
require 'aws-sdk-secretsmanager'

def fetch_smart_credentials
  client = Aws::SecretsManager::Client.new
  secret = client.get_secret_value(secret_id: 'smart/credentials')
  JSON.parse(secret.secret_string)
end

credentials = fetch_smart_credentials
config = Safire::ClientConfig.new(
  base_url: ENV['FHIR_BASE_URL'],
  client_id: credentials['client_id'],
  client_secret: credentials['client_secret'],
  redirect_uri: callback_url,
  scopes: ['openid', 'profile', 'patient/*.read']
)
```

---

## Security Best Practices

### 1. Never Expose Client Secret

```ruby
# ❌ NEVER: Include in client-side code
render json: { client_secret: ENV['SMART_CLIENT_SECRET'] }

# ❌ NEVER: Log the secret
Rails.logger.info("Using secret: #{@client_secret}")

# ❌ NEVER: Commit to version control
# Add to .gitignore: .env, *.pem, credentials.yml

# ✅ DO: Keep server-side only
# The client_secret never leaves your server
```

### 2. Use HTTPS for Redirect URIs

```ruby
# ✅ Production
redirect_uri: 'https://myapp.example.com/auth/callback'

# ❌ Never use HTTP in production
redirect_uri: 'http://myapp.example.com/auth/callback'  # INSECURE
```

### 3. Validate Server Support

```ruby
def validate_server_before_registration
  config = Safire::ClientConfig.new(
    base_url: ENV['FHIR_BASE_URL'],
    client_id: 'temp',  # Will be replaced after registration
    redirect_uri: callback_url,
    scopes: ['openid']
  )

  client = Safire::Client.new(config, auth_type: :public)
  metadata = client.smart_metadata

  {
    supports_confidential_symmetric: metadata.supports_confidential_symmetric_clients?,
    token_auth_methods: metadata.token_endpoint_auth_methods_supported,
    supports_basic_auth: metadata.token_endpoint_auth_methods_supported&.include?('client_secret_basic')
  }
end
```

### 4. Secret Rotation

```ruby
# Support multiple secrets during rotation
module SmartSecretRotation
  def build_smart_client
    begin
      # Try primary secret
      create_client(primary_secret)
    rescue Safire::Errors::AuthError => e
      if e.message.include?('invalid_client')
        # Fall back to secondary during rotation
        create_client(secondary_secret)
      else
        raise
      end
    end
  end

  def primary_secret
    ENV['SMART_CLIENT_SECRET']
  end

  def secondary_secret
    ENV['SMART_CLIENT_SECRET_PREVIOUS']
  end
end
```

---

## Error Handling

### Invalid Client Credentials

```ruby
def callback
  tokens = @client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )
rescue Safire::Errors::AuthError => e
  case e.message
  when /invalid_client/
    # Client credentials are wrong
    Rails.logger.error("Invalid client credentials - check client_id and client_secret")
    notify_operations_team("SMART client credentials invalid")
    render plain: 'Configuration error', status: :internal_server_error
  when /invalid_grant/
    # Authorization code expired or already used
    redirect_to launch_path, alert: 'Authorization expired. Please try again.'
  else
    Rails.logger.error("Token exchange failed: #{e.message}")
    render plain: 'Authorization failed', status: :unauthorized
  end
end
```

### Refresh Token Expiration

```ruby
def refresh_access_token
  new_tokens = client.refresh_token(refresh_token: session[:refresh_token])
  # ...
rescue Safire::Errors::AuthError => e
  if e.message.include?('invalid_grant')
    # Refresh token expired - user must re-authorize
    Rails.logger.info("Refresh token expired for user")
    clear_auth_session
    redirect_to launch_path, alert: 'Your session has expired. Please sign in again.'
  else
    raise
  end
end
```

---

## Testing Your Integration

### Using SMART Health IT Reference Server

```ruby
# .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
SMART_CLIENT_ID=your_test_client_id
SMART_CLIENT_SECRET=your_test_secret
```

{: .note }
> The SMART Health IT reference server supports confidential symmetric clients. Register your client at [https://launch.smarthealthit.org](https://launch.smarthealthit.org).

### Integration Test Example

```ruby
# spec/requests/smart_confidential_auth_spec.rb
require 'rails_helper'

RSpec.describe 'SMART Confidential Symmetric Flow', type: :request do
  let(:client_id) { 'test_client' }
  let(:client_secret) { 'test_secret' }
  let(:basic_auth) { Base64.strict_encode64("#{client_id}:#{client_secret}") }

  before do
    stub_request(:get, "#{ENV['FHIR_BASE_URL']}/.well-known/smart-configuration")
      .to_return(
        status: 200,
        body: {
          authorization_endpoint: "#{ENV['FHIR_BASE_URL']}/authorize",
          token_endpoint: "#{ENV['FHIR_BASE_URL']}/token",
          capabilities: ['launch-standalone', 'client-confidential-symmetric'],
          token_endpoint_auth_methods_supported: ['client_secret_basic'],
          code_challenge_methods_supported: ['S256']
        }.to_json
      )
  end

  describe 'POST /token (exchange)' do
    it 'uses Basic auth header and excludes client_id from body' do
      # Setup
      get '/auth/launch'
      state = session[:oauth_state]
      code_verifier = session[:code_verifier]

      # Stub token exchange
      stub_request(:post, "#{ENV['FHIR_BASE_URL']}/token")
        .with(
          headers: { 'Authorization' => "Basic #{basic_auth}" }
        )
        .to_return(
          status: 200,
          body: {
            access_token: 'access_token_123',
            token_type: 'Bearer',
            expires_in: 3600
          }.to_json
        )

      # Execute callback
      get '/auth/callback', params: { code: 'auth_code', state: state }

      # Verify Basic auth was used and client_id was NOT in body
      expect(WebMock).to have_requested(:post, "#{ENV['FHIR_BASE_URL']}/token")
        .with { |req|
          req.headers['Authorization'] == "Basic #{basic_auth}" &&
          !req.body.include?('client_id')
        }
    end
  end
end
```

---

## Complete Working Example

<details markdown="1">
<summary>Click to expand full Rails controller example</summary>

```ruby
# app/controllers/smart_auth_controller.rb
class SmartAuthController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:callback]
  before_action :initialize_client

  def launch
    auth_data = @client.authorize_url

    session[:oauth_state] = auth_data[:state]
    session[:code_verifier] = auth_data[:code_verifier]
    session[:launch_started_at] = Time.current

    redirect_to auth_data[:auth_url], allow_other_host: true
  end

  def callback
    # Verify state
    unless params[:state] == session[:oauth_state]
      Rails.logger.error("State mismatch")
      render plain: 'Invalid state parameter', status: :unauthorized
      return
    end

    # Check for timeout (5 minute window)
    if session[:launch_started_at] < 5.minutes.ago
      Rails.logger.warn("Authorization timeout")
      redirect_to launch_path, alert: 'Authorization timed out. Please try again.'
      return
    end

    # Exchange code for tokens (Basic auth used automatically)
    tokens = @client.request_access_token(
      code: params[:code],
      code_verifier: session[:code_verifier]
    )

    # Store tokens
    session[:access_token] = tokens['access_token']
    session[:refresh_token] = tokens['refresh_token']
    session[:token_expires_at] = Time.current + tokens['expires_in'].seconds
    session[:patient_id] = tokens['patient']
    session[:scopes] = tokens['scope']

    # Clean up
    session.delete(:oauth_state)
    session.delete(:code_verifier)
    session.delete(:launch_started_at)

    redirect_to patient_path(session[:patient_id])
  rescue Safire::Errors::AuthError => e
    handle_auth_error(e)
  end

  def logout
    clear_session
    redirect_to root_path
  end

  private

  def initialize_client
    config = Safire::ClientConfig.new(
      base_url: ENV['FHIR_BASE_URL'],
      client_id: ENV['SMART_CLIENT_ID'],
      client_secret: ENV['SMART_CLIENT_SECRET'],
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read', 'offline_access']
    )

    @client = Safire::Client.new(config, auth_type: :confidential_symmetric)
  end

  def handle_auth_error(error)
    case error.message
    when /invalid_client/
      Rails.logger.error("Invalid client credentials")
      render plain: 'Configuration error', status: :internal_server_error
    when /invalid_grant/
      redirect_to launch_path, alert: 'Authorization expired. Please try again.'
    else
      Rails.logger.error("Auth error: #{error.message}")
      render plain: 'Authorization failed', status: :unauthorized
    end
  end

  def clear_session
    session.delete(:access_token)
    session.delete(:refresh_token)
    session.delete(:token_expires_at)
    session.delete(:patient_id)
    session.delete(:scopes)
  end
end
```

</details>

---

## Next Steps

- [Public Client Workflow]({% link smart-on-fhir/public-client.md %})
- [SMART Discovery Details]({% link smart-on-fhir/discovery.md %})
- [Troubleshooting Guide]({% link troubleshooting.md %})
