---
layout: default
title: Public Client Workflow
parent: SMART on FHIR
nav_order: 1
has_toc: true
---

# Public Client Workflow (Rails)

{: .no_toc }

<div class="code-example" markdown="1">
This guide demonstrates SMART on FHIR public client integration in a **Rails application**. The patterns shown here can be adapted for Sinatra or other Ruby web frameworks.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Public clients are applications that cannot securely store a client secret, such as:
- Browser-based JavaScript applications (single-page apps)
- Native mobile applications
- Desktop applications distributed to end users

Public clients use **PKCE (Proof Key for Code Exchange)** instead of a client secret for security.

---

## Authorization Flow Steps

The SMART on FHIR public client authorization flow consists of four steps:

1. **Discovery** - Fetch SMART server configuration
2. **Authorization** - Generate authorization URL and redirect user
3. **Token Exchange** - Exchange authorization code for access token
4. **Token Refresh** - Automatically refresh expired access tokens

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
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read']
    )

    @client = Safire::Client.new(config, auth_type: :public)
  end
end
```

### What Safire Does

1. Fetches `/.well-known/smart-configuration` from the FHIR server
2. Parses and validates the response
3. Caches the metadata in the client instance

### Accessing Metadata

```ruby
def show_capabilities
  metadata = @client.smart_metadata

  render json: {
    authorization_endpoint: metadata.authorization_endpoint,
    token_endpoint: metadata.token_endpoint,
    capabilities: metadata.capabilities,
    supports_public_clients: metadata.supports_public_clients?,
    supports_pkce: metadata.code_challenge_methods_supported.include?('S256')
  }
end
```

---

## Step 2: Authorization Request

Generate the authorization URL and redirect the user to the SMART authorization server.

### Code Example

```ruby
# app/controllers/smart_auth_controller.rb
def launch
  # Generate authorization URL with PKCE
  auth_data = @client.authorize_url

  # Store state and code_verifier in session (server-side storage)
  session[:oauth_state] = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  # Redirect user to authorization server
  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

### What Safire Generates

```ruby
auth_data
# => {
#   auth_url: "https://fhir.example.com/authorize?response_type=code&client_id=...",
#   state: "5b03ee70c3ff6b00e7fcd78227fb4bff",      # 32 hex chars (128 bits)
#   code_verifier: "nioBARPNwPA8JvVQdZUPxTk6f..."   # 128 characters
# }
```

{: .important }
> **Fresh State Per Request**
>
> Each call to `authorize_url()` generates a new `state` and `code_verifier`. These values are unique per authorization attempt.

### Authorization URL Parameters

The generated URL includes:

| Parameter | Description |
|---|---|
| `response_type=code` | OAuth 2.0 authorization code flow |
| `client_id` | Your registered client identifier |
| `redirect_uri` | Callback URL for your application |
| `scope` | Requested permissions (space-separated) |
| `state` | CSRF protection token (32 hex chars) |
| `aud` | FHIR server being accessed |
| `code_challenge_method=S256` | PKCE using SHA256 |
| `code_challenge` | SHA256 hash of code_verifier (43 chars) |

### PKCE Security

PKCE protects against authorization code interception:

1. **Code Verifier**: 128-character random string
2. **Code Challenge**: `Base64URL(SHA256(verifier))`
3. Challenge sent during authorization
4. Verifier sent during token exchange
5. Server verifies: `SHA256(verifier) == challenge`

### EHR Launch with Launch Token

For EHR-initiated launches:

```ruby
def ehr_launch
  # EHR provides launch token in query parameter
  launch_token = params[:launch]

  auth_data = @client.authorize_url(launch: launch_token)

  session[:oauth_state] = auth_data[:state]
  session[:code_verifier] = auth_data[:code_verifier]

  redirect_to auth_data[:auth_url], allow_other_host: true
end
```

---

## Step 3: Token Exchange

After user authorization, exchange the authorization code for tokens.

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
  tokens = @client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )

  # Store tokens securely (server-side only)
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

Safire sends a POST request with:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE_FROM_CALLBACK&
redirect_uri=https://myapp.example.com/callback&
code_verifier=nioBARPNwPA8JvVQdZUPxTk6f...&
client_id=my_public_client
```

{: .note }
> **Public Client Authentication**
>
> Public clients include `client_id` in the request body. No `client_secret` is sent because public clients cannot securely store secrets.

### Token Response

```ruby
tokens
# => {
#   "access_token" => "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "token_type" => "Bearer",
#   "expires_in" => 3600,
#   "scope" => "openid profile patient/*.read",
#   "refresh_token" => "eyJhbGciOiJub25lIn0...",
#   "patient" => "123",      # SMART context (if present)
#   "encounter" => "456",    # SMART context (if present)
#   "id_token" => "eyJ..."   # OpenID Connect (if requested)
# }
```

---

## Step 4: Automatic Token Refresh

Automatically refresh expired access tokens using a controller concern.

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
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read']
    )
    Safire::Client.new(config, auth_type: :public)
  end
end
```

### Using the Concern

```ruby
# app/controllers/patients_controller.rb
class PatientsController < ApplicationController
  include SmartAuthentication

  def show
    # Token is automatically refreshed if needed before this action runs
    patient_id = session[:patient_id]
    access_token = session[:access_token]

    # Make FHIR API call using the access token
    @patient = fetch_patient(patient_id, access_token)
  end

  private

  def fetch_patient(patient_id, access_token)
    response = HTTParty.get(
      "#{ENV['FHIR_BASE_URL']}/Patient/#{patient_id}",
      headers: {
        'Authorization' => "Bearer #{access_token}",
        'Accept' => 'application/fhir+json'
      }
    )

    JSON.parse(response.body)
  end
end
```

### Refresh Request Details

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=eyJhbGciOiJub25lIn0...&
client_id=my_public_client
```

### Reduced Scopes

Request fewer permissions during refresh:

```ruby
def refresh_access_token_with_reduced_scopes
  return unless session[:refresh_token]

  client = build_smart_client

  # Request only a subset of original scopes
  new_tokens = client.refresh_token(
    refresh_token: session[:refresh_token],
    scopes: ['patient/Patient.read']  # Must be subset of original
  )

  # Update tokens
  session[:access_token] = new_tokens['access_token']
  session[:token_expires_at] = Time.current + new_tokens['expires_in'].seconds
  session[:refresh_token] = new_tokens['refresh_token'] if new_tokens['refresh_token']
end
```

---

## Security Best Practices

### 1. CSRF Protection (State Parameter)

```ruby
# ✅ ALWAYS verify state parameter
unless params[:state] == session[:oauth_state]
  render plain: 'Invalid state', status: :unauthorized
  return
end

# ✅ Use secure random generation (Safire does this automatically)
# State: 32 hex characters = 128 bits of entropy

# ✅ Store state server-side only
session[:oauth_state] = auth_data[:state]

# ✅ Delete after validation
session.delete(:oauth_state)
```

### 2. Token Storage

```ruby
# ✅ DO: Store in server-side session
session[:access_token] = tokens['access_token']

# ✅ DO: Store in encrypted database
user.update(encrypted_access_token: cipher.encrypt(tokens['access_token']))

# ❌ DON'T: Store in cookies
cookies[:access_token] = tokens['access_token']  # NEVER!

# ❌ DON'T: Send to client-side JavaScript
render json: { access_token: tokens['access_token'] }  # NEVER!
```

### 3. PKCE Code Verifier

```ruby
# ✅ DO: Store server-side only
session[:code_verifier] = auth_data[:code_verifier]

# ✅ DO: Delete immediately after token exchange
session.delete(:code_verifier)

# ❌ DON'T: Send to client or expose in URLs
```

### 4. HTTPS Only

```ruby
# config/environments/production.rb
config.force_ssl = true

# ✅ Ensure redirect_uri uses HTTPS in production
redirect_uri = "https://#{request.host}/auth/callback"
```

### 5. Scope Minimization

```ruby
# ✅ Request only what you need
scopes: ['patient/Patient.read', 'patient/Observation.read']

# ❌ Don't request broad wildcards unnecessarily
scopes: ['patient/*.*']  # Only if you truly need all resources
```

---

## Error Handling

### Discovery Errors

```ruby
def initialize_client
  config = Safire::ClientConfig.new(
    base_url: ENV['FHIR_BASE_URL'],
    client_id: ENV['SMART_CLIENT_ID'],
    redirect_uri: callback_url,
    scopes: ['openid', 'profile', 'patient/*.read']
  )

  @client = Safire::Client.new(config, auth_type: :public)

  # Trigger discovery to catch errors early
  @client.smart_metadata
rescue Safire::Errors::DiscoveryError => e
  Rails.logger.error("SMART discovery failed: #{e.message}")
  render plain: 'FHIR server not available', status: :service_unavailable
end
```

### Token Exchange Errors

```ruby
def callback
  # ... state validation ...

  tokens = @client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )

  # ... store tokens ...
rescue Safire::Errors::AuthError => e
  case e.message
  when /invalid_grant/
    # Authorization code expired or was already used
    redirect_to launch_path, alert: 'Authorization code expired. Please try again.'
  when /invalid_client/
    # Client ID not recognized
    Rails.logger.error("Invalid client configuration: #{e.message}")
    render plain: 'Configuration error', status: :internal_server_error
  else
    Rails.logger.error("Token exchange failed: #{e.message}")
    render plain: 'Authorization failed', status: :unauthorized
  end
end
```

### Refresh Token Errors

The automatic refresh concern handles errors gracefully:

```ruby
rescue Safire::Errors::AuthError => e
  Rails.logger.error("Token refresh failed: #{e.message}")

  # Clear invalid session state
  clear_auth_session

  # Redirect to re-authorize
  redirect_to launch_path, alert: 'Your session has expired. Please sign in again.'
end
```

---

## Testing Your Integration

### Using SMART Health IT Reference Server

```ruby
# config/environments/development.rb or .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
SMART_CLIENT_ID=your_test_client_id
```

### Testing Steps

1. Visit [https://launch.smarthealthit.org](https://launch.smarthealthit.org)
2. Register your client with redirect URI: `http://localhost:3000/auth/callback`
3. Start your Rails server: `rails s`
4. Navigate to: `http://localhost:3000/auth/launch`
5. Complete authorization flow on the reference server
6. Verify callback receives tokens

### Integration Test Example

```ruby
# spec/requests/smart_auth_spec.rb
require 'rails_helper'

RSpec.describe 'SMART Authorization Flow', type: :request do
  before do
    stub_request(:get, "#{ENV['FHIR_BASE_URL']}/.well-known/smart-configuration")
      .to_return(
        status: 200,
        body: {
          authorization_endpoint: "#{ENV['FHIR_BASE_URL']}/authorize",
          token_endpoint: "#{ENV['FHIR_BASE_URL']}/token",
          capabilities: ['launch-standalone', 'client-public'],
          code_challenge_methods_supported: ['S256']
        }.to_json
      )
  end

  describe 'GET /auth/launch' do
    it 'generates authorization URL and stores state' do
      get '/auth/launch'

      expect(response).to redirect_to(/authorize/)
      expect(session[:oauth_state]).to be_present
      expect(session[:code_verifier]).to be_present
      expect(session[:oauth_state].length).to eq(32)
      expect(session[:code_verifier].length).to eq(128)
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

    # Exchange code for tokens
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
    Rails.logger.error("Token exchange failed: #{e.message}")
    render plain: 'Authorization failed', status: :unauthorized
  end

  def logout
    session.delete(:access_token)
    session.delete(:refresh_token)
    session.delete(:patient_id)
    redirect_to root_path
  end

  private

  def initialize_client
    config = Safire::ClientConfig.new(
      base_url: ENV['FHIR_BASE_URL'],
      client_id: ENV['SMART_CLIENT_ID'],
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read']
    )

    @client = Safire::Client.new(config, auth_type: :public)
  end
end
```

</details>

---

## Next Steps

- [Confidential Symmetric Client Workflow]({{ site.baseurl }}{% link smart-on-fhir/confidential-symmetric.md %})
- [SMART Discovery Details]({{ site.baseurl }}{% link smart-on-fhir/discovery.md %})
- [Troubleshooting Guide]({{ site.baseurl }}{% link troubleshooting.md %})
