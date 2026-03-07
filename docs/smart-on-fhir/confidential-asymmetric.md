---
layout: default
title: Confidential Asymmetric Client Workflow
parent: SMART on FHIR
nav_order: 4
has_toc: true
---

# Confidential Asymmetric Client Workflow

{: .no_toc }

<div class="code-example" markdown="1">
This guide demonstrates SMART on FHIR confidential asymmetric client integration in a **Rails application**. The patterns shown here can be adapted for Sinatra or other Ruby web frameworks.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Confidential asymmetric clients authenticate using **private_key_jwt** -- a signed JWT assertion instead of a shared client secret. This is the most secure SMART client authentication method and is required for many production healthcare deployments.

Asymmetric clients are suitable for:
- Backend services and server-side web applications
- Systems that need the highest level of authentication security
- Deployments where client secrets cannot be shared out-of-band
- Multi-tenant platforms where key rotation is operationally simpler than secret rotation

Safire implements `private_key_jwt` authentication per [SMART App Launch STU 2.2.0](https://hl7.org/fhir/smart-app-launch/client-confidential-asymmetric.html).

---

## Key Differences from Other Client Types

| Aspect | Public | Confidential Symmetric | Confidential Asymmetric |
|--------|--------|------------------------|-------------------------|
| **Credential** | None | Shared `client_secret` | RSA or EC private key |
| **Token Request Auth** | `client_id` in body | Basic auth header | JWT assertion in body |
| **Key Rotation** | N/A | Requires coordinated secret change | Publish new public key, rotate at will |
| **Algorithms** | N/A | N/A | RS384 or ES384 |
| **PKCE** | Required | Required | Required |

{: .important }
> **PKCE Still Used**
>
> Confidential asymmetric clients still use PKCE. The JWT assertion authenticates the client; PKCE protects the authorization code exchange. They serve different purposes.

---

## Prerequisites

Before starting, you need:

1. **An RSA or EC private key** -- used to sign JWT assertions
2. **A key ID (`kid`)** -- identifies which public key the server should use to verify the assertion
3. **The public key registered with the authorization server** -- the server must know your public key

### Generating Keys

```bash
# RSA key (2048-bit minimum, 4096-bit recommended)
openssl genrsa -out private_key.pem 4096

# Extract public key for server registration
openssl rsa -in private_key.pem -pubout -out public_key.pem

# --- OR ---

# EC key (P-384 curve, required for ES384)
openssl ecparam -name secp384r1 -genkey -noout -out private_key_ec.pem

# Extract public key
openssl ec -in private_key_ec.pem -pubout -out public_key_ec.pem
```

### Publishing a JWKS

The authorization server needs your public key. You can host a JWKS (JSON Web Key Set) endpoint:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "my-key-id-123",
      "use": "sig",
      "alg": "RS384",
      "n": "<base64url-encoded modulus>",
      "e": "AQAB"
    }
  ]
}
```

{: .note }
> If you provide a `jwks_uri` in your Safire configuration, it will be included as the `jku` header in JWT assertions. This helps the server locate your public key.

---

## Authorization Flow Steps

The flow is identical to other client types, but token requests include a JWT assertion:

1. **Discovery** - Fetch SMART server configuration
2. **Authorization** - Generate authorization URL with PKCE
3. **Token Exchange** - Exchange code for tokens (with JWT assertion)
4. **Token Refresh** - Refresh tokens (with JWT assertion)

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
      scopes: ['openid', 'profile', 'patient/*.read', 'offline_access'],
      private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
      kid: ENV['SMART_KEY_ID'],
      jwks_uri: ENV['SMART_JWKS_URI']  # Optional
    )

    @client = Safire::Client.new(config, auth_type: :confidential_asymmetric)
  end
end
```

### Verifying Server Support

```ruby
def check_server_capabilities
  metadata = @client.smart_metadata

  unless metadata.supports_asymmetric_auth?
    raise "Server does not support confidential asymmetric clients"
  end

  # Check supported auth methods and algorithms
  auth_methods = metadata.token_endpoint_auth_methods_supported
  algorithms = metadata.asymmetric_signing_algorithms_supported

  render json: {
    supports_asymmetric: true,
    auth_methods: auth_methods,
    signing_algorithms: algorithms,
    supports_offline_access: metadata.scopes_supported&.include?('offline_access')
  }
end
```

---

## Step 2: Authorization Request

Authorization URL generation is identical to other client types.

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

{: .note }
> **POST-Based Authorization**
>
> If the server advertises the `authorize-post` capability, you can pass `method: :post` to `authorize_url` to submit the authorization request as a form POST instead of a GET redirect. See [POST-Based Authorization]({% link smart-on-fhir/post-based-authorization.md %}) for details.

---

## Step 3: Token Exchange

This is where confidential asymmetric clients differ. Instead of a shared secret, Safire generates a signed JWT assertion and includes it in the token request body.

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
  # Safire automatically generates and includes a JWT assertion
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
rescue Safire::Errors::TokenError => e
  Rails.logger.error("Token exchange failed: #{e.message}")
  render plain: 'Authorization failed', status: :unauthorized
end
```

### Token Request Details

Safire sends a POST request with a JWT assertion in the body (no Authorization header):

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE_FROM_CALLBACK&
redirect_uri=https://myapp.example.com/callback&
code_verifier=nioBARPNwPA8JvVQdZUPxTk6f...&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6Im15LWtleS1pZCJ9...
```

{: .important }
> **Asymmetric Auth vs Other Methods**
>
> - **Confidential Asymmetric**: `client_assertion` + `client_assertion_type` in body, no Authorization header
> - **Confidential Symmetric**: Credentials in `Authorization: Basic` header
> - **Public**: `client_id` in request body, no Authorization header

### What Safire Does Automatically

When `auth_type: :confidential_asymmetric`:

1. Builds a JWT assertion with the required claims (see below)
2. Signs the JWT using your private key and the configured algorithm
3. Includes `client_assertion_type` and `client_assertion` in the request body
4. Excludes `client_id` from the request body (it is inside the JWT)
5. Sends no `Authorization` header
6. Generates a fresh JWT assertion for each request (unique `jti`, updated `exp`)

### JWT Assertion Structure

The JWT assertion contains these claims:

**Header:**

| Field | Value |
|-------|-------|
| `typ` | `JWT` |
| `alg` | `RS384` or `ES384` |
| `kid` | Your registered key ID |
| `jku` | Your JWKS URI (if configured) |

**Payload:**

| Claim | Value | Description |
|-------|-------|-------------|
| `iss` | `client_id` | Who created the assertion |
| `sub` | `client_id` | Who the assertion is about |
| `aud` | `token_endpoint` | Who the assertion is for |
| `exp` | now + 300s | Expiration (max 5 minutes per spec) |
| `jti` | UUID | Unique ID for replay protection |

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
    # JWT assertion is automatically generated for each refresh request
    new_tokens = client.refresh_token(refresh_token: session[:refresh_token])

    # Update stored tokens
    session[:access_token] = new_tokens['access_token']
    session[:token_expires_at] = Time.current + new_tokens['expires_in'].seconds

    # Some servers issue new refresh tokens
    session[:refresh_token] = new_tokens['refresh_token'] if new_tokens['refresh_token']

    Rails.logger.info("Access token refreshed successfully")
  rescue Safire::Errors::TokenError => e
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
      scopes: ['openid', 'profile', 'patient/*.read', 'offline_access'],
      private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
      kid: ENV['SMART_KEY_ID'],
      jwks_uri: ENV['SMART_JWKS_URI']
    )
    Safire::Client.new(config, auth_type: :confidential_asymmetric)
  end
end
```

### Refresh Request Details

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=eyJhbGciOiJub25lIn0...&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=eyJhbGciOiJSUzM4NCJ9...
```

{: .note }
> Each refresh request generates a fresh JWT assertion with a new `jti` and `exp`. The server verifies the signature using your registered public key.

---

## Private Key Management

### Environment Variables

```ruby
# Load PEM from file path
private_key = OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH']))

# Or load PEM from environment variable directly
private_key = OpenSSL::PKey::RSA.new(ENV['SMART_PRIVATE_KEY_PEM'])
```

```bash
# .env (NEVER commit this file)
SMART_CLIENT_ID=your_client_id
SMART_KEY_ID=my-key-id-123
SMART_PRIVATE_KEY_PATH=/path/to/private_key.pem
SMART_JWKS_URI=https://myapp.example.com/.well-known/jwks.json
```

### Rails Credentials

```bash
# Edit credentials
EDITOR="code --wait" rails credentials:edit

# config/credentials.yml.enc
smart:
  client_id: your_client_id
  kid: my-key-id-123
  private_key_pem: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
```

```ruby
# Usage
config = Safire::ClientConfig.new(
  base_url: ENV['FHIR_BASE_URL'],
  client_id: Rails.application.credentials.smart[:client_id],
  redirect_uri: callback_url,
  scopes: ['openid', 'profile', 'patient/*.read'],
  private_key: OpenSSL::PKey::RSA.new(Rails.application.credentials.smart[:private_key_pem]),
  kid: Rails.application.credentials.smart[:kid]
)
```

### Vault or AWS Secrets Manager

```ruby
# Using AWS Secrets Manager
require 'aws-sdk-secretsmanager'

def fetch_smart_private_key
  client = Aws::SecretsManager::Client.new
  secret = client.get_secret_value(secret_id: 'smart/private-key')
  OpenSSL::PKey::RSA.new(secret.secret_string)
end

config = Safire::ClientConfig.new(
  base_url: ENV['FHIR_BASE_URL'],
  client_id: ENV['SMART_CLIENT_ID'],
  redirect_uri: callback_url,
  scopes: ['openid', 'profile', 'patient/*.read'],
  private_key: fetch_smart_private_key,
  kid: ENV['SMART_KEY_ID']
)
```

---

## Algorithm Selection

Safire supports two signing algorithms required by the SMART specification:

| Algorithm | Key Type | Curve | Use Case |
|-----------|----------|-------|----------|
| **RS384** | RSA | N/A | Most common, widely supported |
| **ES384** | EC | P-384 (secp384r1) | Smaller keys, faster signing |

### Auto-Detection

If you don't specify `jwt_algorithm`, Safire detects it from the key type:

```ruby
# RSA key -> RS384 automatically
config = Safire::ClientConfig.new(
  # ...
  private_key: OpenSSL::PKey::RSA.new(File.read('rsa_key.pem')),
  kid: 'my-rsa-key'
  # jwt_algorithm not needed
)

# EC key -> ES384 automatically
config = Safire::ClientConfig.new(
  # ...
  private_key: OpenSSL::PKey::EC.generate('secp384r1'),
  kid: 'my-ec-key'
  # jwt_algorithm not needed
)
```

### Explicit Algorithm

```ruby
config = Safire::ClientConfig.new(
  # ...
  private_key: rsa_key,
  kid: 'my-key',
  jwt_algorithm: 'RS384'  # Explicit
)
```

---

## Security Best Practices

### 1. Never Expose Private Keys

```ruby
# Never: Include in client-side code or logs
render json: { private_key: @private_key.to_pem }

# Never: Commit to version control
# Add to .gitignore: *.pem, *.key, credentials.yml

# Do: Keep server-side only, load from secure storage
private_key = OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH']))
```

### 2. Use Strong Keys

```ruby
# RSA: minimum 2048-bit, 4096-bit recommended
key = OpenSSL::PKey::RSA.generate(4096)

# EC: must use P-384 curve (required by SMART spec for ES384)
key = OpenSSL::PKey::EC.generate('secp384r1')
```

### 3. Key Rotation

Asymmetric keys are easier to rotate than shared secrets:

1. Generate a new key pair with a new `kid`
2. Add the new public key to your JWKS endpoint
3. Update your application to use the new private key
4. Remove the old public key from your JWKS after a grace period

```ruby
# During rotation, your JWKS should contain both old and new keys
{
  "keys": [
    { "kid": "key-v1", "kty": "RSA", ... },
    { "kid": "key-v2", "kty": "RSA", ... }
  ]
}
```

### 4. Validate Server Support

```ruby
def validate_server_before_registration
  config = Safire::ClientConfig.new(
    base_url: ENV['FHIR_BASE_URL'],
    client_id: 'temp',
    redirect_uri: callback_url,
    scopes: ['openid']
  )

  client = Safire::Client.new(config, auth_type: :public)
  metadata = client.smart_metadata

  {
    supports_asymmetric: metadata.supports_asymmetric_auth?,
    token_auth_methods: metadata.token_endpoint_auth_methods_supported,
    supports_private_key_jwt: metadata.token_endpoint_auth_methods_supported&.include?('private_key_jwt'),
    signing_algorithms: metadata.asymmetric_signing_algorithms_supported
  }
end
```

---

## Error Handling

### Missing Asymmetric Credentials

```ruby
# If private_key or kid is missing, Safire raises a TokenError
# (wrapping a ConfigurationError from validation)
begin
  tokens = @client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )
rescue Safire::Errors::TokenError => e
  if e.message.include?('Missing required asymmetric credentials')
    Rails.logger.error("Asymmetric auth misconfigured: #{e.message}")
    render plain: 'Server configuration error', status: :internal_server_error
  else
    raise
  end
end
```

### Invalid JWT Signature

```ruby
def callback
  tokens = @client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )
rescue Safire::Errors::TokenError => e
  case e.error_code
  when 'invalid_client'
    # Server rejected the JWT assertion (wrong key, expired, bad signature)
    Rails.logger.error("JWT assertion rejected: #{e.message}")
    render plain: 'Client authentication failed', status: :unauthorized
  when 'invalid_grant'
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
rescue Safire::Errors::TokenError => e
  if e.error_code == 'invalid_grant'
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
SMART_PRIVATE_KEY_PATH=test/fixtures/private_key.pem
SMART_KEY_ID=test-key-id
```

{: .note }
> The SMART Health IT reference server supports asymmetric authentication with `private_key_jwt`. Register your public key at [https://launch.smarthealthit.org](https://launch.smarthealthit.org).

### Integration Test Example

```ruby
# spec/requests/smart_asymmetric_auth_spec.rb
require 'rails_helper'

RSpec.describe 'SMART Confidential Asymmetric Flow', type: :request do
  let(:client_id) { 'test_client' }
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:kid) { 'test-key-123' }

  before do
    stub_request(:get, "#{ENV['FHIR_BASE_URL']}/.well-known/smart-configuration")
      .to_return(
        status: 200,
        body: {
          authorization_endpoint: "#{ENV['FHIR_BASE_URL']}/authorize",
          token_endpoint: "#{ENV['FHIR_BASE_URL']}/token",
          capabilities: ['launch-standalone', 'client-confidential-asymmetric'],
          token_endpoint_auth_methods_supported: ['private_key_jwt'],
          token_endpoint_auth_signing_alg_values_supported: ['RS384'],
          code_challenge_methods_supported: ['S256']
        }.to_json
      )
  end

  describe 'POST /token (exchange)' do
    it 'uses JWT assertion in body and excludes client_id' do
      get '/auth/launch'
      state = session[:oauth_state]

      stub_request(:post, "#{ENV['FHIR_BASE_URL']}/token")
        .to_return(
          status: 200,
          body: {
            access_token: 'access_token_123',
            token_type: 'Bearer',
            expires_in: 3600
          }.to_json
        )

      get '/auth/callback', params: { code: 'auth_code', state: state }

      # Verify JWT assertion was used
      expect(WebMock).to have_requested(:post, "#{ENV['FHIR_BASE_URL']}/token")
        .with { |req|
          body = URI.decode_www_form(req.body).to_h
          body['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            body['client_assertion'].present? &&
            !body.key?('client_id') &&
            !req.headers.key?('Authorization')
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

    # Exchange code for tokens (JWT assertion generated automatically)
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
  rescue Safire::Errors::TokenError => e
    handle_token_error(e)
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
      redirect_uri: callback_url,
      scopes: ['openid', 'profile', 'patient/*.read', 'offline_access'],
      private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
      kid: ENV['SMART_KEY_ID'],
      jwks_uri: ENV['SMART_JWKS_URI']
    )

    @client = Safire::Client.new(config, auth_type: :confidential_asymmetric)
  end

  def handle_token_error(error)
    case error.error_code
    when 'invalid_client'
      Rails.logger.error("JWT assertion rejected by server")
      render plain: 'Client authentication failed', status: :unauthorized
    when 'invalid_grant'
      redirect_to launch_path, alert: 'Authorization expired. Please try again.'
    else
      Rails.logger.error("Token error: #{error.message}")
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
- [Confidential Symmetric Client Workflow]({% link smart-on-fhir/confidential-symmetric.md %})
- [SMART Discovery Details]({% link smart-on-fhir/discovery.md %})
- [Troubleshooting Guide]({% link troubleshooting.md %})
