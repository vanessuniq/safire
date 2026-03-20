---
layout: default
title: Token Exchange & Refresh
parent: Confidential Asymmetric Client Workflow
grand_parent: SMART on FHIR
nav_order: 2
---

# Token Exchange & Refresh

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Step 3: Token Exchange

Instead of a shared secret, Safire generates a signed JWT assertion and includes it in the request body. Your application code looks identical to other client types.

```ruby
def callback
  unless params[:state] == session[:oauth_state]
    Rails.logger.error("State mismatch: expected #{session[:oauth_state]}, got #{params[:state]}")
    render plain: 'Invalid state parameter', status: :unauthorized
    return
  end

  # Safire generates and signs a JWT assertion automatically
  tokens = @client.request_access_token(
    code:          params[:code],
    code_verifier: session[:code_verifier]
  )

  session[:access_token]     = tokens['access_token']
  session[:refresh_token]    = tokens['refresh_token']
  session[:token_expires_at] = Time.current + tokens['expires_in'].seconds
  session[:patient_id]       = tokens['patient']   if tokens['patient']
  session[:encounter_id]     = tokens['encounter'] if tokens['encounter']

  session.delete(:oauth_state)
  session.delete(:code_verifier)

  redirect_to patient_path(session[:patient_id])
rescue Safire::Errors::TokenError => e
  Rails.logger.error("Token exchange failed: #{e.message}")
  render plain: 'Authorization failed', status: :unauthorized
end
```

Safire sends:

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
> No `Authorization` header is sent. The `client_id` is inside the JWT assertion, not in the request body.

**What Safire does automatically** when `client_type: :confidential_asymmetric`:

1. Builds a JWT assertion with the required claims
2. Signs the JWT using your private key and the detected or configured algorithm
3. Adds `client_assertion_type` and `client_assertion` to the request body
4. Generates a fresh assertion per request (unique `jti`, updated `exp`)

**JWT assertion structure:**

| Field | Value |
|-------|-------|
| Header `alg` | `RS384` or `ES384` |
| Header `kid` | Your registered key ID |
| Header `jku` | Your JWKS URI (if configured) |
| Claim `iss` | `client_id` |
| Claim `sub` | `client_id` |
| Claim `aud` | Token endpoint URL |
| Claim `exp` | `now + 300s` (5 minutes max per spec) |
| Claim `jti` | UUID (replay protection) |

---

## Step 4: Token Refresh

Each refresh request generates a fresh JWT assertion automatically.

```ruby
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
    return unless session[:access_token] && session[:token_expires_at]
    refresh_access_token if session[:token_expires_at] < 5.minutes.from_now
  end

  def refresh_access_token
    return unless session[:refresh_token]

    # Fresh JWT assertion generated automatically per request
    new_tokens = build_smart_client.refresh_token(
      refresh_token: session[:refresh_token]
    )

    session[:access_token]     = new_tokens['access_token']
    session[:token_expires_at] = Time.current + new_tokens['expires_in'].seconds
    session[:refresh_token]    = new_tokens['refresh_token'] if new_tokens['refresh_token']
  rescue Safire::Errors::TokenError => e
    Rails.logger.error("Token refresh failed: #{e.message}")
    clear_auth_session
    redirect_to launch_path, alert: 'Your session has expired. Please sign in again.'
  end

  def clear_auth_session
    %i[access_token refresh_token token_expires_at patient_id encounter_id].each do |key|
      session.delete(key)
    end
  end

  def build_smart_client
    config = Safire::ClientConfig.new(
      base_url:     ENV['FHIR_BASE_URL'],
      client_id:    ENV['SMART_CLIENT_ID'],
      redirect_uri: callback_url,
      scopes:       ['openid', 'profile', 'patient/*.read', 'offline_access'],
      private_key:  OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
      kid:          ENV['SMART_KEY_ID'],
      jwks_uri:     ENV['SMART_JWKS_URI']
    )
    Safire::Client.new(config, client_type: :confidential_asymmetric)
  end
end
```

The refresh request includes a fresh JWT assertion:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=eyJhbGciOiJub25lIn0...&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=eyJhbGciOiJSUzM4NCJ9...
```

---

## Error Handling

| Error code | Meaning | Suggested action |
|------------|---------|-----------------|
| `invalid_client` | JWT assertion rejected (wrong key, bad signature, expired) | Log, check key config, return 500 |
| `invalid_grant` | Code or refresh token expired | Redirect to launch |

```ruby
rescue Safire::Errors::TokenError => e
  case e.error_code
  when 'invalid_client'
    Rails.logger.error("JWT assertion rejected: #{e.message}")
    render plain: 'Client authentication failed', status: :unauthorized
  when 'invalid_grant'
    redirect_to launch_path, alert: 'Authorization expired. Please try again.'
  else
    Rails.logger.error("Token exchange failed: #{e.message}")
    render plain: 'Authorization failed', status: :unauthorized
  end
```

**Missing credentials** — if `private_key` or `kid` is absent, Safire raises before the HTTP call:

```ruby
rescue Safire::Errors::TokenError => e
  if e.message.include?('Missing required asymmetric credentials')
    Rails.logger.error("Asymmetric auth misconfigured: #{e.message}")
    render plain: 'Server configuration error', status: :internal_server_error
  else
    raise
  end
```

---

## Testing Your Integration

```bash
# .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
SMART_CLIENT_ID=your_test_client_id
SMART_PRIVATE_KEY_PATH=test/fixtures/private_key.pem
SMART_KEY_ID=test-key-id
```

{: .note }
> Register your public key at [https://launch.smarthealthit.org](https://launch.smarthealthit.org). The reference server supports `private_key_jwt`.

```ruby
RSpec.describe 'SMART Confidential Asymmetric Flow', type: :request do
  it 'uses JWT assertion in body and sends no Authorization header' do
    get '/auth/launch'
    state = session[:oauth_state]

    stub_request(:post, "#{ENV['FHIR_BASE_URL']}/token")
      .to_return(status: 200, body: {
        access_token: 'token_123', token_type: 'Bearer', expires_in: 3600
      }.to_json)

    get '/auth/callback', params: { code: 'auth_code', state: state }

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
```

{: .note }
> A complete Rails controller implementation is available in the [Advanced Examples]({{ site.baseurl }}/advanced/) guide.

---

**See also:** [Security Guide]({{ site.baseurl }}/security/) · [Troubleshooting]({% link troubleshooting/index.md %}) · [SMART Discovery]({% link smart-on-fhir/discovery/index.md %})
