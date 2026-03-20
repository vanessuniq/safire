---
layout: default
title: Token Exchange & Refresh
parent: Confidential Symmetric Client Workflow
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

This is where confidential symmetric clients differ from public clients. Safire automatically adds an `Authorization: Basic` header — your application code looks identical.

```ruby
def callback
  unless params[:state] == session[:oauth_state]
    Rails.logger.error("State mismatch: expected #{session[:oauth_state]}, got #{params[:state]}")
    render plain: 'Invalid state parameter', status: :unauthorized
    return
  end

  # Safire uses Basic auth automatically for :confidential_symmetric
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
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=authorization_code&
code=AUTH_CODE_FROM_CALLBACK&
redirect_uri=https://myapp.example.com/callback&
code_verifier=nioBARPNwPA8JvVQdZUPxTk6f...
```

{: .important }
> The Basic auth value is `Base64(client_id:client_secret)`. Safire constructs this automatically — `client_id` is **not** included in the request body for confidential symmetric clients.

Safire does this automatically when `client_type: :confidential_symmetric`:
1. Constructs the `Authorization: Basic` header from `client_id` and `client_secret`
2. Excludes `client_id` from the request body
3. Applies Basic auth to both token exchange and token refresh

---

## Step 4: Token Refresh

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

    # Basic auth is applied automatically
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
      base_url:      ENV.fetch('FHIR_BASE_URL'),
      client_id:     ENV.fetch('SMART_CLIENT_ID'),
      client_secret: ENV.fetch('SMART_CLIENT_SECRET'),
      redirect_uri:  callback_url,
      scopes:        ['openid', 'profile', 'patient/*.read', 'offline_access']
    )
    Safire::Client.new(config, client_type: :confidential_symmetric)
  end
end
```

The refresh request uses Basic auth in the same way as the exchange:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=

grant_type=refresh_token&
refresh_token=eyJhbGciOiJub25lIn0...
```

---

## Error Handling

| Error code | Meaning | Suggested action |
|------------|---------|-----------------|
| `invalid_client` | Wrong `client_id` or `client_secret` | Log, alert ops team, return 500 |
| `invalid_grant` | Code or refresh token expired | Redirect to launch |

```ruby
rescue Safire::Errors::TokenError => e
  case e.error_code
  when 'invalid_client'
    Rails.logger.error('Invalid client credentials — check client_id and client_secret')
    notify_operations_team('SMART client credentials invalid')
    render plain: 'Configuration error', status: :internal_server_error
  when 'invalid_grant'
    redirect_to launch_path, alert: 'Authorization expired. Please try again.'
  else
    Rails.logger.error("Token exchange failed: #{e.message}")
    render plain: 'Authorization failed', status: :unauthorized
  end
```

---

## Testing Your Integration

```bash
# .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
SMART_CLIENT_ID=your_test_client_id
SMART_CLIENT_SECRET=your_test_secret
```

{: .note }
> Register your client at [https://launch.smarthealthit.org](https://launch.smarthealthit.org). The reference server supports `client_secret_basic`.

```ruby
RSpec.describe 'SMART Confidential Symmetric Flow', type: :request do
  it 'uses Basic auth header and excludes client_id from body' do
    get '/auth/launch'
    state = session[:oauth_state]

    stub_request(:post, "#{ENV['FHIR_BASE_URL']}/token")
      .to_return(status: 200, body: {
        access_token: 'token_123', token_type: 'Bearer', expires_in: 3600
      }.to_json)

    get '/auth/callback', params: { code: 'auth_code', state: state }

    expected_basic = Base64.strict_encode64("#{ENV['SMART_CLIENT_ID']}:#{ENV['SMART_CLIENT_SECRET']}")
    expect(WebMock).to have_requested(:post, "#{ENV['FHIR_BASE_URL']}/token")
      .with { |req|
        req.headers['Authorization'] == "Basic #{expected_basic}" &&
          !req.body.include?('client_id')
      }
  end
end
```

{: .note }
> A complete Rails controller implementation is available in the [Advanced Examples]({{ site.baseurl }}/advanced/) guide.

---

**See also:** [Security Guide]({{ site.baseurl }}/security/) · [Troubleshooting]({% link troubleshooting/index.md %}) · [SMART Discovery]({% link smart-on-fhir/discovery/index.md %})
