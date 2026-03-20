---
layout: default
title: Token Exchange & Refresh
parent: Public Client Workflow
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

After the user authorizes, the server redirects to your callback with an authorization code. Exchange it for tokens.

```ruby
def callback
  # Verify state parameter (CSRF protection)
  unless params[:state] == session[:oauth_state]
    Rails.logger.error("State mismatch: expected #{session[:oauth_state]}, got #{params[:state]}")
    render plain: 'Invalid state parameter', status: :unauthorized
    return
  end

  tokens = @client.request_access_token(
    code:          params[:code],
    code_verifier: session[:code_verifier]
  )

  # Store tokens server-side only
  session[:access_token]     = tokens['access_token']
  session[:refresh_token]    = tokens['refresh_token']
  session[:token_expires_at] = Time.current + tokens['expires_in'].seconds

  # SMART context parameters
  session[:patient_id]   = tokens['patient']   if tokens['patient']
  session[:encounter_id] = tokens['encounter'] if tokens['encounter']

  # Clean up authorization state immediately
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
client_id=my_public_client
```

{: .note }
> Public clients include `client_id` in the request body. No `Authorization` header or `client_secret` is sent.

The token response includes:

```ruby
tokens
# => {
#   "access_token"  => "eyJhbGci...",
#   "token_type"    => "Bearer",
#   "expires_in"    => 3600,
#   "scope"         => "openid profile patient/*.read",
#   "refresh_token" => "eyJhbGci...",
#   "patient"       => "123",    # SMART context (if present)
#   "encounter"     => "456",    # SMART context (if present)
#   "id_token"      => "eyJ..."  # OpenID Connect (if requested)
# }
```

See the [Security Guide]({{ site.baseurl }}/security/#token-and-session-security) for token storage rules.

---

## Step 4: Token Refresh

Use a controller concern to automatically refresh tokens before they expire.

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
    return unless session[:access_token] && session[:token_expires_at]
    refresh_access_token if session[:token_expires_at] < 5.minutes.from_now
  end

  def refresh_access_token
    return unless session[:refresh_token]

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
    session.delete(:access_token)
    session.delete(:refresh_token)
    session.delete(:token_expires_at)
    session.delete(:patient_id)
    session.delete(:encounter_id)
  end

  def build_smart_client
    config = Safire::ClientConfig.new(
      base_url:     ENV['FHIR_BASE_URL'],
      client_id:    ENV['SMART_CLIENT_ID'],
      redirect_uri: callback_url,
      scopes:       ['openid', 'profile', 'patient/*.read']
    )
    Safire::Client.new(config, client_type: :public)
  end
end
```

**Reduced scopes on refresh** — request a subset of the original grant:

```ruby
client.refresh_token(
  refresh_token: session[:refresh_token],
  scopes: ['patient/Patient.read'] # Must be a subset of the original
)
```

---

## Error Handling

| Error code | Meaning | Suggested action |
|------------|---------|-----------------|
| `invalid_grant` | Code expired or already used | Redirect to launch |
| `invalid_client` | Client ID not recognised | Log and return 500 — configuration issue |

```ruby
rescue Safire::Errors::TokenError => e
  case e.error_code
  when 'invalid_grant'
    redirect_to launch_path, alert: 'Authorization code expired. Please try again.'
  when 'invalid_client'
    Rails.logger.error("Invalid client configuration: #{e.message}")
    render plain: 'Configuration error', status: :internal_server_error
  else
    Rails.logger.error("Token exchange failed: #{e.message}")
    render plain: 'Authorization failed', status: :unauthorized
  end
```

**Discovery errors** — catch early to surface server availability issues:

```ruby
def initialize_client
  # ...
  @client.server_metadata # Trigger discovery eagerly if desired
rescue Safire::Errors::DiscoveryError => e
  Rails.logger.error("SMART discovery failed: #{e.message}")
  render plain: 'FHIR server not available', status: :service_unavailable
end
```

---

## Testing Your Integration

Set up against the [SMART Health IT reference server](https://launch.smarthealthit.org):

```bash
# .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
SMART_CLIENT_ID=your_test_client_id
```

Steps:
1. Register your client with redirect URI `http://localhost:3000/auth/callback`
2. Start your Rails server: `rails s`
3. Visit `http://localhost:3000/auth/launch`
4. Complete the flow on the reference server
5. Verify the callback receives tokens with SMART context

```ruby
# spec/requests/smart_auth_spec.rb
RSpec.describe 'SMART Public Client Flow', type: :request do
  before do
    stub_request(:get, "#{ENV['FHIR_BASE_URL']}/.well-known/smart-configuration")
      .to_return(status: 200, body: {
        authorization_endpoint:          "#{ENV['FHIR_BASE_URL']}/authorize",
        token_endpoint:                  "#{ENV['FHIR_BASE_URL']}/token",
        capabilities:                    ['launch-standalone', 'client-public'],
        code_challenge_methods_supported: ['S256']
      }.to_json)
  end

  it 'generates authorization URL and stores state' do
    get '/auth/launch'

    expect(response).to redirect_to(/authorize/)
    expect(session[:oauth_state].length).to eq(32)
    expect(session[:code_verifier].length).to eq(128)
  end
end
```

{: .note }
> A complete Rails controller implementation is available in the [Advanced Examples]({{ site.baseurl }}/advanced/) guide.

---

**See also:** [Security Guide]({{ site.baseurl }}/security/) · [Troubleshooting]({% link troubleshooting/index.md %}) · [SMART Discovery]({% link smart-on-fhir/discovery/index.md %})
