---
layout: default
title: Advanced Examples
nav_order: 7
permalink: /advanced/
---

# Advanced Examples

{: .no_toc }

<div class="code-example" markdown="1">
Patterns for caching, multi-server management, token lifecycle, and complete Rails integration.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Metadata Caching

Safire caches SMART metadata within the client instance. In high-traffic applications you may want to share that cache across requests or processes using Rails.cache to avoid repeated HTTP calls to the FHIR server.

```ruby
# app/services/smart_metadata_service.rb
class SmartMetadataService
  CACHE_TTL = 1.hour

  def self.fetch(base_url)
    Rails.cache.fetch("smart_metadata:#{base_url}", expires_in: CACHE_TTL) do
      config = Safire::ClientConfig.new(
        base_url:     base_url,
        client_id:    'discovery_only',
        redirect_uri: 'https://example.com',
        scopes:       []
      )
      client = Safire::Client.new(config)
      client.server_metadata.to_hash
    end
  end

  def self.invalidate(base_url)
    Rails.cache.delete("smart_metadata:#{base_url}")
  end
end
```

```ruby
# Usage
metadata = SmartMetadataService.fetch('https://fhir.example.com/r4')
auth_endpoint = metadata[:authorization_endpoint]
```

{: .note }
> Cache the serialised hash (`to_hash`), not the `SmartMetadata` object itself — the object holds an HTTPClient reference that does not serialise cleanly.

---

## Multi-Server Management

Applications that connect to multiple FHIR servers can use a registry to manage one client per server, keeping each client's metadata cache isolated.

```ruby
# app/services/fhir_server_registry.rb
class FhirServerRegistry
  def initialize
    @clients = {}
    @mutex   = Mutex.new
  end

  def client_for(server_key)
    @mutex.synchronize do
      @clients[server_key] ||= build_client(server_key)
    end
  end

  def invalidate(server_key)
    @mutex.synchronize { @clients.delete(server_key) }
  end

  private

  SERVERS = {
    epic:  { base_url: ENV['EPIC_BASE_URL'],  client_id: ENV['EPIC_CLIENT_ID']  },
    cerner: { base_url: ENV['CERNER_BASE_URL'], client_id: ENV['CERNER_CLIENT_ID'] }
  }.freeze

  def build_client(server_key)
    cfg = SERVERS.fetch(server_key) { raise ArgumentError, "Unknown server: #{server_key}" }
    config = Safire::ClientConfig.new(
      base_url:     cfg[:base_url],
      client_id:    cfg[:client_id],
      redirect_uri: ENV['REDIRECT_URI'],
      scopes:       ['openid', 'profile', 'patient/*.read']
    )
    Safire::Client.new(config)
  end
end

# Shared registry — initialise once at application boot
FHIR_REGISTRY = FhirServerRegistry.new
```

```ruby
# In a controller
client   = FHIR_REGISTRY.client_for(:epic)
metadata = client.server_metadata
```

---

## Token Management

### Proactive Refresh

Check token expiry before making API calls rather than waiting for a 401:

```ruby
# app/services/token_manager.rb
class TokenManager
  EXPIRY_BUFFER = 5.minutes

  def self.valid_token(session)
    return refresh_token(session) if expiring_soon?(session)

    session[:access_token]
  end

  def self.expiring_soon?(session)
    expires_at = session[:token_expires_at]
    return true if expires_at.nil?

    Time.current >= (expires_at - EXPIRY_BUFFER)
  end

  def self.refresh_token(session)
    client        = build_client(session)
    token_params  = { refresh_token: session[:refresh_token] }
    response      = client.refresh_token(token_params)

    session[:access_token]     = response[:access_token]
    session[:refresh_token]    = response[:refresh_token] || session[:refresh_token]
    session[:token_expires_at] = Time.current + response[:expires_in].to_i.seconds

    response[:access_token]
  end
end
```

### Retry with Exponential Backoff

For transient failures during token exchange:

```ruby
def exchange_with_retry(client, params, max_attempts: 3)
  attempts = 0

  begin
    attempts += 1
    client.exchange_code_for_token(params)
  rescue Safire::Errors::TokenError => e
    raise if attempts >= max_attempts
    raise unless e.message.match?(/timeout|503|429/i)

    sleep(2**attempts)
    retry
  end
end
```

### Custom Scopes Per Request

Override the default scopes for specific actions without reconfiguring the client:

```ruby
def launch_with_scopes(client, extra_scopes: [])
  base_scopes  = ['openid', 'profile', 'patient/*.read']
  merged       = (base_scopes + extra_scopes).uniq
  client.authorization_url(scope_override: merged)
end

# Requesting additional write access for a specific workflow
url = launch_with_scopes(client, extra_scopes: ['patient/*.write', 'user/*.read'])
```

---

## Complete Rails Example

A single controller covers the full SMART authorization cycle. Only the client setup differs between client types — the controller logic is identical.

```ruby
# config/routes.rb
Rails.application.routes.draw do
  get  '/auth/launch',   to: 'smart_auth#launch'
  get  '/auth/callback', to: 'smart_auth#callback'
  post '/auth/logout',   to: 'smart_auth#logout'
end

# app/controllers/smart_auth_controller.rb
class SmartAuthController < ApplicationController
  before_action :initialize_client

  # Step 1 — Redirect user to the authorization server
  def launch
    auth_url = @client.authorization_url
    session[:pkce_verifier] = @client.code_verifier
    session[:state]         = @client.state

    redirect_to auth_url, allow_other_host: true
  end

  # Step 2 — Handle the authorization server callback
  def callback
    if params[:error]
      redirect_to root_path, alert: "Authorization failed: #{params[:error_description]}"
      return
    end

    token_response = @client.exchange_code_for_token(
      code:          params[:code],
      state:         params[:state],
      pkce_verifier: session.delete(:pkce_verifier)
    )

    session[:access_token]     = token_response[:access_token]
    session[:refresh_token]    = token_response[:refresh_token]
    session[:token_expires_at] = Time.current + token_response[:expires_in].to_i.seconds

    redirect_to dashboard_path
  end

  def logout
    reset_session
    redirect_to root_path
  end

  private

  def initialize_client
    config = Safire::ClientConfig.new(
      base_url:     ENV['FHIR_BASE_URL'],
      client_id:    ENV['SMART_CLIENT_ID'],
      redirect_uri: callback_url,
      scopes:       ['openid', 'profile', 'patient/*.read', 'offline_access']
    )

    @client = Safire::Client.new(config) # :public is the default client_type
  end
end
```

### Switching Client Types

Only `initialize_client` changes. The rest of the controller is untouched.

```ruby
# Confidential Symmetric — add client_secret
config = Safire::ClientConfig.new(
  base_url:      ENV['FHIR_BASE_URL'],
  client_id:     ENV['SMART_CLIENT_ID'],
  client_secret: ENV['SMART_CLIENT_SECRET'],   # from ENV, credentials, or secrets manager
  redirect_uri:  callback_url,
  scopes:        ['openid', 'profile', 'patient/*.read', 'offline_access']
)
@client = Safire::Client.new(config, client_type: :confidential_symmetric)

# Confidential Asymmetric — add private_key and kid
config = Safire::ClientConfig.new(
  base_url:    ENV['FHIR_BASE_URL'],
  client_id:   ENV['SMART_CLIENT_ID'],
  private_key: OpenSSL::PKey::RSA.new(File.read(ENV['SMART_PRIVATE_KEY_PATH'])),
  kid:         ENV['SMART_KEY_ID'],
  redirect_uri: callback_url,
  scopes:       ['openid', 'profile', 'patient/*.read', 'offline_access']
)
@client = Safire::Client.new(config, client_type: :confidential_asymmetric)
```

See the [Security Guide]({{ site.baseurl }}/security/) for credential loading patterns and key rotation.