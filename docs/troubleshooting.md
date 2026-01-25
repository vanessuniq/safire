---
layout: default
title: Troubleshooting
nav_order: 4
---

# Troubleshooting

{: .no_toc }

<div class="code-example" markdown="1">
Common issues and solutions when integrating SMART on FHIR with Safire.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Discovery Errors

### DiscoveryError: Failed to discover SMART configuration

**Symptoms:**
```ruby
Safire::Errors::DiscoveryError: Failed to discover SMART configuration: "HTTP request failed: the server responded with status 404"
```

**Causes:**
- The FHIR server doesn't support SMART on FHIR
- Incorrect `base_url` configuration
- The server uses a non-standard configuration path

**Solutions:**

1. Verify the server supports SMART on FHIR:
   ```bash
   curl -I https://fhir.example.com/.well-known/smart-configuration
   ```

2. Check your `base_url` is correct (no trailing path segments):
   ```ruby
   # Correct
   base_url: 'https://fhir.example.com/fhir/r4'

   # Incorrect - extra path
   base_url: 'https://fhir.example.com/fhir/r4/Patient'
   ```

3. If the server doesn't support discovery, provide endpoints manually:
   ```ruby
   config = Safire::ClientConfig.new(
     base_url: 'https://fhir.example.com',
     client_id: 'my_client',
     redirect_uri: 'https://myapp.com/callback',
     scopes: ['openid', 'profile'],
     authorization_endpoint: 'https://fhir.example.com/authorize',
     token_endpoint: 'https://fhir.example.com/token'
   )
   ```

### DiscoveryError: Invalid SMART configuration format

**Symptoms:**
```ruby
Safire::Errors::DiscoveryError: Invalid SMART configuration format: expected JSON object but received "..."
```

**Causes:**
- Server returns HTML error page instead of JSON
- Server returns a JSON array instead of object
- Malformed JSON response

**Solutions:**

1. Test the endpoint manually:
   ```bash
   curl https://fhir.example.com/.well-known/smart-configuration
   ```

2. Verify the response is valid JSON with an object (not array):
   ```json
   {
     "authorization_endpoint": "...",
     "token_endpoint": "..."
   }
   ```

---

## Authorization Errors

### ConfigurationError: SMART Client auth flow requires scopes

**Symptoms:**
```ruby
Safire::Errors::ConfigurationError: SMART Client auth flow requires scopes (Array)
```

**Causes:**
- No scopes configured in `ClientConfig`
- No `custom_scopes` passed to `authorize_url`

**Solutions:**

1. Configure scopes in the client:
   ```ruby
   config = Safire::ClientConfig.new(
     base_url: 'https://fhir.example.com',
     client_id: 'my_client',
     redirect_uri: 'https://myapp.com/callback',
     scopes: ['openid', 'profile', 'patient/*.read']  # Required
   )
   ```

2. Or pass custom scopes when generating the URL:
   ```ruby
   auth_data = client.authorize_url(
     custom_scopes: ['openid', 'profile', 'patient/Patient.read']
   )
   ```

### State Mismatch in Callback

**Symptoms:**
- User is redirected back but authorization fails
- State parameter doesn't match

**Causes:**
- State not stored in session before redirect
- Session expired during authorization
- Multiple browser tabs causing state confusion

**Solutions:**

1. Ensure state is stored before redirect:
   ```ruby
   def launch
     auth_data = client.authorize_url

     # Store BOTH state and code_verifier
     session[:oauth_state] = auth_data[:state]
     session[:code_verifier] = auth_data[:code_verifier]

     redirect_to auth_data[:auth_url], allow_other_host: true
   end
   ```

2. Add session timeout handling:
   ```ruby
   def callback
     if session[:oauth_state].nil?
       redirect_to launch_path, alert: 'Session expired. Please try again.'
       return
     end

     unless params[:state] == session[:oauth_state]
       render plain: 'Invalid state', status: :unauthorized
       return
     end
     # ...
   end
   ```

---

## Token Exchange Errors

### AuthError: Failed to obtain access token

**Symptoms:**
```ruby
Safire::Errors::AuthError: Failed to obtain access token: "{\"error\":\"invalid_grant\"}"
```

**Common Causes and Solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_grant` | Authorization code expired or already used | Codes are single-use; user must re-authorize |
| `invalid_client` | Client ID not recognized | Verify client registration |
| `invalid_request` | Missing required parameter | Check all parameters are included |
| `unauthorized_client` | Client not authorized for grant type | Verify client configuration on server |

**Debugging Steps:**

1. Check the authorization code hasn't been used:
   ```ruby
   # Authorization codes are single-use
   # Don't retry the same code
   ```

2. Verify the redirect_uri matches exactly:
   ```ruby
   # Must match what was registered and used in authorization
   redirect_uri: 'https://myapp.com/callback'  # Exact match required
   ```

3. Ensure code_verifier is correct:
   ```ruby
   # Must be the same verifier used to generate the challenge
   tokens = client.request_access_token(
     code: params[:code],
     code_verifier: session[:code_verifier]  # From authorization step
   )
   ```

### AuthError: Missing access token in response

**Symptoms:**
```ruby
Safire::Errors::AuthError: Missing access token in response: {...}
```

**Causes:**
- Server returned error but with 200 status
- Non-standard token response format

**Solutions:**

1. Inspect the actual response:
   ```ruby
   begin
     tokens = client.request_access_token(code: code, code_verifier: verifier)
   rescue Safire::Errors::AuthError => e
     Rails.logger.error("Token response: #{e.message}")
     # Check if there's an error field in the response
   end
   ```

---

## Confidential Client Errors

### ConfigurationError: client_secret is needed

**Symptoms:**
```ruby
Safire::Errors::ConfigurationError: client_secret is needed to request access token for confidential_symmetric
```

**Causes:**
- Using `:confidential_symmetric` auth type without providing client_secret

**Solutions:**

1. Provide client_secret in config:
   ```ruby
   config = Safire::ClientConfig.new(
     base_url: 'https://fhir.example.com',
     client_id: 'my_client',
     client_secret: ENV['SMART_CLIENT_SECRET'],  # Required
     redirect_uri: 'https://myapp.com/callback',
     scopes: ['openid', 'profile']
   )

   client = Safire::Client.new(config, auth_type: :confidential_symmetric)
   ```

2. Or pass it during token exchange:
   ```ruby
   tokens = client.request_access_token(
     code: code,
     code_verifier: verifier,
     client_secret: ENV['SMART_CLIENT_SECRET']
   )
   ```

### 401 Unauthorized with Basic Auth

**Symptoms:**
- Token exchange fails with 401
- Server rejects Basic auth credentials

**Causes:**
- Incorrect client_id or client_secret
- Special characters in secret not properly encoded
- Server expects different auth method

**Solutions:**

1. Verify credentials are correct:
   ```ruby
   # Check for typos or extra whitespace
   client_id: ENV['SMART_CLIENT_ID'].strip
   client_secret: ENV['SMART_CLIENT_SECRET'].strip
   ```

2. Special characters are handled automatically by Safire:
   ```ruby
   # Safire uses Base64.strict_encode64 for proper encoding
   # No need to manually encode
   ```

3. Verify server supports `client_secret_basic`:
   ```ruby
   metadata = client.smart_metadata
   methods = metadata.token_endpoint_auth_methods_supported

   unless methods.include?('client_secret_basic')
     raise "Server doesn't support Basic auth"
   end
   ```

---

## Refresh Token Errors

### AuthError: Failed to refresh access token

**Symptoms:**
```ruby
Safire::Errors::AuthError: Failed to refresh access token: "{\"error\":\"invalid_grant\"}"
```

**Causes:**
- Refresh token expired
- Refresh token revoked
- Refresh token already used (if single-use)

**Solutions:**

1. Handle refresh failures by re-authenticating:
   ```ruby
   def refresh_access_token
     new_tokens = client.refresh_token(refresh_token: stored_refresh_token)
     # Update stored tokens
   rescue Safire::Errors::AuthError => e
     if e.message.include?('invalid_grant')
       # Refresh token is no longer valid
       clear_session
       redirect_to launch_path, alert: 'Session expired. Please sign in again.'
     else
       raise
     end
   end
   ```

2. Check if server issues rotating refresh tokens:
   ```ruby
   new_tokens = client.refresh_token(refresh_token: stored_refresh_token)

   # Update BOTH tokens if new refresh token is issued
   session[:access_token] = new_tokens['access_token']
   if new_tokens['refresh_token']
     session[:refresh_token] = new_tokens['refresh_token']
   end
   ```

---

## PKCE Errors

### Invalid code_challenge

**Symptoms:**
- Authorization fails at the server
- Error mentions code_challenge or PKCE

**Causes:**
- Mismatch between challenge and verifier
- Code verifier not stored correctly

**Solutions:**

1. Ensure verifier is stored and retrieved correctly:
   ```ruby
   # Store during authorization
   auth_data = client.authorize_url
   session[:code_verifier] = auth_data[:code_verifier]

   # Retrieve during token exchange
   code_verifier = session[:code_verifier]
   tokens = client.request_access_token(code: code, code_verifier: code_verifier)
   ```

2. Don't regenerate the verifier:
   ```ruby
   # WRONG - generates new verifier
   tokens = client.request_access_token(
     code: code,
     code_verifier: Safire::PKCE.generate_code_verifier  # Don't do this!
   )

   # CORRECT - use stored verifier
   tokens = client.request_access_token(
     code: code,
     code_verifier: session[:code_verifier]
   )
   ```

---

## Network and Connection Errors

### NetworkError: HTTP request failed

**Symptoms:**
```ruby
Safire::Errors::NetworkError: HTTP request failed: Connection refused
```

**Causes:**
- Server unreachable
- Network issues
- Firewall blocking requests
- SSL/TLS errors

**Solutions:**

1. Check server connectivity:
   ```bash
   curl -v https://fhir.example.com/.well-known/smart-configuration
   ```

2. Add retry logic in your application:
   ```ruby
   def request_tokens_with_retry(code:, code_verifier:, retries: 3)
     attempts = 0
     begin
       client.request_access_token(code: code, code_verifier: code_verifier)
     rescue Safire::Errors::NetworkError => e
       attempts += 1
       if attempts < retries
         sleep(2 ** attempts)  # Exponential backoff
         retry
       end
       raise
     end
   end
   ```

---

## Debugging Tips

### Enable Logging

Configure Safire's logger for detailed output:

```ruby
# config/initializers/safire.rb
Safire.configure do |config|
  config.logger = Rails.logger
  config.log_level = Logger::DEBUG  # In development
end
```

Log output includes:
- Discovery requests
- Authorization URL generation
- Token requests
- Response status codes

### Inspect HTTP Requests

Safire logs HTTP requests automatically:

```
INFO -- : request: POST https://fhir.example.com/token
INFO -- : request: User-Agent: "Safire v0.0.1"
         Accept: "application/json"
         Content-Type: "application/x-www-form-urlencoded"
INFO -- : response: Status 200
```

### Test with Reference Server

Use the SMART Health IT reference server for testing:

```ruby
# .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
```

The reference server provides:
- Standard SMART configuration
- Simulated authorization flow
- Configurable responses

Visit [launch.smarthealthit.org](https://launch.smarthealthit.org) to configure and register test clients.

---

## Common Patterns

### Handling All Error Types

```ruby
def smart_auth_callback
  tokens = client.request_access_token(
    code: params[:code],
    code_verifier: session[:code_verifier]
  )
  # Store tokens...
rescue Safire::Errors::ConfigurationError => e
  # Client misconfiguration
  Rails.logger.error("Configuration error: #{e.message}")
  render plain: 'Server configuration error', status: :internal_server_error
rescue Safire::Errors::AuthError => e
  # Authorization/token errors
  Rails.logger.error("Auth error: #{e.message}")
  redirect_to launch_path, alert: 'Authorization failed. Please try again.'
rescue Safire::Errors::NetworkError => e
  # Network/connection errors
  Rails.logger.error("Network error: #{e.message}")
  render plain: 'Server temporarily unavailable', status: :service_unavailable
end
```

### Safe Token Refresh

```ruby
def ensure_valid_token
  return unless token_expired?

  begin
    new_tokens = client.refresh_token(refresh_token: session[:refresh_token])
    update_tokens(new_tokens)
  rescue Safire::Errors::AuthError
    # Refresh token invalid - need to re-authenticate
    clear_session
    redirect_to launch_path
  end
end

def token_expired?
  return true unless session[:token_expires_at]

  Time.current > session[:token_expires_at] - 5.minutes
end
```

---

## Getting Help

If you're still experiencing issues:

1. **Check the logs** - Safire logs detailed information about requests
2. **Test the endpoints manually** - Use curl to verify server responses
3. **Review the spec** - [SMART App Launch v2.2.0](http://hl7.org/fhir/smart-app-launch/)
4. **Open an issue** - Report bugs at the project repository

When reporting issues, include:
- Safire version (`Safire::VERSION`)
- Ruby version
- Error message and backtrace
- Server type (if known)
- Sanitized configuration (no secrets!)
