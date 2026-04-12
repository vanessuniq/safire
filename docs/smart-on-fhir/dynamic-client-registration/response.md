---
layout: default
title: Registration Response
parent: Dynamic Client Registration
grand_parent: SMART
nav_order: 2
permalink: /smart-on-fhir/dynamic-client-registration/response/
description: "What register_client returns: client_id, client_secret, echoed fields, building a runtime Safire::Client from the response, and handling DiscoveryError, RegistrationError, and NetworkError."
---

# Registration Response
{: .no_toc }

<div class="code-example" markdown="1">
On success, `register_client` returns the server's response as a Hash. On failure, it raises `DiscoveryError`, `RegistrationError`, or `NetworkError`.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Response Fields

### `client_id`

The `client_id` is always present. It is the permanent identifier the server assigned to this client and is required for every subsequent authorization flow.

```ruby
client_id = registration['client_id']  # => "dyn_abc123"
```

### `client_secret`

For clients registered with `token_endpoint_auth_method: 'client_secret_basic'`, the server also issues a `client_secret`. Store it durably in a secrets manager or encrypted storage. The server will not return it again in routine operation; if it is lost, you will need to obtain a replacement through the server's administrative process.

```ruby
client_secret = registration['client_secret']  # => "s3cr3t..." or nil
```

### Additional fields

The server typically echoes back some or all of the metadata you submitted, along with server-assigned values such as `client_id_issued_at` or `client_secret_expires_at`. Servers that also implement the OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592) may include a `registration_client_uri` and `registration_access_token` for subsequent read, update, and delete operations. Safire does not implement RFC 7592 management operations, but you can store those fields if you need to interact with the management endpoint using another tool.

---

## Building Your Runtime Client

After persisting credentials, build a new `Safire::Client` configured for the authorization flows you intend to use. The client type determines how authentication works at the token endpoint.

```ruby
# Public client — authorization_code grant with PKCE
client = Safire::Client.new(
  {
    base_url:     'https://fhir.example.com',
    client_id:    registration['client_id'],
    redirect_uri: 'https://myapp.example.com/callback',
    scopes:       ['openid', 'profile', 'patient/*.read']
  }
)

# Confidential symmetric — client_secret_basic
client = Safire::Client.new(
  {
    base_url:      'https://fhir.example.com',
    client_id:     registration['client_id'],
    client_secret: registration['client_secret'],
    redirect_uri:  'https://myapp.example.com/callback',
    scopes:        ['openid', 'profile', 'patient/*.read']
  },
  client_type: :confidential_symmetric
)

# Confidential asymmetric — private_key_jwt
client = Safire::Client.new(
  {
    base_url:    'https://fhir.example.com',
    client_id:   registration['client_id'],
    redirect_uri: 'https://myapp.example.com/callback',
    scopes:      ['openid', 'profile', 'patient/*.read'],
    private_key: OpenSSL::PKey::RSA.new(File.read('private.pem')),
    kid:         'my-key-id'
  },
  client_type: :confidential_asymmetric
)
```

---

## Error Handling

`register_client` raises one of three error classes. All inherit from `Safire::Errors::Error`, so you can rescue any Safire error with a single clause when needed.

### `Safire::Errors::DiscoveryError`

Raised when no `registration_endpoint:` was passed and the server either does not publish `/.well-known/smart-configuration`, returns a non-JSON response, or does not include a `registration_endpoint` field in its SMART metadata.

```ruby
rescue Safire::Errors::DiscoveryError => e
  puts e.message   # "Failed to discover SMART configuration from https://...: server does not advertise a 'registration_endpoint'..."
  puts e.endpoint  # "https://fhir.example.com/.well-known/smart-configuration"
  puts e.status    # HTTP status code, or nil if the server was unreachable
```

### `Safire::Errors::RegistrationError`

Raised when the server returns an HTTP error response (4xx or 5xx), or when a 2xx response does not include `client_id`.

```ruby
rescue Safire::Errors::RegistrationError => e
  # HTTP error path — server returned an RFC 7591 error response
  puts e.status            # 400
  puts e.error_code        # "invalid_redirect_uri"
  puts e.error_description # "Redirect URI must use HTTPS"

  # Structural failure path — 2xx response missing client_id
  puts e.received_fields   # ["error", "error_description"]
  puts e.message           # "Registration response missing client_id; received fields: ..."
```

To rescue any OAuth protocol error in one clause, use `Safire::Errors::OAuthError`, the shared base class for `RegistrationError`, `TokenError`, and `AuthError`.

### `Safire::Errors::NetworkError`

Raised when the HTTP request fails at the transport level: connection refused, timeout, or SSL handshake error.

```ruby
rescue Safire::Errors::NetworkError => e
  puts e.message           # "HTTP request failed: ..."
  puts e.error_description # underlying transport error message
```

### Full rescue example

```ruby
begin
  registration = client.register_client(
    { client_name: 'My App', ... },
    registration_endpoint: explicit_endpoint,
    authorization:         initial_access_token
  )
rescue Safire::Errors::DiscoveryError => e
  logger.error("Registration endpoint not found: #{e.message}")
rescue Safire::Errors::RegistrationError => e
  logger.error("Server rejected registration: #{e.message}")
rescue Safire::Errors::NetworkError => e
  logger.error("Network failure during registration: #{e.message}")
end
```
