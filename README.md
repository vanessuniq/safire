# Safire (WIP)

[![Gem Version](https://badge.fury.io/rb/safire.svg)](https://badge.fury.io/rb/safire)
[![CI](https://github.com/vanessuniq/safire/workflows/CI/badge.svg)](https://github.com/vanessuniq/safire/actions)
[![Documentation](https://img.shields.io/badge/docs-yard-blue.svg)](https://vanessuniq.github.io/safire)

Implementation is still **work in progress**.

Safire is a lean Ruby library that implements **SMART on FHIR** and **UDAP** client protocols for healthcare applications.

---

## Features

**Working:**
- SMART App Launch Discovery (`/.well-known/smart-configuration`)
- SMART on FHIR Public Client (PKCE)
- SMART on FHIR Confidential Symmetric Client (client_secret + Basic Auth)

**Planned:**
- SMART on FHIR Confidential Asymmetric (private_key_jwt)
- UDAP Discovery (`/.well-known/udap`)
- UDAP Client Flows (JWT Auth, Dynamic Client Registration, Tiered OAuth)


## Installation

Add this line to your Gemfile:

```ruby
gem 'safire'
```

Then install:

```bash
bundle install
```

## Supported Auth Types

| Auth Type                  | Description                                                | Client Authentication                                  | Supported  |
| -------------------------- | ---------------------------------------------------------- | ------------------------------------------------------ | ---------- |
| `:public`                  | Public client using PKCE (no secret)                       | `client_id` in token/refresh requests                  | ✅          |
| `:confidential_symmetric`  | Confidential client using client_secret with Basic auth    | `Authorization: Basic base64(client_id:client_secret)` | ✅          |
| `:confidential_asymmetric` | Confidential client using asymmetric key (private_key_jwt) | JWT assertion                                          | Planned |
| `:udap`                    | UDAP client using X.509 certificate and JWT-based auth     | Tiered OAuth (RFC 9126)                                | Planned |


## Usage Example – SMART App Launch (Public Client)

```ruby
require 'safire'

# Initialize client configuration
config = Safire::ClientConfig.new(
  base_url: 'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.example.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

# Initialize Safire client
client = Safire::Client.new(config)

# Discover SMART metadata
metadata = client.smart_metadata

puts "Authorization endpoint: #{metadata.authorization_endpoint}"
puts "Token endpoint: #{metadata.token_endpoint}"
puts "Capabilities: #{metadata.capabilities.join(', ')}"

# Safire automatically retrieves the authorization_endpoint and token_endpoint from the SMART metadata, so you do not need to pass those in the config

# Step 1 – /launch route (authorization request)
client = Safire::Client.new(config, auth_type: :public)
auth_data = client.authorize_url

session[:state] = auth_data[:state]
session[:code_verifier] = auth_data[:code_verifier]
redirect_to auth_data[:auth_url]

# Step 2 – /callback route (token exchange)
return head :unauthorized unless params[:state] == session[:state]

client = Safire::Client.new(config, auth_type: :public)
token_data = client.request_access_token(
  code: params[:code],
  code_verifier: session[:code_verifier]
)

# The data in the token data should be stored in a secure server-side store (session, DB, etc.)
puts token_data["access_token"]

# Refreshing an access token
client = Safire::Client.new(config, auth_type: :public)
new_tokens = client.refresh_token(refresh_token: stored_refresh_token)

puts new_tokens["access_token"]
```

To see additional examples for confidential clients, visit the [Safire Docs](https://vanessuniq.github.io/safire/).

## Development

After checking out the repo, run:

```bash
bin/setup            # Install dependencies
bin/console          # Interactive prompt
bundle exec rspec    # Run tests
```

## Contributing

Bug reports and pull requests are welcome on this [GitHub repo](https://github.com/vanessuniq/safire).

## License

The gem is available as open source under the terms of the Apache 2.0 License.
