# Safire

[![Gem Version](https://badge.fury.io/rb/safire.svg)](https://badge.fury.io/rb/safire)
[![CI](https://github.com/vanessuniq/safire/workflows/CI/badge.svg)](https://github.com/vanessuniq/safire/actions)
[![Documentation](https://img.shields.io/badge/docs-yard-blue.svg)](https://vanessuniq.github.io/safire)

Safire is a lean Ruby library that implements **[SMART on FHIR](https://hl7.org/fhir/smart-app-launch/)** and **[UDAP](https://hl7.org/fhir/us/udap-security/)** client protocols for healthcare applications.

---

## Features

### SMART on FHIR App Launch

- Discovery (`/.well-known/smart-configuration`)
- Public Client (PKCE)
- Confidential Symmetric Client (client_secret + Basic Auth)
- Confidential Asymmetric Client (private_key_jwt with RS384/ES384)
- POST-Based Authorization

### UDAP

> Planned. See [ROADMAP.md](ROADMAP.md) for details (coming soon).

## Requirements

- Ruby >= 4.0.1
- Bundler

## Installation

Add this line to your Gemfile:

```ruby
gem 'safire'
```

Then install:

```bash
bundle install
```

## Supported SMART Client Types

| Client Type                | Description                                                | Client Authentication                                  |
| -------------------------- | ---------------------------------------------------------- | ------------------------------------------------------ |
| `:public`                  | Public client using PKCE (no secret)                       | `client_id` in token/refresh requests                  |
| `:confidential_symmetric`  | Confidential client using client_secret with Basic auth    | `Authorization: Basic base64(client_id:client_secret)` |
| `:confidential_asymmetric` | Confidential client using asymmetric key (private_key_jwt) | JWT assertion (RS384/ES384)                            |



## Usage Example – SMART App Launch (Public Client)

```ruby
require 'safire'

# Initialize Safire client with Hash config (simplest approach)
# You can also use Safire::ClientConfig.new(...) if you prefer
client = Safire::Client.new(
  base_url: 'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.example.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

# Discover SMART metadata
metadata = client.server_metadata

puts "Authorization endpoint: #{metadata.authorization_endpoint}"
puts "Token endpoint: #{metadata.token_endpoint}"
puts "Capabilities: #{metadata.capabilities.join(', ')}"

# Safire automatically retrieves endpoints from SMART metadata

# Step 1 – /launch route (authorization request)
# Use method: :post if the server advertises the 'authorize-post' capability
auth_data = client.authorization_url            # GET redirect (default)
# auth_data = client.authorization_url(method: :post)  # POST form submission

session[:state] = auth_data[:state]
session[:code_verifier] = auth_data[:code_verifier]
redirect_to auth_data[:auth_url]

# Step 2 – /callback route (token exchange)
return head :unauthorized unless params[:state] == session[:state]

token_data = client.request_access_token(
  code: params[:code],
  code_verifier: session[:code_verifier]
)

# Store tokens securely (session, DB, etc.)
puts token_data["access_token"]

# Refreshing an access token
new_tokens = client.refresh_token(refresh_token: stored_refresh_token)
puts new_tokens["access_token"]
```

### Confidential Asymmetric Client (private_key_jwt)

```ruby
require 'safire'

# Load your RSA or EC private key
private_key = OpenSSL::PKey::RSA.new(File.read('private_key.pem'))

client = Safire::Client.new(
  {
    base_url: 'https://fhir.example.com',
    client_id: 'my_client_id',
    redirect_uri: 'https://myapp.example.com/callback',
    scopes: ['openid', 'profile', 'patient/*.read'],
    private_key: private_key,
    kid: 'my-key-id-123',          # Key ID registered with the server
    jwks_uri: 'https://myapp.example.com/.well-known/jwks.json'  # Optional
  },
  client_type: :confidential_asymmetric
)

# Usage is the same — Safire handles JWT assertion automatically
auth_data = client.authorization_url
token_data = client.request_access_token(code: '...', code_verifier: '...')
```

To see additional examples for all client types, visit the [Safire Docs](https://vanessuniq.github.io/safire/).

## Demo Application

A Sinatra-based demo application is included in [`examples/sinatra_app/`](examples/sinatra_app/) that demonstrates all SMART on FHIR features:

- **Server Management**: Add, edit, and remove FHIR server configurations
- **SMART Discovery**: View server capabilities from `/.well-known/smart-configuration`
- **Authorization Flows**: Test provider standalone, patient standalone, and EHR launch flows
- **Token Refresh**: Test token refresh functionality

To run the demo:

```bash
bin/demo
```

Then visit http://localhost:4567 in your browser. See [`examples/sinatra_app/README.md`](examples/sinatra_app/README.md) for more details.

## Development

After checking out the repo, run:

```bash
bin/setup            # Install dependencies
bin/console          # Interactive prompt
bundle exec rspec    # Run tests
```

### Documentation

To serve the documentation site locally:

```bash
bin/docs                                        # Generate YARD API docs
cd docs && bundle install && bundle exec jekyll serve
```

Then visit http://localhost:4000/safire/ in your browser.

## Contributing

Bug reports and pull requests are welcome on this [GitHub repo](https://github.com/vanessuniq/safire).

## License

The gem is available as open source under the terms of the Apache 2.0 License.

---

*Parts of this project were developed with AI assistance (Claude Code) and reviewed by maintainers.*
