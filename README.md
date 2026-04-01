# Safire

[![Gem Version](https://badge.fury.io/rb/safire.svg)](https://badge.fury.io/rb/safire)
[![CI](https://github.com/vanessuniq/safire/workflows/CI/badge.svg)](https://github.com/vanessuniq/safire/actions)
[![Coverage](https://codecov.io/gh/vanessuniq/safire/branch/main/graph/badge.svg)](https://codecov.io/gh/vanessuniq/safire)
[![Documentation](https://img.shields.io/badge/docs-yard-blue.svg)](https://vanessuniq.github.io/safire)

Safire is a lean Ruby library that implements [SMART on FHIR](https://hl7.org/fhir/smart-app-launch/) and [UDAP](https://hl7.org/fhir/us/udap-security/) client protocols for healthcare applications.

---

## Features

### SMART on FHIR App Launch (v2.2.0)

- Discovery (`/.well-known/smart-configuration`)
- Public Client (PKCE)
- Confidential Symmetric Client (`client_secret` + HTTP Basic Auth)
- Confidential Asymmetric Client (`private_key_jwt` with RS384/ES384)
- POST-Based Authorization

### SMART on FHIR Backend Services

- System-to-system access token request (`client_credentials` grant)
- JWT assertion authentication (RS384/ES384) — no user interaction, redirect, or PKCE
- Scope defaults to `system/*.rs` when not configured

### UDAP

> Planned. See [ROADMAP.md](https://github.com/vanessuniq/safire/blob/main/ROADMAP.md) for details.

---

## Installation

Requires Ruby ≥ 4.0.2.

```ruby
gem 'safire'
```

```bash
bundle install
```

---

## Quick Start

```ruby
require 'safire'

# Step 1 — Create a client (Hash config or Safire::ClientConfig.new)
client = Safire::Client.new(
  {
    base_url:     'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir',
    client_id:    'my_client_id',
    redirect_uri: 'https://myapp.example.com/callback',
    scopes:       ['openid', 'profile', 'patient/*.read']
  }
)

# Step 2 — Discover SMART metadata (lazy — only called when needed)
metadata = client.server_metadata
puts metadata.authorization_endpoint
puts metadata.capabilities.join(', ')

# Step 3 — Build the authorization URL (Safire generates state + PKCE automatically)
auth_data = client.authorization_url
# auth_data => { auth_url:, state:, code_verifier: }
# Store state and code_verifier server-side, redirect the user to auth_data[:auth_url]

# Step 4 — Exchange the authorization code for tokens (on callback)
token_data = client.request_access_token(
  code:          params[:code],
  code_verifier: session[:code_verifier]
)
# token_data => { "access_token" => "...", "token_type" => "Bearer", ... }

# Step 5 — Refresh when the access token expires
new_tokens = client.refresh_token(refresh_token: token_data['refresh_token'])
```

### Supported SMART Client Types

| `client_type:` | Authentication | When to use |
|----------------|----------------|-------------|
| `:public` (default) | PKCE only | Browser/mobile apps that cannot store a secret |
| `:confidential_symmetric` | HTTP Basic Auth (`client_secret`) | Server-side apps with a securely stored secret |
| `:confidential_asymmetric` | JWT assertion (`private_key_jwt`, RS384/ES384) | Server-side apps using a registered key pair |

For a confidential asymmetric client, provide a private key and key ID:

```ruby
client = Safire::Client.new(
  {
    base_url:    'https://fhir.example.com',
    client_id:   'my_client_id',
    redirect_uri: 'https://myapp.example.com/callback',
    scopes:      ['openid', 'profile', 'patient/*.read'],
    private_key: OpenSSL::PKey::RSA.new(File.read('private_key.pem')),
    kid:         'my-key-id-123'
  },
  client_type: :confidential_asymmetric
)
# Authorization and token exchange are identical — Safire builds the JWT assertion automatically
```

### Backend Services (system-to-system)

No user interaction, redirect URI, or PKCE required — the client authenticates entirely via a signed JWT assertion:

```ruby
client = Safire::Client.new(
  {
    base_url:    'https://fhir.example.com',
    client_id:   'my_backend_client',
    private_key: OpenSSL::PKey::RSA.new(File.read('private_key.pem')),
    kid:         'my-key-id-123',
    scopes:      ['system/Patient.rs', 'system/Observation.rs']
  }
)

token_data = client.request_backend_token
# token_data => { "access_token" => "...", "token_type" => "Bearer", "expires_in" => 300, ... }

# Override scope or credentials per call
token_data = client.request_backend_token(
  scopes:      ['system/Patient.rs'],
  private_key: OpenSSL::PKey::RSA.new(File.read('new_key.pem')),
  kid:         'new-key-id'
)

# Validate the token response (flow: :backend_services also checks expires_in)
client.token_response_valid?(token_data, flow: :backend_services)
```

---

## Configuration

```ruby
Safire.configure do |config|
  config.logger   = Rails.logger   # Default: $stdout
  config.log_http = true           # Log HTTP requests (sensitive headers always filtered)
end
```

See the [Configuration Guide](https://vanessuniq.github.io/safire/configuration/) for all options including `user_agent`, `log_level`, and SSL settings.

---

## Demo Application

A Sinatra-based demo is included in [`examples/sinatra_app/`](examples/sinatra_app/):

```bash
bin/demo
# Visit http://localhost:4567
```

Demonstrates SMART discovery, all authorization flows, token refresh, and backend services token requests. See [`examples/sinatra_app/README.md`](examples/sinatra_app/README.md) for details.

---

## Development

```bash
bin/setup            # Install dependencies
bundle exec rspec    # Run tests
bin/console          # Interactive prompt
```

To serve the docs locally:

```bash
bin/docs
cd docs && bundle install && bundle exec jekyll serve
# Visit http://localhost:4000/safire/
```

---

## Contributing

Bug reports and pull requests are welcome. Please read [CONTRIBUTION.md](https://github.com/vanessuniq/safire/blob/main/CONTRIBUTION.md) before opening a PR — it covers branch naming, commit message style, and the sign-off requirement.

---

## License

Available as open source under the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

---

*Parts of this project were developed with AI assistance (Claude Code) and reviewed by maintainers.*
