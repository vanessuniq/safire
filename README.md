# Safire (WIP)

[![Gem Version](https://badge.fury.io/rb/safire.svg)](https://badge.fury.io/rb/safire)
[![CI](https://github.com/vanessuniq/safire/workflows/CI/badge.svg)](https://github.com/vanessuniq/safire/actions)
[![Documentation](https://img.shields.io/badge/docs-yard-blue.svg)](https://vanessuniq.github.io/safire)

⚠️ Implementation is still **work in progress**.

A lean Ruby gem that implements **SMART on FHIR** and **UDAP** protocols for clients.

## What Works

✅ **Discovery:**
- SMART App Launch discovery (`/.well-known/smart-configuration`)
- SMART App Launch for Public Client

🚧 **Coming Soon:**
- UDAP discovery (`/.well-known/udap`)
- SMART client implementations (confidential, backend services)
- UDAP client implementations (JWT auth, DCR, Tiered OAuth)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'safire', '~> 0.0.1'
```

## Development

After checking out the repo, run:

```
bin/setup            # Install dependencies
bin/console          # Interactive prompt
bundle exec rspec    # Run tests
```

## Quick Start

### SMART Discovery

```ruby
require 'safire'
# Initialize client configuration
config = Safire::ClientConfig.new(base_url: '"https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir')

# Initialize Safire Client with config
safire_client = Safire::Client.new(config)

# Discovery SMART Configuration
metadata = safire_client.smart_metadata

puts "Authorization endpoint: #{metadata.authorization_endpoint}"
# Authorization endpoint: https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/auth/authorize
# => nil

puts "Token endpoint: #{metadata.token_endpoint}"
# Token endpoint: https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/auth/token
# => nil

puts "Capabilities: #{metadata.capabilities}"
# Capabilities: ["launch-ehr", "launch-standalone", "client-public", "client-confidential-symmetric", "client-confidential-asymmetric", "sso-openid-connect", "context-passthrough-banner", "context-passthrough-style", "context-ehr-patient", "context-ehr-encounter", "context-standalone-patient", "context-standalone-encounter", "permission-offline", "permission-patient", "permission-user", "permission-v1", "permission-v2", "authorize-post"]
# => nil
```

### SMART APP Lauch for Public Client

```ruby
#
```

## Contributing

Bug reports and pull requests are welcome on this [GitHub repo](https://github.com/vanessuniq/safire).

## License

The gem is available as open source under the terms of the Apache 2.0 License.
