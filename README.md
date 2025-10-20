# Safire (WIP)

[![Gem Version](https://badge.fury.io/rb/safire.svg)](https://badge.fury.io/rb/safire)
[![CI](https://github.com/vanessuniq/safire/workflows/CI/badge.svg)](https://github.com/vanessuniq/safire/actions)
[![Documentation](https://img.shields.io/badge/docs-yard-blue.svg)](https://vanessuniq.github.io/safire)

⚠️ **ALPHA SOFTWARE** - APIs will change! Not ready for production use.

A lean Ruby gem that implements **SMART on FHIR** and **UDAP** protocols for both clients and servers.

## What Works

✅ **Discovery:**
- SMART App Launch discovery (`/.well-known/smart-configuration`)

🚧 **Coming Soon:**
- UDAP discovery (`/.well-known/udap`)
- SMART client implementations (public, confidential, backend services)
- UDAP client implementations (JWT auth, DCR, Tiered OAuth)
- Server tooling and Rails integration

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'safire', '~> 0.0.1'
```

## Quick Start

### SMART Discovery

```ruby
require 'safire'
# Initialize client configuration
config = Safire::ClientConfig.new(base_url: 'https://example/com/fhir')

# Initialize Safire Client with config
safire_client = Safire::Client.new(config)

# Discovery SMART Configuration
metadata = safire_client.smart_discovery

puts "Authorization endpoint: #{metadata.authorization_endpoint}"
puts "Token endpoint: #{metadata.token_endpoint}"
puts "Capabilities: #{metadata.capabilities}"

# Once the SMART discovery endpoint has been fetched, you can all access the SMART metadata as follow:
client.smart_metadata

puts "Token endpoint: #{client.smart_metadata.token_endpoint}"
```

## Development

After checking out the repo, run:

```
bin/setup            # Install dependencies
bin/console          # Interactive prompt
bundle exec rspec    # Run tests
```

## Contributing

Bug reports and pull requests are welcome on this [GitHub repo](https://github.com/vanessuniq/safire).

## License

The gem is available as open source under the terms of the Apache 2.0 License.
