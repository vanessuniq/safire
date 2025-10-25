---
layout: default
title: Installation
nav_order: 2
---

# Installation

## Requirements

- **Ruby:** 3.3.6 or later
- **Bundler:** Latest version recommended
- **OpenSSL:** For cryptographic operations

## Install from RubyGems

```bash
gem install safire
```

Or add to your Gemfile:

```ruby
gem 'safire'
```

Then run:

```bash
bundle install
```

## Development Installation

Clone the repository and set up the development environment:

```bash
# Clone the repository
git clone https://github.com/vanessuniq/safire.git
cd safire

# Set up dev
rake setup # or `bin/setup`

# Run tests to verify installation
rake spec # or `bundle exec rspec`

# Generate yard documentation
rake docs # or `bundle exec yard doc`

# Drop into the Safire console for interactive prompt
bin/console
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
metadata = safire_client.smart_discovery

puts "Authorization endpoint: #{metadata.authorization_endpoint}"
# Authorization endpoint: https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/auth/authorize
# => nil

puts "Token endpoint: #{metadata.token_endpoint}"
# Token endpoint: https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/auth/token
# => nil

puts "Capabilities: #{metadata.capabilities}"
# Capabilities: ["launch-ehr", "launch-standalone", "client-public", "client-confidential-symmetric", "client-confidential-asymmetric", "sso-openid-connect", "context-passthrough-banner", "context-passthrough-style", "context-ehr-patient", "context-ehr-encounter", "context-standalone-patient", "context-standalone-encounter", "permission-offline", "permission-patient", "permission-user", "permission-v1", "permission-v2", "authorize-post"]
# => nil

# Once the SMART discovery endpoint has been fetched, you can also access the SMART metadata as follow:
client.smart_metadata

puts "Token endpoint: #{client.smart_metadata.token_endpoint}"
```

## Troubleshooting

### Common Issues

**Ruby Version Compatibility**

If you encounter version compatibility issues:

```bash
# Check your Ruby version
ruby --version

# Then Install the specified Ruby version in the Gemfile using rbenv, rvm, or asdf
# then set that version as default
```

## Next Steps

Once installation is complete:

1. __[Configuration Guide]({{ site.baseurl }}/configuration/)__ - Set up client configuration

1. __[SMART Protocols]({{ site.baseurl }}/protocols/smart/)__ - Learn about SMART on FHIR

1. __[UDAP Protocols]({{ site.baseurl }}/protocols/udap/)__ - Learn about UDAP

1. __[API Reference]({{ site.baseurl }}/api/)__ - Explore the complete API

## Getting Help

If you encounter issues:

- __GitHub Issues:__ [Report bugs and request features](https://github.com/vanessuniq/safire/issues)
- __Documentation:__ [Full documentation site]({{ site.baseurl }}/)

---

*Last updated: {{ site.time | date: '%B %d, %Y' }}*
