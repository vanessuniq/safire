---
layout: default
title: Installation
nav_order: 2
---

# Installation

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Requirements

- **Ruby:** 3.4.7 or later
- **Bundler:** Latest version recommended
- **OpenSSL:** For cryptographic operations

---

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

---

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
rake docs # or `bin/docs`

# Drop into the Safire console for interactive prompt
bin/console
```

---

## Quick Start

### SMART Discovery

```ruby
require 'safire'

# Initialize Safire Client with Hash config (simplest approach)
client = Safire::Client.new(
  base_url: 'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir',
  client_id: 'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes: ['openid', 'profile', 'patient/*.read']
)

# Discover SMART Configuration
metadata = client.smart_metadata

puts "Authorization endpoint: #{metadata.authorization_endpoint}"
# => https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/auth/authorize

puts "Token endpoint: #{metadata.token_endpoint}"
# => https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/auth/token

puts "Capabilities: #{metadata.capabilities.join(', ')}"
# => launch-ehr, launch-standalone, client-public, ...
```

---

## Troubleshooting

### Common Issues

**Ruby Version Compatibility**

If you encounter version compatibility issues:

```bash
# Check your Ruby version
ruby --version

# Install Ruby 3.4.7 or later using rbenv, rvm, or asdf
# then set that version as default
```

For more detailed troubleshooting, see the [Troubleshooting Guide]({{ site.baseurl }}/troubleshooting/).

---

## Next Steps

Once installation is complete:

1. **[Configuration Guide]({{ site.baseurl }}/configuration/)** - Set up client configuration
2. **[SMART on FHIR]({{ site.baseurl }}/smart-on-fhir/)** - Learn about SMART authorization flows
3. **[UDAP]({{ site.baseurl }}/udap/)** - Learn about UDAP (coming soon)
4. **[API Reference]({{ site.baseurl }}/api/)** - Explore the complete API

---

## Getting Help

If you encounter issues:

- **GitHub Issues:** [Report bugs and request features](https://github.com/vanessuniq/safire/issues)
- **Documentation:** [Full documentation site]({{ site.baseurl }}/)
