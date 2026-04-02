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

## Install

**Requirements:** Ruby ≥ 4.0.2. OpenSSL is bundled with Ruby — no separate install needed.

Add to your Gemfile:

```ruby
gem 'safire'
```

Then run:

```bash
bundle install
```

Or install directly:

```bash
gem install safire
```

---

## Development Setup

Clone the repo and set up the development environment:

```bash
git clone https://github.com/vanessuniq/safire.git
cd safire
bin/setup          # Install dependencies
bundle exec rspec  # Run tests to verify
bin/console        # Interactive prompt
```

To serve the docs site locally:

```bash
bin/docs                                           # Generate YARD API docs
cd docs && bundle install && bundle exec jekyll serve
```

Then visit `http://localhost:4000/safire/`.

---

## Verify

A quick smoke test to confirm the gem is installed and SMART discovery is working:

```ruby
require 'safire'

client = Safire::Client.new(
  {
    base_url:     'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir',
    client_id:    'test',
    redirect_uri: 'https://example.com/callback',
    scopes:       ['openid', 'profile', 'patient/*.read']
  }
)

metadata = client.server_metadata
puts metadata.authorization_endpoint
# => https://launch.smarthealthit.org/.../auth/authorize
```

If you see an authorization endpoint URL, the gem is working. For troubleshooting, see the [Troubleshooting Guide]({{ site.baseurl }}/troubleshooting/).

---

## Next Steps

| | |
|-|-|
| [Configuration]({{ site.baseurl }}/configuration/) | Client credentials, logging, and protocol selection |
| [SMART on FHIR]({{ site.baseurl }}/smart-on-fhir/) | Authorization flows for public and confidential clients |
| [Security Guide]({{ site.baseurl }}/security/) | HTTPS requirements, credential protection, token storage |
| [API Reference]({{ site.baseurl }}/api/){:target="_blank"} | Complete YARD documentation |
