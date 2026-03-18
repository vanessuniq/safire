---
layout: default
title: SMART Discovery
parent: SMART on FHIR
nav_order: 1
has_children: true
permalink: /smart-on-fhir/discovery/
---

# SMART Discovery

{: .no_toc }

<div class="code-example" markdown="1">
SMART on FHIR discovery allows clients to dynamically learn about a FHIR server's authorization capabilities before initiating the OAuth flow.
</div>

---

## Overview

Safire fetches server metadata from `/.well-known/smart-configuration`, appended to your `base_url`:

```ruby
base_url = 'https://fhir.example.com/r4'
# Fetches: https://fhir.example.com/r4/.well-known/smart-configuration
```

Trailing slashes are handled automatically. The metadata is fetched lazily on first use and cached within the client instance.

```ruby
config = Safire::ClientConfig.new(
  base_url:     'https://fhir.example.com',
  client_id:    'my_client',
  redirect_uri: 'https://myapp.com/callback',
  scopes:       ['openid', 'profile']
)

# :public is the default client_type — appropriate for discovery
client   = Safire::Client.new(config)
metadata = client.server_metadata
# => #<Safire::Protocols::SmartMetadata ...>
```

`server_metadata` returns a `Safire::Protocols::SmartMetadata` object with typed accessors for all fields. See [Metadata Fields and Validation]({% link smart-on-fhir/discovery/metadata.md %}) for the full field reference and validation rules.

---

## Error Handling

```ruby
begin
  metadata = client.server_metadata
rescue Safire::Errors::DiscoveryError => e
  case e.message
  when /404/
    puts 'FHIR server does not support SMART on FHIR'
  when /timeout/i
    puts 'Discovery request timed out'
  when /expected JSON object/
    puts 'Server returned invalid SMART configuration'
  else
    puts "Discovery failed: #{e.message}"
  end
end
```

**Graceful fallback** — fall back to known endpoints when discovery is unavailable:

```ruby
def discover_with_fallback(client)
  metadata = client.server_metadata
  {
    authorization_endpoint: metadata.authorization_endpoint,
    token_endpoint:         metadata.token_endpoint,
    source:                 :discovery
  }
rescue Safire::Errors::DiscoveryError => e
  Rails.logger.warn("Discovery failed, using fallback: #{e.message}")
  {
    authorization_endpoint: ENV['FALLBACK_AUTH_ENDPOINT'],
    token_endpoint:         ENV['FALLBACK_TOKEN_ENDPOINT'],
    source:                 :fallback
  }
end
```

{: .note }
> Application-level metadata caching (e.g. `Rails.cache`) and multi-server registry patterns are covered in the [Advanced Examples]({{ site.baseurl }}/advanced/) guide.

---

## What's Next

- [Metadata Fields and Validation]({% link smart-on-fhir/discovery/metadata.md %}) — field reference, validation rules, PKCE checks
- [Capability Checks and Client Selection]({% link smart-on-fhir/discovery/capability-checks.md %}) — all capability methods and dynamic client type selection
