---
layout: default
title: Troubleshooting
nav_order: 8
has_children: true
permalink: /troubleshooting/
---

# Troubleshooting

{: .no_toc }

<div class="code-example" markdown="1">
Common issues and solutions when integrating with Safire.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Error Types

Safire raises typed errors so you can handle each failure category separately:

| Error class | When raised |
|-------------|-------------|
| `Safire::Errors::ConfigurationError` | Missing or invalid client configuration — caught at construction time |
| `Safire::Errors::DiscoveryError` | SMART metadata fetch failed (HTTP error, invalid JSON, missing field) |
| `Safire::Errors::RegistrationError` | Dynamic Client Registration failed (server error, or 2xx response missing `client_id`) |
| `Safire::Errors::TokenError` | Token exchange or refresh failed (OAuth error, missing fields) |
| `Safire::Errors::NetworkError` | Transport-level failure (connection refused, timeout, blocked redirect) |

`RegistrationError`, `TokenError`, and `AuthError` share a common base class `Safire::Errors::OAuthError` with `status`, `error_code`, and `error_description` attributes — you can rescue all three in one clause using `OAuthError`. All Safire errors inherit from `Safire::Errors::Error` for a single catch-all rescue.

```ruby
begin
  tokens = client.request_access_token(code: code, code_verifier: verifier)
rescue Safire::Errors::ConfigurationError => e
  # Client misconfiguration — fix before retrying
  Rails.logger.error("Configuration error: #{e.message}")
  render plain: 'Server configuration error', status: :internal_server_error
rescue Safire::Errors::TokenError => e
  # OAuth error — e.status, e.error_code, e.error_description are all available
  Rails.logger.error("Token error: #{e.message}")
  redirect_to launch_path, alert: 'Authorization failed. Please try again.'
rescue Safire::Errors::NetworkError => e
  Rails.logger.error("Network error: #{e.message}")
  render plain: 'Server temporarily unavailable', status: :service_unavailable
end
```

---

## Debugging

### Enable detailed logging

```ruby
Safire.configure do |config|
  config.logger    = Rails.logger
  config.log_level = Logger::DEBUG
end
```

HTTP request logging is on by default. Sensitive headers (`Authorization`) are always filtered. Request and response bodies are never logged.

```
INFO: request: POST https://fhir.example.com/token
INFO: request: Authorization: [FILTERED]
INFO: response: Status 200
```

To disable HTTP logging:

```ruby
Safire.configure { |c| c.log_http = false }
```

### Test against the SMART reference server

```ruby
# .env.development
FHIR_BASE_URL=https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir
```

Visit [launch.smarthealthit.org](https://launch.smarthealthit.org) to configure simulated patients and launch contexts.

---

## Getting Help

- **Check the logs first** — Safire logs one line per error with all relevant context
- **Test endpoints manually** — `curl https://fhir.example.com/.well-known/smart-configuration`
- **Open an issue** — [github.com/vanessuniq/safire/issues](https://github.com/vanessuniq/safire/issues)

When reporting an issue, include: Safire version (`Safire::VERSION`), Ruby version, the error message and backtrace, and the server type if known. Never include credentials or tokens.
