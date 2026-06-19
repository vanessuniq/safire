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
| `Safire::Errors::DiscoveryError` | SMART or UDAP metadata discovery failed (HTTP error, invalid JSON, missing SMART `token_endpoint` when required, or UDAP `signed_metadata` validation failure) |
| `Safire::Errors::CertificateError` | UDAP `x5c` certificate data could not be parsed during `signed_metadata` validation |
| `Safire::Errors::RegistrationError` | Dynamic Client Registration failed (server error, or 2xx response with a missing or invalid `client_id`) |
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

## Discovery Errors

### SMART discovery

SMART clients fetch `/.well-known/smart-configuration` lazily when metadata or an auth flow needs it. A `DiscoveryError` means the SMART metadata endpoint returned an HTTP error, did not return a JSON object, or a token request needed discovery but the response did not include `token_endpoint`.

```ruby
begin
  metadata = smart_client.server_metadata
rescue Safire::Errors::DiscoveryError => e
  Rails.logger.error("SMART discovery failed: #{e.message}")
end
```

### UDAP discovery

UDAP clients fetch `/.well-known/udap` and validate the required `signed_metadata` JWT before returning metadata. In production, pass trust anchors plus CRLs or a custom revocation checker:

```ruby
metadata = udap_client.server_metadata(
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

Common UDAP discovery outcomes:

| Response or condition | Meaning |
|-----------------------|---------|
| `404 Not Found` | Per UDAP Security STU2, treat this as "UDAP workflows are not supported" for that server |
| `204 No Content` | No UDAP workflows are supported for the requested `community:`; Safire raises `DiscoveryError` before parsing the body |
| `signed_metadata validation failed` | Safire could not validate the JWT signature, certificate chain, revocation status, issuer/SAN relationship, required claims, or signed endpoint URLs |
| `ConfigurationError` for `community:` | The community value was not a URI string; Safire raises before making an HTTP request |

For development and tests only, `verify_chain: false` skips X.509 chain and revocation validation:

```ruby
metadata = udap_client.server_metadata(verify_chain: false)
```

Never use `verify_chain: false` in production.

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

### Test discovery endpoints manually

```sh
curl https://fhir.example.com/.well-known/smart-configuration
curl https://fhir.example.com/.well-known/udap
curl 'https://fhir.example.com/.well-known/udap?community=https%3A%2F%2Fudap.example.org%2Fcommunity1'
```

SMART metadata is unsigned JSON. UDAP metadata must include `signed_metadata`; Safire validates that JWT before returning `UdapMetadata`.

---

## Getting Help

- **Check the logs first** — Safire logs one line per error with all relevant context
- **Test endpoints manually** — check the SMART or UDAP well-known endpoint for the protocol you selected
- **Open an issue** — [github.com/vanessuniq/safire/issues](https://github.com/vanessuniq/safire/issues)

When reporting an issue, include: Safire version (`Safire::VERSION`), Ruby version, the error message and backtrace, and the server type if known. Never include credentials or tokens.
