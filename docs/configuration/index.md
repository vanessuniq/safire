---
layout: default
title: Configuration
nav_order: 3
has_children: true
permalink: /configuration/
---

# Configuration

Safire is configured in two places:

- **Client configuration** — the FHIR server URL, credentials, and OAuth parameters passed to `Safire::Client.new`
- **Global configuration** — the logger, log level, and HTTP logging behaviour set once via `Safire.configure`

## Quick Reference

`protocol:` and `client_type:` are keyword arguments to `Safire::Client.new`. All other parameters are keys in the configuration hash (or `Safire::ClientConfig` attributes).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `base_url` | String | Yes | — | FHIR server base URL |
| `client_id` | String | Yes | — | OAuth2 client identifier |
| `redirect_uri` | String | Yes | — | Registered callback URL |
| `protocol:` | Symbol | No | `:smart` | Authorization protocol — `:smart` or `:udap` |
| `client_type:` | Symbol | No | `:public` | SMART client type — `:public`, `:confidential_symmetric`, or `:confidential_asymmetric` |
| `client_secret` | String | No | — | Required for `:confidential_symmetric` |
| `private_key` | OpenSSL::PKey / String | No | — | RSA/EC private key; required for `:confidential_asymmetric` |
| `kid` | String | No | — | Key ID matching the public key registered with the server |
| `jwt_algorithm` | String | No | auto | `RS384` or `ES384`; auto-detected from key type |
| `jwks_uri` | String | No | — | URL to client's public JWKS, included as `jku` in JWT header |
| `scopes` | Array | No | — | Default scopes for authorization requests |
| `authorization_endpoint` | String | No | — | Override the discovered authorization endpoint |
| `token_endpoint` | String | No | — | Override the discovered token endpoint |

## In This Section

- [Client Setup]({{ site.baseurl }}/configuration/client-setup/) — creating a client, protocol and client type selection, URI rules, and credential protection
- [Logging]({{ site.baseurl }}/configuration/logging/) — global logger setup, HTTP request logging, log levels, and environment variables
