---
layout: default
title: Client Setup
parent: Configuration
nav_order: 1
---

# Client Setup

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Creating a Client

Pass configuration as a Hash — Safire wraps it in a `ClientConfig` automatically:

```ruby
client = Safire::Client.new(
  {
    base_url:     'https://fhir.example.com/r4',
    client_id:    'my_client_id',
    redirect_uri: 'https://myapp.com/callback',
    scopes:       ['openid', 'profile', 'patient/*.read']
  }
)
```

If you need to reuse the same configuration across multiple clients or inspect it before use, create a `ClientConfig` explicitly:

```ruby
config = Safire::ClientConfig.new(
  base_url:     'https://fhir.example.com/r4',
  client_id:    'my_client_id',
  redirect_uri: 'https://myapp.com/callback',
  scopes:       ['openid', 'profile', 'patient/*.read']
)

client = Safire::Client.new(config)
```

{: .note }
> `client_id` is the only authorization parameter validated at call time rather than at construction. `authorization_url`, `request_access_token`, `refresh_token`, and `request_backend_token` each raise `Safire::Errors::ConfigurationError` if `client_id` is absent when called. This means you can build a client without a `client_id` and call `register_client` to obtain one at runtime. See [Dynamic Client Registration]({{ site.baseurl }}/smart-on-fhir/dynamic-client-registration/) for details.

---

## Protocol and Client Type

`protocol:` and `client_type:` are keyword arguments to `Safire::Client.new`. `protocol:` selects the protocol implementation; `client_type:` selects the SMART authentication style and is not used for UDAP.

```ruby
client = Safire::Client.new(config, protocol: :smart, client_type: :confidential_symmetric)
```

### Protocol

Selects the authorization protocol. Defaults to `:smart`.

| Value | Status | Description |
|-------|--------|-------------|
| `:smart` | Implemented | SMART App Launch 2.2.0 |
| `:udap` | Partial | UDAP Security STU2 discovery — `server_metadata` validates `signed_metadata`, supports optional `community:`, and accepts trust policy keywords (`trusted_anchors:`, `crls:`, `revocation_checker:`, `verify_chain:`); auth flows raise `NotImplementedError` |

For UDAP, `client_type:` is not applicable. Passing any explicit value, either at initialization or through `client.client_type=`, raises `Safire::Errors::ConfigurationError`. Future UDAP authentication flows will use signed JWT assertions rather than SMART client types.

```ruby
client = Safire::Client.new(
  { base_url: 'https://fhir.example.com' },
  protocol: :udap
)

metadata = client.server_metadata(verify_chain: false) # development/test only
```

Production UDAP discovery must validate `signed_metadata` with trust anchors and an explicit revocation policy:

```ruby
ca_cert = OpenSSL::X509::Certificate.new(File.read('udap_ca.pem'))
ca_crl  = OpenSSL::X509::CRL.new(File.read('udap_ca.crl'))

metadata = client.server_metadata(
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

Pass `community:` when the server participates in a specific UDAP trust community:

```ruby
metadata = client.server_metadata(
  community:       'https://udap.example.org/community1',
  trusted_anchors: [ca_cert],
  crls:            [ca_crl]
)
```

See [UDAP]({{ site.baseurl }}/udap/) for validation helpers, 404/204 discovery behavior, and the `verify_chain: false` development caveat.

#### UDAP client signing credentials

UDAP software statements use a client private key and a leaf-first X.509
certificate chain. Configure these reusable credentials on the client:

```ruby
config = Safire::ClientConfig.new(
  base_url:   'https://fhir.example.com',
  private_key: File.read(ENV.fetch('UDAP_CLIENT_PRIVATE_KEY_PATH')),
  certificate_chain: [
    File.read(ENV.fetch('UDAP_CLIENT_CERTIFICATE_PATH')),
    File.read(ENV.fetch('UDAP_CLIENT_ISSUING_CA_PATH'))
  ],
  jwt_algorithm: 'RS256'
)

client = Safire::Client.new(config, protocol: :udap)
```

`certificate_chain` accepts PEM strings or
`OpenSSL::X509::Certificate` instances. The leaf certificate must be first, as
required by the
[UDAP Security STU2 JWT header profile](https://hl7.org/fhir/us/udap-security/STU2/general.html#jwt-headers).
`ClientConfig` requires a non-empty collection, copies and freezes PEM strings,
and snapshots certificate objects as DER. Accessing the chain returns fresh
certificate objects, so subsequent caller mutations cannot alter the configured
identity. Safire defers PEM parsing, private-key matching, validity checks, and
URI SAN checks until a software statement is built.

Configured credentials are intended to serve as defaults, with per-call
overrides for applications that select signing identities dynamically. The
end-to-end UDAP Dynamic Client Registration API is not available yet. These
fields provide its configuration foundation; UDAP discovery does not access
them.

### Client Type

Selects the SMART authentication method. Applies only when `protocol: :smart`. Defaults to `:public`.

| Value | Extra config required | Authentication |
|-------|-----------------------|----------------|
| `:public` | None | PKCE; `client_id` in request body |
| `:confidential_symmetric` | `client_secret` | HTTP Basic auth |
| `:confidential_asymmetric` | `private_key`, `kid` | JWT assertion (RS384/ES384) |

```ruby
# Public (default)
client = Safire::Client.new(config)

# Confidential symmetric
client = Safire::Client.new(
  { **base_config, client_secret: ENV.fetch('SMART_CLIENT_SECRET') },
  client_type: :confidential_symmetric
)

# Confidential asymmetric
client = Safire::Client.new(
  {
    **base_config,
    private_key: OpenSSL::PKey::RSA.new(File.read(ENV.fetch('SMART_PRIVATE_KEY_PATH'))),
    kid:         ENV.fetch('SMART_KEY_ID'),
    jwks_uri:    ENV.fetch('SMART_JWKS_URI')  # optional
  },
  client_type: :confidential_asymmetric
)
```

You can also change `client_type` after initialization — useful when selecting a type based on server capabilities discovered at runtime:

```ruby
client = Safire::Client.new(config)
metadata = client.server_metadata

client.client_type = :confidential_asymmetric if metadata.supports_asymmetric_auth?
```

For a decision guide on which workflow to use, see [SMART App Launch — Choosing a Workflow]({{ site.baseurl }}/smart-on-fhir/).

---

## URI Validation

All URI parameters are validated at initialization. Safire raises `Safire::Errors::ConfigurationError` for any violation:

- URIs must be well-formed (scheme + host required)
- URIs must use `https` — required for SMART App Launch and UDAP discovery
- **Exception:** `http` is permitted for `localhost` and `127.0.0.1` (local development only)

The following attributes are validated:

| Attribute | Validated when |
|-----------|----------------|
| `base_url` | Always |
| `redirect_uri` | When provided (required for App Launch; not used in Backend Services) |
| `issuer` | When provided (defaults to `base_url`) |
| `authorization_endpoint` | When provided |
| `token_endpoint` | When provided |
| `jwks_uri` | When provided |

If you need to bypass discovery and provide endpoints directly, set `authorization_endpoint` and `token_endpoint` in your config. Safire will use them as-is instead of fetching `/.well-known/smart-configuration`.

UDAP discovery always uses the FHIR `base_url` and the `/.well-known/udap` endpoint. UDAP endpoint values are taken from discovered, signed metadata rather than from SMART endpoint overrides.

---

## Credential Protection

`ClientConfig` prevents `client_secret`, `private_key`, and
`certificate_chain` from leaking in logs or REPL output. The certificate chain
is masked even though certificates are public because the full chain can be
large and identifies the client's operational signing identity.

`#to_hash` replaces sensitive fields with `'[FILTERED]'`:

```ruby
config.to_hash[:client_secret]      # => "[FILTERED]"
config.to_hash[:certificate_chain]  # => "[FILTERED]"
config.to_hash[:base_url]           # => "https://fhir.example.com"
```

`#inspect` is overridden to mask sensitive fields and omit `nil` attributes, so REPL sessions and error messages never expose credentials:

```ruby
config.inspect
# => "#<Safire::ClientConfig base_url: \"https://fhir.example.com\", client_id: \"my_client_id\", client_secret: \"[FILTERED]\", ...>"
```

---

## Next Steps

- [Logging]({{ site.baseurl }}/configuration/logging/) — configure Safire's logger and HTTP request logging
- [UDAP Discovery]({{ site.baseurl }}/udap/) — discover and validate UDAP Security STU2 server metadata
- [Dynamic Client Registration]({{ site.baseurl }}/smart-on-fhir/dynamic-client-registration/) — obtain a `client_id` at runtime using RFC 7591
- [SMART App Launch Workflows]({{ site.baseurl }}/smart-on-fhir/) — step-by-step authorization flow guides
