# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Safire::Protocols::UdapSignedMetadataValidator` validates the `signed_metadata` JWT per UDAP
  Security STU2: RS256 algorithm, `x5c` leaf certificate, JWT signature, X.509 chain and
  revocation validation, and all required claims (`iss`, `sub`, `exp`, `jti`, `token_endpoint`,
  `registration_endpoint`, conditionally `authorization_endpoint`). Signed endpoint claims are
  returned for merging over unsigned discovery values.

- `Udap#server_metadata` now validates `signed_metadata` on every fetch and merges the
  authoritative signed endpoint claims into the returned `UdapMetadata`. Raises
  `Safire::Errors::DiscoveryError` if validation fails. Accepts `trusted_anchors:` and
  `crls:` or `revocation_checker:` for production chain and revocation validation, plus
  `verify_chain:` (`verify_chain: false` for dev/test only). Cached UDAP metadata is
  revalidated before reuse and refetched if its signed JWT, certificate chain, or revocation
  policy no longer validates.

- `UdapMetadata#signed_metadata_valid?` for explicit cryptographic re-validation of the
  `signed_metadata` JWT against a specific set of trust anchors and revocation policy.

- The Sinatra demo now includes a protocol-aware UDAP Discovery workflow with community-scoped
  discovery, signed metadata validation status, and configurable UDAP trust material.

- `Safire::Client.new(..., protocol: :udap).server_metadata` now works end-to-end:
  `Protocols::Udap` fetches and parses `/.well-known/udap`, supports the optional `community:` URI
  parameter, caches results per community, and raises `DiscoveryError` on HTTP errors or a 204 response.

- Added `Safire::Protocols::UdapMetadata` for HL7 UDAP Security STU2 discovery metadata,
  including structural `valid?` checks and helper methods for advertised UDAP profiles and capabilities.

- `Safire::Errors::DiscoveryError` accepts a `label:` keyword argument (default: `'SMART configuration'`)
  and exposes it as a readable attribute; consumers can inspect `error.label` to identify which
  protocol's discovery failed

### Changed

- Ruby requirement changed from >= 4.0.2 to >= 4.0.4.
- `Safire::Client` now raises `ConfigurationError` when `client_type:` is passed explicitly for
  `protocol: :udap`, both at construction and via `client_type=`; previously the value was
  ignored silently

## [0.3.0] - 2026-04-15

### Added

- `Safire::Client#register_client` implements the OAuth 2.0 Dynamic Client Registration
  Protocol (RFC 7591): POSTs client metadata to the server's registration endpoint and
  returns the response as a Hash containing at minimum a `client_id`
  - Endpoint is resolved from SMART discovery (`registration_endpoint` field) when not
    supplied explicitly via the `registration_endpoint:` keyword argument; HTTPS is
    enforced on the endpoint regardless of source
  - Supports an optional initial access token via the `authorization:` keyword argument
    (full `Authorization` header value including token type prefix)
  - Raises `Safire::Errors::DiscoveryError` when no registration endpoint is available,
    `Safire::Errors::RegistrationError` on server error or a 2xx response missing
    `client_id`, and `Safire::Errors::NetworkError` on transport failure
- `Safire::Errors::RegistrationError` — new error class for Dynamic Client Registration
  failures; inherits from `Safire::Errors::OAuthError` with `status`, `error_code`,
  `error_description`, and `received_fields` attributes
- `Safire::Errors::OAuthError` — new shared base class for `RegistrationError`,
  `TokenError`, and `AuthError`; provides `status`, `error_code`, and
  `error_description` attributes and can be used as a single rescue point for any
  server-side OAuth protocol error

### Changed

- `client_id` is now optional at `ClientConfig` and `Protocols::Smart` initialization;
  all authorization flows (`authorization_url`, `request_access_token`, `refresh_token`,
  `request_backend_token`) validate its presence at call time and raise
  `Safire::Errors::ConfigurationError` if it is absent
- `Protocols::Smart#token_endpoint` now raises `Safire::Errors::DiscoveryError` when
  the discovery response does not include a `token_endpoint` field, rather than silently
  passing `nil` to the HTTP client

## [0.2.0] - 2026-04-04

### Added

- SMART Backend Services Authorization flow (`client_credentials` grant) via
  `Safire::Client#request_backend_token` and `Safire::Protocols::Smart#request_backend_token`:
  - Authenticates exclusively via a signed JWT assertion (RS384 or ES384); no redirect,
    PKCE, or user interaction required
  - Scope defaults to `["system/*.rs"]` when none is configured or provided
  - `private_key` and `kid` can be overridden per call
- `token_response_valid?` now accepts a `flow:` keyword argument (`:app_launch` default):
  when `flow: :backend_services`, also validates `expires_in` presence (required per
  SMART Backend Services spec)
- `token_response_valid?` accepts both `"Bearer"` (SMART App Launch spec) and `"bearer"`
  (SMART Backend Services) as valid `token_type` values; the non-compliance warning
  now references the expected value for the active flow
- `SmartMetadata#supports_backend_services?` returns `true` when the server advertises the
  `client_credentials` grant type and supports `private_key_jwt` authentication
  (i.e. `grant_types_supported` includes `"client_credentials"` and
  `supports_asymmetric_auth?` is `true`)

### Changed

- Corrected spec name throughout: "SMART on FHIR" → "SMART App Launch" per the
  [SMART App Launch IG](https://hl7.org/fhir/smart-app-launch/); Backend Services is
  presented as a feature within the spec, not a separate spec
- `redirect_uri` and `authorization_endpoint` are now optional in `Safire::Protocols::Smart`;
  both are validated only when `authorization_url` is called (app launch flow)
- `redirect_uri` is now optional in `Safire::ClientConfig` to support backend services
  clients that operate without a redirect URI; the field is still validated when provided

### Fixed

- YARD API docs nav links broken after in-page navigation: relative hrefs from the nav
  iframe were resolved against the parent window URL (which changes on each navigation)
  instead of the iframe base; `bin/docs` now patches the generated `full_list.js` to
  resolve links to absolute URLs before messaging the parent

## [0.1.0] - 2026-03-25

### Added

- `Safire::Client` facade with `protocol:` (`:smart`) and `client_type:`
  (`:public`, `:confidential_symmetric`, `:confidential_asymmetric`) keywords
- SMART App Launch 2.2.0 support via `Safire::Protocols::Smart`:
  - Server metadata discovery from `/.well-known/smart-configuration`
  - Authorization URL builder for GET and POST-based authorization
    (`authorize-post` capability)
  - Authorization code → access token exchange
  - Token refresh
- PKCE (S256) support with per-request code verifier generation
- Private key JWT assertion (`private_key_jwt`) for confidential asymmetric
  clients; RS384 and ES384 auto-detected from the key type
- Token response validation (`token_response_valid?`) per SMART App Launch
  2.2.0 §Token Response
- `Protocols::Behaviours` contract module defining the required protocol
  interface
- Sensitive data filtering in HTTP request/response logs
- SSL verification warning when `ssl_options: { verify: false }` is configured
- HTTPS-only redirect enforcement with an exception for localhost
- Configurable logger, HTTP logging toggle, and `User-Agent` header via
  `Safire::Configuration`
- `Safire::ClientConfigBuilder` for constructing `ClientConfig` with a fluent
  interface
