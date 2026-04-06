# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
