# Changelog

All notable changes to the packaged Safire gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Safire::Client#authorization_url` accepts `idp:` on `protocol: :udap`
  clients to request UDAP Security STU2 Tiered OAuth (client side, §6.1).
  Safire adds the `udap` scope (without duplicating it) and the `idp` query
  parameter with the preferred OpenID Connect IdP's base URL. `idp` must be an
  absolute HTTPS URL without a fragment (HTTP loopback only with
  `allow_insecure_localhost`); otherwise `ValidationError` before any network
  request. When `idp` is given, the data holder must advertise `udap_to` in
  `udap_profiles_supported` and `udap` in `scopes_supported`; otherwise
  `DiscoveryError`. Without `idp`, behavior is unchanged. Documentation covers
  `invalid_idp` handling. Data-holder-to-IdP interactions remain out of scope.
- The demo's UDAP authorization page has an optional preferred-IdP field and a
  specific message for `invalid_idp`.

## [0.6.0] - 2026-11-01

### Added

- `Safire::Client#authorization_url`, `#request_access_token`, and
  `#refresh_token` now support the UDAP Security STU2 authorization code flow
  for consumer-facing and interactive B2B apps when initialized with
  `protocol: :udap`. `authorization_url` uses the authoritative signed
  `authorization_endpoint` and sends exactly `response_type=code`, `client_id`,
  `redirect_uri`, `scope`, a generated `state`, and an S256 `code_challenge`;
  it returns `{auth_url:, state:, code_verifier:}`. The application must
  compare `state` at its callback before exchanging the code. The code exchange
  and refresh requests authenticate with a UDAP Authentication Token (no
  `extensions` by default), send `udap=1`, and never send an `Authorization`
  header or client secret. Requested wildcard scopes that are not advertised
  produce a value-free warning in `authorization_url` and a `ValidationError`
  when a refresh requests scope. An `hl7-b2b` extension is rejected for these
  grants; required authorization extensions that are not sent produce a
  warning.
- The demo application includes a UDAP authorization code launch, callback
  (with `state` verification), and refresh workflow.

### Removed

- **Breaking:** SMART Backend Services no longer falls back to `system/*.rs`.
  `request_backend_token` raises `ConfigurationError`
  (`missing_attributes: [:scopes]`) before any HTTP request when neither the
  per-call `scopes:` nor the configured `scopes` contains a non-blank entry. To
  keep the old behavior, pass `scopes: ['system/*.rs']` explicitly. This
  completes the deprecation announced in v0.4.1.

## [0.5.0] - 2026-11-01

### Added

- `Safire::Client#request_backend_token` now supports UDAP Security STU2 B2B
  access tokens when initialized with `protocol: :udap`. Safire validates
  caller input before any network request, performs trusted UDAP discovery
  (signed metadata must validate), checks token-request readiness (`udap_authn`
  profile, `client_credentials` grant, authoritative HTTPS token endpoint,
  `private_key_jwt`, signing-algorithm metadata, and required authorization
  extensions), and POSTs `grant_type=client_credentials`, the required `scope`,
  `client_assertion_type`, `client_assertion`, and `udap=1` without an
  `Authorization` header or client secret. Server errors surface as
  `TokenError` with their OAuth error code; requests are never retried.
- UDAP Authentication Tokens (certificate-backed JWT client authentication):
  `iss`/`sub` are the registered `client_id`, `aud` is the signed token
  endpoint exactly as advertised, the lifetime is 300 seconds, each token has a
  fresh `jti`, and the JOSE header carries only `alg` and a leaf-first `x5c`.
  The signing algorithm is negotiated from
  `token_endpoint_auth_signing_alg_values_supported` and the key type.
- The `b2b:` argument builds the required STU2 `hl7-b2b` B2B Authorization
  Extension Object: Safire sets `version` `"1"`, requires an absolute-URI
  `organization_id` and at least one `purpose_of_use`, accepts the optional
  members, rejects unknown members, and requires `consent_policy` whenever
  `consent_reference` is present. Additional extension objects can be passed
  with `extensions:`.
- The demo application can request a UDAP B2B token and shows its error paths.

### Changed

- **Breaking:** UDAP Dynamic Client Registration and modification now enforce
  the UDAP Security STU2 scope-negotiation rule that a client may request a
  wildcard scope only if wildcards are listed in `scopes_supported`, using
  Safire's stricter exact-advertisement check. A requested scope token
  containing a literal `*` raises
  `ValidationError` unless it appears exactly in `scopes_supported`, and raises
  `DiscoveryError` when `scopes_supported` provides no usable scope strings
  while a wildcard must be evaluated. Usable advertised entries are still
  honored when a malformed sibling entry is present. This replaces the v0.4.1
  deprecation warning. The scope check stays warning-only during cancellation,
  so scope-advertisement drift alone cannot block credential cleanup, and
  non-wildcard scopes remain subject to server-side negotiation with at most a
  value-free warning. UDAP B2B token requests apply the same wildcard check.

### Fixed

- `Safire::PKCE.generate_code_challenge` now raises `ArgumentError` for a
  non-String code verifier (for example `nil`, an Integer, or a Symbol) instead
  of leaking `NoMethodError` or `TypeError`. The message names only the received
  class, never the verifier value. Verifiers with non-ASCII, invalid-byte, or
  ASCII-incompatible encodings now raise the existing invalid-characters
  `ArgumentError` instead of an encoding error.
- Documentation examples and error-handling guidance now match the public
  API: advanced, security, SMART discovery, registration, token-exchange, and
  troubleshooting pages use the error classes Safire actually raises, no
  longer claim an `iat` claim in SMART client assertions, include the
  `allow_insecure_localhost` setting for local HTTP redirects, and fix broken
  documentation-site links. References to an SSL configuration option that the
  public API does not expose were removed, and `user_agent` is documented.

## [0.4.1] - 2026-08-29

### Changed

- SMART and UDAP discovery now accept usable raw JSON-object response bodies
  when incorrect or missing response content types leave them undecoded by the
  HTTP adapter. Shared discovery, registration, and OAuth error handling treats
  malformed or non-object JSON plus ambiguous, recursive, or non-JSON-compatible
  adapter-provided Hashes as unusable instead of risking silent normalization
  or unexpected type errors.
- SMART metadata diagnostics now validate array-valued field shapes. Capability
  and signing-algorithm helpers treat malformed list advertisements as
  unsupported instead of applying scalar substring semantics or raising an
  unexpected type error. Authorization and token operations now also apply the
  configured HTTPS/localhost policy to endpoints obtained through SMART
  discovery before using them. OAuth authorization, token, registration, and
  redirect endpoint URIs are rejected when they contain fragment components.
- UDAP Dynamic Client Registration now validates and snapshots caller input
  before discovery, then gates only on trusted DCR profile, endpoint, algorithm,
  certification, and scope values needed by the request. Missing RS256
  advertisement and unconfirmed scope support produce value-free warnings when
  an otherwise usable request can proceed; unrelated metadata conformance
  defects remain available through `UdapMetadata#valid?`. In v0.4.1,
  unadvertised wildcards still proceed after warning; registration and
  modification require exact advertisement in v0.5.0, while wildcard scope
  compatibility remains warning-only during cancellation.
- UDAP authorization-code registration now rejects only locally provable
  `logo_uri` defects. Usable HTTPS URLs whose PNG, JPG/JPEG, or GIF format
  cannot be inferred from the path are accepted with a value-free warning;
  Safire does not dereference caller-supplied logo URLs during validation.
- UDAP registration returns metadata only for completed `200`/`201` outcomes;
  `202 Accepted` is reported as pending rather than treated as completed.
  Cancellation error messages now more clearly distinguish an unconfirmed
  outcome from server rejection. Safire never retries registration lifecycle
  requests automatically when the authorization server may already have
  committed them.

### Deprecated

- SMART Backend Services requests without usable configured or per-call scopes
  still use `system/*.rs` for v0.4.x compatibility, but now emit a deprecation warning.
  Configure or pass scopes explicitly before v0.6.0, when missing scopes will
  raise `ConfigurationError`.

## [0.4.0] - 2026-08-07

### Added

- `Safire::Client#register_client` and `Safire::Client#cancel_registration` now
  support the UDAP Security STU2 Dynamic Client Registration lifecycle when
  initialized with `protocol: :udap`. Safire performs discovery-bound
  registration against authoritative signed endpoints, checks structural DCR
  capability, posts the fixed UDAP envelope with optional certification or
  endorsement JWTs, accepts new-registration `201` and update-style `200`
  responses with a valid `client_id`, and confirms cancellation through a
  successful response containing a valid `client_id` and an empty `grant_types`
  array. OAuth-style failures preserve UDAP error codes such as
  `invalid_software_statement` and `unapproved_software_statement`.
- `Safire::Protocols::UdapRegistrationMetadata` validates and normalizes
  caller-controlled UDAP Security STU2 registration and cancellation metadata
  before software-statement signing. It enforces exact grant shapes, HTTPS
  redirect and logo URIs, required `mailto:` contact data, protocol-owned
  fields, JSON-compatible extensions, and immutable canonical output. An
  explicit `allow_insecure_localhost: true` option permits development-only
  HTTP loopback URIs without allowing remote HTTP. Registration software
  statements use minimal `alg`/`x5c` headers, exact `iss`/`sub`/`aud` claims, a
  five-minute lifetime, fresh `jti`, key-compatible algorithm negotiation, and
  local certificate/key/SAN checks. `ClientConfig` accepts and masks the
  non-empty, leaf-first `certificate_chain` of PEM strings or
  `OpenSSL::X509::Certificate` instances required for UDAP registration.
- UDAP Security STU2 discovery is now available with
  `Safire::Client.new(..., protocol: :udap).server_metadata`. Safire fetches
  `/.well-known/udap`, supports community-scoped discovery via `community:`, accepts
  `trusted_anchors:`, `crls:`, `revocation_checker:`, and `verify_chain:` for
  signed metadata trust validation (`verify_chain: false` is for development/test
  only), parses metadata into `Safire::Protocols::UdapMetadata`, and raises
  `DiscoveryError` for HTTP errors, 204 responses, a response body that is not a
  JSON object, or failed signed metadata validation.
- `Safire::Protocols::UdapMetadata` provides STU2 structural validation and helper
  predicates for advertised UDAP profiles and capabilities.
- `Safire::Protocols::UdapSignedMetadataValidator` validates the `signed_metadata`
  JWT per UDAP Security STU2, including RS256, `x5c`, JWT signature, certificate
  chain and revocation checks, issuer/subject/time claims, `jti`, and signed
  endpoint claims.
- UDAP signed endpoint claims are merged over unsigned discovery metadata after
  successful validation. Cached UDAP metadata is revalidated before reuse and
  refetched if the signed JWT, certificate chain, or revocation policy no longer
  validates.
- `UdapMetadata#signed_metadata_valid?` allows explicit cryptographic re-validation
  against caller-provided trust anchors and revocation material.
- `Safire::Errors::DiscoveryError` accepts a `label:` keyword argument (default:
  `'SMART configuration'`) and exposes it as a readable attribute so callers can
  identify which protocol's discovery failed.

### Breaking Changes

- SMART and shared HTTP URI handling now require an explicit
  `allow_insecure_localhost: true` opt-in before accepting HTTP loopback URIs
  or redirects. This aligns SMART local-development behavior with UDAP DCR
  metadata validation while keeping production defaults HTTPS-only.

### Changed

- SMART Dynamic Client Registration now requires successful RFC 7591 responses
  to contain a non-blank string `client_id`. Malformed identifiers that were
  previously accepted now raise `Safire::Errors::RegistrationError`; valid
  registration responses are unchanged.
- Ruby requirement relaxed from `>= 4.0.4` to `>= 3.2` to support Rails 7.1+ apps still
  running on Ruby 3.x. The minimum is 3.2 because the gem uses anonymous keyword splat
  forwarding (`**` without a name), which was introduced in Ruby 3.2.
- ActiveSupport requirement relaxed from `~> 8.0.0` to `>= 7.1, < 9`, resolving the
  bundler conflict that prevented the gem from being used in Rails 8.1 apps or any app
  pinning ActiveSupport 8.1.x.
- `Safire::Client` now raises `ConfigurationError` when `client_type:` is passed explicitly for
  `protocol: :udap`, both at construction and via `client_type=`; previously the value was
  ignored silently.

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
