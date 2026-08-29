# Safire Roadmap

## Latest Published Release — v0.4.0

Safire is in early development (pre-release). The API is functional but not yet stable — breaking changes may occur before v1.0.0. Published to [RubyGems](https://rubygems.org/gems/safire).

The `main` branch may include features not yet published to RubyGems; see the
[Unreleased section of CHANGELOG.md](CHANGELOG.md#unreleased).

Feedback, bug reports, and pull requests are welcome via the [issue tracker](https://github.com/vanessuniq/safire/issues).

---

## Implemented Features

### SMART App Launch (v2.2.0)

- **Discovery** — lazy fetch of `/.well-known/smart-configuration`; metadata cached per client instance
- **Public Client** — PKCE-only authorization code flow (RS256/ES256)
- **Confidential Symmetric Client** — client secret + HTTP Basic Auth + PKCE
- **Confidential Asymmetric Client** — `private_key_jwt` with RS384/ES384; JWKS URI support; auto-detected algorithm from key type
- **POST-Based Authorization** — form-encoded authorization requests
- **JWT Assertion Builder** — signed JWT assertions with configurable `kid` and expiry
- **PKCE** — automatic code verifier and challenge generation
- **Backend Services** — `client_credentials` grant for system-to-system flows; JWT assertion (RS384/ES384); no user interaction, redirect, or PKCE required; client-selected scopes with a deprecated v0.4.x compatibility fallback
- **Dynamic Client Registration** — runtime client registration per [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591); endpoint discovered from SMART metadata or supplied explicitly; supports initial access token

### UDAP Security (STU2 / v2.0.0)

- **UDAP Discovery** — lazy fetch of `/.well-known/udap`; optional
  community-scoped discovery; STU2 metadata parsing plus explicit
  `UdapMetadata#valid?` structural validation
- **Signed Metadata Validation** — validates `signed_metadata` JWTs using RS256,
  JOSE `x5c`, certificate chain and revocation policy, required claims, and
  signed endpoint claim precedence
- **Protocol-Aware Client Facade** — `Safire::Client.new(..., protocol: :udap)`
  exposes UDAP discovery while rejecting SMART-only `client_type:` values
- **UDAP Dynamic Client Registration** — certificate-backed STU2 new
  registration, modification, and cancellation via signed software statements;
  includes metadata validation, signed endpoint precedence, community-scoped
  discovery, certification envelope handling, RFC 7591-shaped registration
  response parsing, and cancellation confirmation through an empty
  `grant_types` response

### Demo Application

- **Protocol-Aware Workflows** — Sinatra demo supports protocol-aware server
  setup, SMART discovery, registration, authorization, and token workflows,
  plus UDAP signed metadata discovery and the registration/cancellation
  lifecycle

---

## Planned Features

### v0.5.0 — UDAP JWT Client Authentication and B2B Authorization

- **UDAP Registration Wildcard Enforcement** — require exact
  `scopes_supported` advertisement for requested wildcard scopes during new
  registration and modification after the v0.4.1 warning period; cancellation
  remains warning-only so metadata drift cannot strand an existing registration
- **UDAP Authentication Tokens** — certificate-backed JWT client authentication
  for token endpoint requests, using authoritative signed discovery metadata
- **B2B Client Credentials** — headless system-to-system authorization with the
  STU2 `hl7-b2b` authorization extension and discovery-constrained scopes,
  signing algorithms, and extension support

### v0.6.0 — UDAP Authorization Code Flows

- **Explicit SMART Backend Scopes** — remove the deprecated `system/*.rs`
  fallback; Backend Services requests without configured or per-call scopes
  raise `ConfigurationError`
- **Consumer-Facing Authorization** — UDAP authorization code flow with state,
  PKCE, Authentication Tokens, code exchange, and refresh support
- **Interactive B2B Authorization** — authorization code flow for B2B clients,
  including local-user authorization and UDAP client authentication

### v0.7.0 — UDAP Tiered OAuth

- **Tiered OAuth** — identity chaining for multi-system access

### Quality and Compliance

- **Inferno SMART App Launch STU 2.2 Test Suite** — compliance validation using
  [Inferno](https://inferno-framework.github.io/) as a mock EHR authorization server,
  with Safire's demo app acting as the SMART client. Delivered in two phases.

  **Phase 1 — HTTP-only flows (no browser automation required)**
  - Discovery (local conformance gate): Safire discovers Inferno's
    `/.well-known/smart-configuration` and validates the parsed metadata via
    `SmartMetadata#valid?`; this is a local parsing and conformance check,
    not an Inferno-driven assertion
  - Backend Services (Inferno-driven): JWT assertion construction, `client_credentials`
    token request format, and token response validation against Inferno's mock token
    endpoint
  - Inferno test results published as a GitHub Actions artifact (static HTML report
    generated from Inferno's JSON output)

  **Phase 2 — Authorization code flows (browser automation via Capybara)**
  - Standalone Patient Launch for all three client types: public (PKCE-only),
    confidential symmetric (`client_secret_basic`), and confidential asymmetric
    (`private_key_jwt`)
  - EHR Launch: Inferno redirects the user agent to the demo app's `GET /launch`
    endpoint with `iss` and `launch` as query parameters, exercising the EHR-initiated
    authorization code flow as a separate Inferno test group
  - Infrastructure: Docker Compose for a local Inferno instance, Capybara and headless
    Chrome for OAuth consent screen automation

  **Note on Client Registration:** Inferno's reference server documentation states that
  there is currently no registration process and apps must use preconfigured client IDs,
  so DCR is not covered under this Inferno-based plan.

---

## Compatibility

| Component | Version |
|-----------|---------|
| Ruby | ≥ 3.2 |
| ActiveSupport | ≥ 7.1, < 9 |
| Rails (optional) | ≥ 7.1 |
| SMART App Launch | 2.2.0 (STU2) |
| UDAP Security | 2.0.0 (STU2 discovery and Dynamic Client Registration lifecycle implemented; JWT client authentication and authorization flows planned) |
| FHIR | R4, R4B |
