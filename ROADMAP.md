# Safire Roadmap

## Current Release — v0.3.0

Safire is in early development (pre-release). The API is functional but not yet stable — breaking changes may occur before v1.0.0. Published to [RubyGems](https://rubygems.org/gems/safire).

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
- **Backend Services** — `client_credentials` grant for system-to-system flows; JWT assertion (RS384/ES384); no user interaction, redirect, or PKCE required; scope defaults to `system/*.rs` when not configured
- **Dynamic Client Registration** — runtime client registration per [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591); endpoint discovered from SMART metadata or supplied explicitly; supports initial access token

---

## Planned Features

### UDAP Security

- **UDAP Discovery** — `/.well-known/udap` metadata fetch and validation
- **UDAP Dynamic Client Registration** — signed software statements and client registration
- **UDAP JWT Client Auth** — B2B and consumer-facing authorization flows
- **Tiered OAuth** — identity chaining for multi-system access

### Quality and Compliance

- **Inferno SMART App Launch STU 2.2 Test Suite** — compliance validation using
  [Inferno](https://inferno-framework.github.io/) as a mock EHR authorization server,
  with Safire's demo app acting as the SMART client. Inferno captures every OAuth message
  and validates it against the spec. Delivered in two phases.

  **Phase 1 — HTTP-only flows (no browser automation required)**
  - Discovery compliance: Safire discovers Inferno's `/.well-known/smart-configuration`
    and asserts full spec conformance via `SmartMetadata#valid?`
  - Backend Services compliance: JWT assertion construction, `client_credentials` token
    request format, and token response validation against Inferno's mock token endpoint
  - Inferno test results published as a GitHub Actions artifact (static HTML report
    generated from Inferno's JSON output)

  **Phase 2 — Authorization code flows (browser automation via Capybara)**
  - Standalone Patient Launch for all three client types: public (PKCE-only),
    confidential symmetric (`client_secret_basic`), and confidential asymmetric
    (`private_key_jwt`)
  - Dynamic Client Registration: register via `register_client`, then complete an
    authorization code flow with the returned `client_id`
  - Infrastructure: Docker Compose for a local Inferno instance, Capybara and headless
    Chrome for OAuth consent screen automation

---

## Compatibility

| Component | Version |
|-----------|---------|
| Ruby | ≥ 4.0.2 |
| ActiveSupport | ~> 8.0 |
| Rails (optional) | 7.x, 8.x |
| SMART App Launch | 2.2.0 (STU2) |
| UDAP Security | 1.0 (planned) |
| FHIR | R4, R4B |
