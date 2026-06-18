# Safire Roadmap

## Latest Published Release — v0.3.0

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
- **Backend Services** — `client_credentials` grant for system-to-system flows; JWT assertion (RS384/ES384); no user interaction, redirect, or PKCE required; scope defaults to `system/*.rs` when not configured
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
- **Demo Workflow** — Sinatra demo supports protocol-aware server setup and a
  UDAP Discovery screen with signed metadata trust status

---

## Planned Features

### UDAP Security

- **UDAP Dynamic Client Registration** — signed software statements and client registration
- **UDAP JWT Client Auth** — B2B and consumer-facing authorization flows
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
| UDAP Security | 2.0.0 (STU2 discovery implemented; DCR/auth flows planned) |
| FHIR | R4, R4B |
