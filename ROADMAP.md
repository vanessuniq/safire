# Safire Roadmap

## Current Release — v0.0.1

Safire is in early development (pre-release). The API is functional but not yet stable — breaking changes may occur before v1.0.0. Published to [RubyGems](https://rubygems.org/gems/safire).

Feedback, bug reports, and pull requests are welcome via the [issue tracker](https://github.com/vanessuniq/safire/issues).

---

## Implemented Features

### SMART on FHIR App Launch (v2.2.0)

- **Discovery** — lazy fetch of `/.well-known/smart-configuration`; metadata cached per client instance
- **Public Client** — PKCE-only authorization code flow (RS256/ES256)
- **Confidential Symmetric Client** — client secret + HTTP Basic Auth + PKCE
- **Confidential Asymmetric Client** — `private_key_jwt` with RS384/ES384; JWKS URI support; auto-detected algorithm from key type
- **POST-Based Authorization** — form-encoded authorization requests
- **JWT Assertion Builder** — signed JWT assertions with configurable `kid` and expiry
- **PKCE** — automatic code verifier and challenge generation

---

## Planned Features

### SMART on FHIR

- **Backend Services** — `client_credentials` grant for system-to-system flows (no user interaction)
- **Dynamic Client Registration** — programmatic client registration per [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)

### UDAP Security

- **UDAP Discovery** — `/.well-known/udap` metadata fetch and validation
- **UDAP Dynamic Client Registration** — signed software statements and client registration
- **UDAP JWT Client Auth** — B2B and consumer-facing authorization flows
- **Tiered OAuth** — identity chaining for multi-system access

### Quality and Compliance

- **Inferno SMART App Launch STU2.2 Test Suite** — full passing run against the [Inferno Framework](https://inferno-framework.github.io/)

---

## Compatibility

| Component | Version |
|-----------|---------|
| Ruby | ≥ 4.0.1 |
| ActiveSupport | ~> 8.0 |
| Rails (optional) | 7.x, 8.x |
| SMART App Launch | 2.2.0 (STU2) |
| UDAP Security | 1.0 (planned) |
| FHIR | R4, R4B |