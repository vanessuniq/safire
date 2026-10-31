---
layout: default
title: "ADR-016: UDAP Authentication Token construction"
parent: Architecture Decision Records
nav_order: 16
---

# ADR-016: UDAP Authentication Token construction

**Status:** Accepted

---

## Context

UDAP clients that registered with a certificate authenticate at the token
endpoint with a signed Authentication Token (AnT) sent as `client_assertion`.
HL7 UDAP Security STU2 defines the AnT in the B2B and Consumer-Facing guides
("Constructing Authentication Token") and applies the General Guidance §7.1
JWT header and claim rules to it.

`UdapSoftwareStatement` (ADR-014) already signs UDAP JWTs, and its key, chain,
algorithm, and `alg`/`x5c` header logic was extracted into the private
`UdapSigningCredentials` class. The AnT differs from the software statement
in its claims (`iss`/`sub` are the server-assigned `client_id`, `aud` is the
token endpoint) and in the optional `extensions` claim.

This ADR records how the private `UdapAuthenticationToken` builder applies
those rules. Nothing calls it yet; token-request wiring lands separately.

---

## Decision

Each item is labelled **Normative** (STU2 text, quoted) or **Safire choice**.

### Reuse `UdapSigningCredentials`

**Safire choice.** The builder delegates key parsing, chain order,
key-to-leaf match, certificate validity dates, algorithm negotiation, the JOSE
header, and signing to `UdapSigningCredentials`. No signing logic is
duplicated.

### Claims

- **Normative.** `iss` and `sub` are "The application's `client_id` as
  assigned by the Authorization Server during the registration process"; `aud`
  is "The FHIR Authorization Server's token endpoint URL"; `exp` and `iat` are
  integers; `jti` is "A nonce string value that uniquely identifies this
  authentication JWT" (B2B and Consumer-Facing, Constructing Authentication
  Token).
- **Safire choice.** `client_id` must be a non-blank String. `nil` or blank
  values raise `ConfigurationError` with `missing_attributes: [:client_id]`,
  matching how the SMART protocol reports a missing `client_id`; non-String
  values raise `ConfigurationError` for `:client_id`.

### Lifetime is exactly 300 seconds

- **Normative.** "The maximum lifetime for an Authentication Token SHALL be 5
  minutes, i.e. the value of `exp` minus the value of `iat` SHALL NOT exceed
  300 seconds."
- **Safire choice.** `exp` is always `iat + 300`, matching the software
  statement. The clock is read once per token.

### Fresh `jti` per token

- **Normative.** "the issuer of a JWT SHALL NOT reuse the same `jti` value in
  a new JWT with the same `iss` value prior to the expiration of the previous
  JWT" (General Guidance, JWT Claims).
- **Safire choice.** Every `#to_jwt` call generates a new `jti`, by default
  `SecureRandom.uuid`. An injectable generator must return a non-blank String.

### `aud` is the token endpoint exactly as supplied

- **Normative (SHOULD-level note).** Clients that use a server-provided URI as
  `aud` "should include the URI exactly as it was originally provided by that
  server" (General Guidance, Normalization of URI values in JWTs).
- **Safire choice.** The token endpoint is signed byte-for-byte; Safire does
  not normalize case, ports, or trailing slashes. It must be an absolute HTTPS
  URI with a host and no fragment. `allow_insecure_localhost: true` permits HTTP
  only on `localhost` or `127.0.0.1`, consistent with ADR-007.

### Minimal JOSE header

- **Normative.** All UDAP JWTs carry `alg` and `x5c`, with the leaf
  certificate first (General Guidance, JWT headers).
- **Safire choice.** The header contains only `alg` and `x5c`; no `kid`,
  `typ`, `jku`, or `x5u`.

### No URI SAN check

**Safire choice.** STU2 requires the software statement's `iss` (the client
URI) to match a certificate URI SAN; the AnT's `iss` is the server-assigned
`client_id`, which is not a certificate identity. Safire therefore does not
check URI SANs for the AnT. This is reasoning from the claim definitions, not
a quoted STU2 rule; the authorization server remains responsible for binding
the certificate to the registered client.

### `extensions` shape

- **Normative.** `extensions` is "conditional": "A JSON object containing one
  or more extensions". The B2B guide requires the `hl7-b2b` extension for
  `client_credentials` and says to omit it for `authorization_code`.
- **Safire choice.**
  - `nil` omits the claim. An empty Hash raises `ValidationError` because the
    spec describes "one or more extensions"; silently dropping it would hide a
    caller bug.
  - Keys are non-blank Strings; Symbol keys are stringified at every level, and
    duplicates after stringification are rejected.
  - Each extension value must be a non-empty JSON object. Nested values must be
    JSON-compatible: String, Integer, finite Float, `true`, `false`, `nil`,
    Array, or Hash. Cyclic structures are rejected.
  - The input is deep-copied and frozen at construction, so later caller
    mutation does not change emitted tokens.
  - The builder does not interpret extension contents. Validating `hl7-b2b`
    belongs to a dedicated extension builder; the AnT accepts already-built
    extension objects.
  - `ValidationError` reasons never include extension values.

### Algorithm negotiation

**Safire choice.** The caller passes the server's
`token_endpoint_auth_signing_alg_values_supported`. `UdapSigningCredentials`
selects the first key-compatible advertised algorithm (RS256 preferred for RSA
keys), honors an explicit algorithm only when it is supported, key-compatible,
and advertised, and raises `ConfigurationError` when there is no usable
intersection (ADR-014).

### Certificate validity at signing time

**Safire choice.** Certificate validity dates are checked at construction and
rechecked at the signing time read in `#to_jwt`; an expired or not-yet-valid
certificate raises `CertificateError`.

---

## Consequences

- AnT and software-statement signing share one signing identity
  implementation and differ only in claims.
- Each `#to_jwt` call returns a new token with a fresh `jti`, so callers must
  build a new assertion for every token request rather than caching one.
- Invalid client IDs, endpoints, or extension objects fail before any JWT is
  produced, and error messages do not contain key material or claim values.
- The builder is not yet wired into token requests.
