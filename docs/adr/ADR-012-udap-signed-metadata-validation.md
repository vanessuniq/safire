---
layout: default
title: "ADR-012: signed_metadata JWT validation — design and chain verification defaults"
parent: Architecture Decision Records
nav_order: 12
---

# ADR-012: `signed_metadata` JWT validation — design and chain verification defaults

**Status:** Accepted

---

## Context

UDAP Security STU2 requires that servers include a `signed_metadata` JWT in their discovery
response. Per the spec, clients MUST validate this JWT before using any of the discovered endpoint
URLs. Signed endpoint claims (`token_endpoint`, `registration_endpoint`, and optionally
`authorization_endpoint`) take precedence over the unsigned values in the JSON body.

Validation involves:

1. Decoding the JOSE header and verifying `alg == RS256` and `x5c` is present.
2. Verifying the JWT signature against the leaf certificate in `x5c[0]`.
3. Optionally validating the X.509 chain using `x5c[1..]` and caller-supplied trust anchors.
4. Checking required claims: `iss`, `sub`, `exp`, `iat`, `jti`, `token_endpoint`,
   `registration_endpoint`, and conditionally `authorization_endpoint`.

---

## Decisions

### Separate validator class (`UdapSignedMetadataValidator`)

Cryptographic validation is isolated in `UdapSignedMetadataValidator`, keeping it out of
`UdapMetadata` (the structural entity) and `Udap` (the HTTP discovery orchestrator). This follows
the single-responsibility principle and keeps the entity layer free of crypto dependencies.

### Warn-and-return-nil per failure; raise only on unrecoverable parse errors

Each validation step logs a warning via `Safire.logger.warn` and returns `nil` on failure rather
than raising. This surfaces every applicable warning in a single call. The only exception is a
malformed DER certificate in `x5c`, which raises `Safire::Errors::CertificateError` because the
input cannot be interpreted at all, making further validation impossible.

### Chain verification on by default; `verify_chain: false` for dev/test only

`verify_chain: true` is the secure production default. Skipping chain verification is an explicit
opt-in intended for development and testing against servers whose certificates are not rooted in a
trusted CA. The parameter threads from `Udap#server_metadata` through to `UdapSignedMetadataValidator`.

### Signed endpoint claims merged before constructing `UdapMetadata`

`Udap#fetch_metadata` validates `signed_metadata` and merges the authoritative signed endpoint
claims over the unsigned JSON values before constructing the `UdapMetadata` instance. Callers
never receive a `UdapMetadata` object with unverified endpoint URLs. If validation fails,
`Safire::Errors::DiscoveryError` is raised.

### `UdapMetadata#signed_metadata_valid?` for re-validation

`UdapMetadata` exposes `signed_metadata_valid?(base_url:, ...)` as a convenience for callers who
hold a metadata object and want to explicitly re-validate (for example, with a different trust
anchor set). Instances returned by `Udap#server_metadata` are already pre-validated.

---

## Consequences

- Production use requires providing `trusted_anchors:` to `server_metadata`. Without them, chain
  validation will fail for any certificate not self-signed by a CA in the system store.
- `CertificateError` is reserved for unrecoverable DER parse failures. All other validation
  decisions use the warn-and-return-nil pattern.
- `UdapMetadata#valid?` remains a structural check only; it does not invoke the JWT validator.
