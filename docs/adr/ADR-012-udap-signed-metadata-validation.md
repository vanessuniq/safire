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
3. Validating the X.509 chain using `x5c[1..]`, caller-supplied trust anchors, and explicit
   revocation policy/material.
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

### Chain and revocation verification on by default; `verify_chain: false` for dev/test only

`verify_chain: true` is the secure production default. Skipping chain and revocation verification
is an explicit opt-in intended for development and testing against servers whose certificates are
not rooted in a trusted CA. The parameter threads from `Udap#server_metadata` through to
`UdapSignedMetadataValidator`.

When `verify_chain: true`, validation fails closed unless the caller supplies either `crls:` or a
custom `revocation_checker:`. CRLs are applied to the OpenSSL certificate store with CRL checking
enabled. A custom checker must return literal `true`; any other value or exception is treated as a
revocation validation failure.

### Signed endpoint claims merged before constructing `UdapMetadata`

`Udap#fetch_metadata` validates `signed_metadata` and merges the authoritative signed endpoint
claims over the unsigned JSON values before constructing the `UdapMetadata` instance. Callers
never receive a `UdapMetadata` object with unverified endpoint URLs. If validation fails,
`Safire::Errors::DiscoveryError` is raised.

### Cached metadata is revalidated before reuse

`Protocols::Udap` caches parsed metadata per community and trust policy, but cache hits are not
blind returns. Before returning cached metadata, Safire revalidates the original `signed_metadata`
JWT against the current trust policy. If the JWT has expired, the certificate chain no longer
validates, or the configured revocation policy rejects it, the cache entry is discarded and
discovery is fetched again.

### `UdapMetadata#signed_metadata_valid?` for re-validation

`UdapMetadata` exposes `signed_metadata_valid?(base_url:, ...)` as a convenience for callers who
hold a metadata object and want to explicitly re-validate (for example, with a different trust
anchor set). Instances returned by `Udap#server_metadata` are already pre-validated.

---

## Consequences

- Production use requires providing `trusted_anchors:` plus an explicit revocation policy
  (`crls:` or `revocation_checker:`) to `server_metadata`. With `verify_chain: true`, Safire
  validates against caller-supplied material; it does not fall back to the operating system trust
  store or perform implicit online revocation checks.
- `CertificateError` is reserved for unrecoverable DER parse failures. All other validation
  decisions use the warn-and-return-nil pattern.
- `UdapMetadata#valid?` remains a structural check only; it does not invoke the JWT validator.
