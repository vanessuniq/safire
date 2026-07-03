---
layout: default
title: "ADR-014: UDAP software-statement signing"
parent: Architecture Decision Records
nav_order: 14
---

# ADR-014: UDAP software-statement signing

**Status:** Accepted

---

## Context

UDAP Dynamic Client Registration submits caller-controlled registration
metadata inside a signed software statement. HL7 UDAP Security STU2 requires
that statement to be a compact JWS with an `alg` header, an inline leaf-first
`x5c` certificate chain, issuer and subject set to the client URI, audience set
to the authorization server's registration endpoint, a short validity window,
and a fresh `jti`.

Safire already has `JWTAssertion` for SMART private-key JWT authentication, but
that class has SMART-specific audiences, claims, headers, algorithms, and key
distribution assumptions. Reusing it for UDAP would require protocol branches
in the signing path and make both flows harder to reason about.

---

## Decision

### Use a dedicated builder

`UdapSoftwareStatement` builds only UDAP registration software statements. It
accepts a validated `UdapRegistrationMetadata` object, a client URI, the
discovered registration endpoint, a private key, a leaf-first certificate
chain, and the server-advertised registration signing algorithms.

The builder has no HTTP behavior and does not perform discovery. UDAP protocol
orchestration will remain responsible for fetching metadata, checking DCR
capability, and POSTing the request envelope in a later PR.

### Keep URI comparison exact

The client URI is used exactly as `iss` and `sub` and must exactly match a
`uniformResourceIdentifier` Subject Alternative Name entry in the leaf
certificate. Safire does not derive it from `ClientConfig#issuer` and does not
canonicalize case, ports, or trailing slashes.

STU2 does not constrain the URI scheme used for client identifiers, so Safire
does not require `client_uri` to use HTTPS. HTTP and HTTPS client URIs must have
a host, while trust-community schemes such as `did:` can be valid when they are
absolute and exactly match the certificate URI SAN.

The registration endpoint is different: it is a server endpoint used as `aud`
and must be an absolute HTTPS URI by default. `allow_insecure_localhost: true`
permits HTTP only on `localhost` or `127.0.0.1` for local development. The value
is still signed exactly as supplied.

### Generate a minimal JOSE header

Safire includes only the required `alg` and `x5c` header fields. It does not
emit `typ`, `kid`, `jku`, or `x5u`. STU2's experimental `jku` alternative does
not apply to registration requests.

`x5c` is generated from the supplied certificate chain in leaf-first order. Each
entry is Base64 DER with no PEM wrapper.

### Constrain algorithm selection

Safire supports the STU2 algorithm set it can sign safely:

| Key | Algorithms |
|-----|------------|
| RSA | `RS256`, `RS384` |
| EC P-256 | `ES256` |
| EC P-384 | `ES384` |

An explicit algorithm must be supported by Safire, compatible with the private
key, and advertised by the server. Without an explicit algorithm, Safire chooses
the first key-compatible advertised algorithm, preferring `RS256` over `RS384`
for RSA keys because `RS256` is the STU2 baseline.

### Validate local signing identity, not server trust

Before signing, Safire parses and snapshots the certificate chain, checks
certificate validity dates with the injected clock, verifies that the private
key matches the leaf certificate, and checks that the client URI appears in the
leaf certificate URI SAN.

Safire does not decide whether the authorization server will trust the client
certificate chain. Chain-building, revocation policy, and community trust for
the client certificate remain authorization-server decisions during
registration processing.

### Keep test seams explicit

The builder accepts a clock and a JTI generator. Production defaults are
`Time.now` and `SecureRandom.uuid`; specs inject deterministic values without
stubbing global randomness.

---

## Consequences

- SMART JWT assertions and UDAP software statements remain separate, readable
  signing paths.
- Invalid local signing configuration fails before a malformed JWT can be
  produced.
- The generated JWT is short-lived: `exp` is always `iat + 300`.
- Private keys, compact JWTs, and certificate contents are not included in
  validation error messages.
- End-to-end UDAP registration still requires the protocol orchestration PR
  that discovers metadata, builds the request envelope, POSTs to the
  registration endpoint, and parses the response.
