---
layout: default
title: Software Statements
parent: Dynamic Client Registration
grand_parent: UDAP
nav_order: 2
permalink: /udap/dynamic-client-registration/software-statement/
description: "How Safire builds UDAP Security STU2 X.509-backed software statements for Dynamic Client Registration."
---

# Software Statements

{: .no_toc }

<div class="code-example" markdown="1">
**Current status:** Safire can validate registration metadata and construct a
conformant X.509-backed UDAP Security STU2 software statement. Submitting the
registration request to the server is not implemented yet.
</div>

## What Safire Builds

UDAP registration metadata is signed into a compact JWS software statement. The
software statement carries the client registration parameters plus the required
security claims:

| Claim | Safire behavior |
|-------|-----------------|
| `iss` | Exact `client_uri` supplied by the caller |
| `sub` | Same exact value as `iss` |
| `aud` | Exact discovered registration endpoint |
| `iat` | Integer NumericDate from the signing clock |
| `exp` | `iat + 300` seconds |
| `jti` | Fresh UUID by default |

The JOSE header contains only `alg` and `x5c`. The `x5c` value is the supplied
leaf-first, issuer-ordered certificate chain encoded as Base64 DER strings,
without PEM wrappers.

Safire does not emit `typ`, `kid`, `jku`, or `x5u` for registration software
statements.

## Signing Identity

Configure a private key and a leaf-first, issuer-ordered certificate chain as
the client signing identity:

```ruby
config = Safire::ClientConfig.new(
  base_url: 'https://fhir.example.com',
  private_key: File.read('client-key.pem'),
  certificate_chain: [
    File.read('client-cert.pem'),
    File.read('issuing-ca.pem')
  ],
  jwt_algorithm: 'RS256'
)
```

The private key must match the leaf certificate. The leaf certificate must
contain a URI Subject Alternative Name that exactly matches the `client_uri`
used for registration. Safire does not canonicalize the URI before comparison:
case, port, and trailing slash differences are significant.

The `client_uri` is not required to use HTTPS. STU2 permits trust communities to
use other URI schemes for client identifiers, such as decentralized identifiers.
If the client URI uses HTTP or HTTPS, it must include a host.

## Algorithms

The registration server advertises supported software-statement algorithms in
`registration_endpoint_jwt_signing_alg_values_supported`. Safire intersects
that list with the configured private key:

| Key | Safire-supported algorithms |
|-----|-----------------------------|
| RSA | `RS256`, `RS384` |
| EC P-256 | `ES256` |
| EC P-384 | `ES384` |

When `jwt_algorithm` is omitted, Safire selects the first compatible advertised
algorithm. RSA keys prefer `RS256` because it is the STU2 baseline. An explicit
algorithm must be advertised by the server and compatible with the key.

## Validation Boundaries

Safire performs local consistency checks before signing:

- registration metadata must already be a `UdapRegistrationMetadata` object
- certificate chains must be non-empty, leaf-first, and issuer-ordered
- certificate entries must be parseable PEM strings or `OpenSSL::X509::Certificate` objects
- every certificate must be valid according to the signing clock when the
  builder is created and when the JWT is emitted
- the private key must contain private material and match the leaf certificate
- the client URI must exactly match a URI SAN in the leaf certificate
- the registration endpoint must be HTTPS unless `allow_insecure_localhost: true`
  is explicitly used for an HTTP loopback endpoint in development

Safire does not decide whether the authorization server trusts the client
certificate. Chain validation, revocation status, and community trust for the
client certificate are authorization-server decisions during registration.

See [ADR-014]({% link adr/ADR-014-udap-software-statement-signing.md %}) for
the signing design rationale.
