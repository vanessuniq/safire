---
layout: default
title: "ADR-013: UDAP registration metadata as an immutable value object"
parent: Architecture Decision Records
nav_order: 13
---

# ADR-013: UDAP registration metadata as an immutable value object

**Status:** Accepted

---

## Context

UDAP Dynamic Client Registration signs caller-controlled client metadata into a
software statement. Once signed, that statement is authoritative: the
registration server uses it instead of an unsigned request-body field when the
same metadata appears in both places.

This creates a trust boundary before cryptographic construction. Safire must
reject malformed or ambiguous registration metadata before signing, while still
preserving valid extension fields allowed by RFC 7591. Discovery entities are
not an appropriate model for this boundary: they represent remote input and use
warn-and-return-false compliance checks, whereas registration metadata is local
input that must either produce one canonical payload or raise.

The conformance target is
[HL7 UDAP Security STU2 / v2.0.0](https://hl7.org/fhir/us/udap-security/STU2/registration.html),
which builds on the
[UDAP Dynamic Client Registration profile](https://www.udap.org/udap-dynamic-client-registration-stu1.html).

---

## Decision

### Use a dedicated strict value object

`UdapRegistrationMetadata` validates and normalizes the caller's metadata at
construction. Invalid input raises `Safire::Errors::ValidationError` with the
failing attribute and a value-free reason. The class does not inherit from
`Entity` and does not use the discovery layer's warn-and-return-false contract.

Top-level string and symbol keys are normalized to strings. Supplying both forms
of one key is rejected rather than allowing insertion order to decide which
value is signed. The value object and its canonical internal hash are frozen,
and `to_h` returns a defensive copy.

### Enforce exact STU2 grant shapes

Registration accepts exactly one primary grant:

- `authorization_code`, optionally with `refresh_token`
- `client_credentials`

Unknown and duplicate grant values are rejected. `redirect_uris`, `logo_uri`,
and generated `response_types: ["code"]` apply only to authorization-code
registration. Redirect and logo URIs require absolute HTTPS by default.

For local development without TLS, callers may explicitly pass
`allow_insecure_localhost: true`. This permits HTTP only on `localhost` and
`127.0.0.1`; remote HTTP remains invalid. Safire warns only when the exception
is actually used. The library does not infer a framework environment because
an implicit environment default could silently weaken production validation.
Metadata created through the exception is intentionally documented as
non-conformant.

Cancellation is a separate `operation: :cancel` mode. Callers omit
`grant_types`; Safire injects an empty array and removes authorization-only
metadata from the canonical result.

### Reserve protocol-owned fields

Safire generates `token_endpoint_auth_method: "private_key_jwt"` and, when
applicable, `response_types`. Callers cannot supply those fields, registered JWT
claims, or request-envelope fields such as `software_statement`,
`certifications`, and `udap`.

Unknown RFC 7591 extension fields are retained only when their values are exact
JSON data: strings, finite JSON numbers, booleans, null, arrays, or objects with
string keys and recursively valid values. Ruby-specific values and recursive
collections are rejected.

### Use the standard-library mail boundary

`contacts` must be a non-empty array of absolute URI strings with at least one
valid `mailto:` address. Safire parses mail contacts as `URI::MailTo`, obtains
addresses from `URI::MailTo#to`, and applies
`URI::MailTo::EMAIL_REGEXP`. It does not maintain a project-specific email
regular expression.

---

## Consequences

- Signing code can consume one canonical, already validated metadata hash.
- Caller mutations cannot change metadata between validation and signing.
- Protocol-owned claims cannot be shadowed through caller input.
- Plain HTTP remains impossible for remote hosts; local HTTP requires a literal
  boolean opt-in and produces a warning.
- Extension metadata remains forward-compatible without permitting arbitrary
  Ruby objects into a JWT payload.
- Metadata validation is available before the software-statement builder and
  network registration flow are implemented; this ADR does not make UDAP DCR
  end to end available.
