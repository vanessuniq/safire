---
layout: default
title: "ADR-011: UdapMetadata entity — structural validation separate from cryptographic validation"
parent: Architecture Decision Records
nav_order: 11
---

# ADR-011: `UdapMetadata` entity — structural validation separate from cryptographic validation

**Status:** Accepted

---

## Context

UDAP Security STU2 discovery returns a JSON object from `/.well-known/udap`. That object must be
parsed into a typed entity and validated before any downstream flow (Dynamic Client Registration,
JWT client authentication, etc.) can proceed. Two distinct validation concerns arise:

1. **Structural validation** — are all required fields present? Do they satisfy the fixed-value
   and conditional constraints specified in STU2?
2. **Cryptographic validation** — is the `signed_metadata` JWT signature valid, and does the
   embedded X.509 chain chain to a trusted anchor?

These concerns operate at different layers: structural checks need only the parsed JSON object,
while cryptographic checks require a trusted certificate store and key material. Mixing them
inside the same class would make the entity difficult to test (crypto requires real certs) and
would couple two unrelated failure modes.

---

## Decision

`UdapMetadata` handles structural parsing and validation only. It inherits from `Safire::Entity`
(the same base used by `SmartMetadata`) and follows the same warn-and-return-false convention
for `valid?`.

**Conformance target:** HL7 UDAP Security STU2 / v2.0.0
([discovery section](https://hl7.org/fhir/us/udap-security/STU2/discovery.html)).

**Signed metadata:** STU2 uses `signed_metadata` (not the deprecated `signed_endpoints` from
earlier drafts). `signed_metadata` is treated as a required field by `UdapMetadata#valid?` and
as an opaque string. Cryptographic validation of the JWT is intentionally deferred to a
dedicated validator (see ADR-012).

**Presence check uses `nil?`, not `blank?`:** Several required array fields — for example,
`udap_authorization_extensions_supported` — may legitimately be empty arrays in a conformant
response. Using `blank?` would flag `[]` as absent; using `nil?` preserves the distinction
between "field not present in the JSON response" and "field present but empty".

**Array type validation is explicit:** Discovery metadata is untrusted JSON. `UdapMetadata#valid?`
verifies every array-valued field is actually an Array before it performs profile, grant,
non-empty, or subset checks. Public helper methods also treat malformed scalar metadata as
unsupported instead of using Ruby string `include?` semantics.

**Value-level constraints in `valid?`:**

- `udap_versions_supported` must equal `["1"]` exactly (STU2 fixed value)
- `udap_profiles_supported` must include `"udap_dcr"` and `"udap_authn"` (both required by STU2)
- `token_endpoint_auth_methods_supported` must equal `["private_key_jwt"]` exactly (STU2 fixed value)
- `scopes_supported` and `grant_types_supported` must each have at least one element
- `authorization_endpoint` is conditionally required when `grant_types_supported` includes
  `"authorization_code"`
- `"udap_authz"` is conditionally required in `udap_profiles_supported` when `grant_types_supported`
  includes `"client_credentials"`
- `"authorization_code"` is conditionally required in `grant_types_supported` when `"refresh_token"`
  is also present
- `udap_authorization_extensions_required` is conditionally required when
  `udap_authorization_extensions_supported` is non-empty; its values must be a subset of
  `udap_authorization_extensions_supported`
- `udap_certifications_required` is conditionally required when `udap_certifications_supported`
  is non-empty; its values must be a subset of `udap_certifications_supported`

**Public helpers follow a two-tier naming convention:**

- *Profile checks* (`dynamic_registration_profile?`, `jwt_client_auth_profile?`, etc.) test
  only whether the server advertises the profile string in `udap_profiles_supported`; they do
  not check whether all required supporting fields are present.
- *Capability checks* (`supports_dynamic_registration?`, `supports_jwt_client_auth?`, etc.)
  combine profile advertisement with any additional preconditions (e.g.,
  `supports_dynamic_registration?` also requires `registration_endpoint` to be present).

---

## Consequences

**Benefits:**

- Structural conformance is independently testable without any certificate infrastructure
- `valid?` follows the same warn-and-return-false contract as `SmartMetadata#valid?`, giving
  callers a consistent API across protocols
- `signed_metadata` cryptographic validation can be added (or skipped in dev/test) without
  touching the entity

**Trade-offs:**

- A structurally valid `UdapMetadata` object is not automatically cryptographically validated;
  callers that require full STU2 conformance must also invoke `signed_metadata_valid?`
  (introduced in ADR-012) after structural validation passes
