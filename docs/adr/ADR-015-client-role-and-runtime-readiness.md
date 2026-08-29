---
layout: default
title: "ADR-015: Client role and runtime readiness"
parent: Architecture Decision Records
nav_order: 15
---

# ADR-015: Client role and runtime readiness

**Status:** Accepted

---

## Context

Safire consumes metadata and protocol responses from remote SMART App Launch
and UDAP servers. Some defects make a client request unsafe or impossible;
others are server conformance defects that an interoperable client can report
without blocking an otherwise valid operation.

A blanket rule such as "caller input raises, server input warns" is not
sufficient at a protocol trust boundary. A server controls discovery and token
responses, but Safire must still reject an untrusted value when it is needed to
select a secure endpoint, validate a signed assertion, protect credentials, or
establish that a lifecycle operation completed. Conversely, complete server
certification is outside a client library's runtime role.

Safire therefore needs a consistent way to distinguish operational readiness
from optional conformance diagnostics. Comprehensive server certification
belongs in a conformance harness such as Inferno.

## Decision

Safire classifies protocol checks by their effect on the requested client
operation:

1. **Runtime hard failure:** reject a condition that would violate a client
   obligation, make the operation unsafe or impossible, expose credentials, or
   leave a security-sensitive result unconfirmed. This includes malformed wire
   shapes required by the operation and failed UDAP signed-metadata trust
   validation.
2. **Warning or negotiation:** report a server defect or uncertain capability
   when Safire can still send a safe, conformant request and the server remains
   authoritative for acceptance.
3. **Explicit diagnostic:** methods such as `SmartMetadata#valid?`,
   `UdapMetadata#valid?`, and `Smart#token_response_valid?` warn and return a
   Boolean when called. Discovery does not automatically promote every failed
   diagnostic into a workflow failure.
4. **Server-owned decision:** authorization grants, requested scope approval,
   client registration policy, certifications, and issued credentials are
   decided by the authorization server. Safire validates its request and the
   response shape it must consume, but does not predict the policy result.

This decision refines ADR-008. Server-controlled data is warning-only when the
defect does not cross a security or operation-readiness boundary; its remote
origin alone does not determine the error behavior.

Protocol response bodies that must be JSON objects use the private,
protocol-neutral `JSONResponseParsing` collaborator. It accepts an already
parsed `Hash` or a raw JSON string, produces a new deeply string-keyed Hash, and
rejects malformed or non-object JSON. Adapter-supplied Hashes also fail closed
when they contain recursive structures, unsupported JSON key or value types,
non-finite numbers, invalid string encodings, excessive nesting, or keys that
collide after symbol-to-string normalization. The collaborator returns a parse
failure and leaves each consumer to choose its protocol-specific error class.

Parsing a valid raw JSON object allows interoperability when an HTTP adapter did
not decode the body because the server sent an incorrect or missing content
type. Safire's tolerance does not make that server response conformant.

Metadata capability helpers type-check list-shaped advertisements before using
membership semantics. A malformed list cannot assert a SMART capability or
raise an unexpected type error. The complete structural assessment remains the
caller's explicit `SmartMetadata#valid?` diagnostic rather than an automatic
discovery failure.

SMART discovery preserves metadata for inspection, but an operation validates
its discovered authorization or token endpoint against Safire's HTTPS policy
before use. This focused runtime stop protects authorization data and client
credentials without promoting unrelated metadata defects into discovery
failures.

UDAP DCR uses focused readiness rather than calling `UdapMetadata#valid?` as an
operational gate. Safire requires trusted discovery, an advertised `udap_dcr`
profile, a usable authoritative registration endpoint, usable registration
algorithm metadata, and type-safe certification requirements. Other structural
conformance checks remain available through the explicit `valid?` diagnostic.

In v0.4.1, requested UDAP registration scopes are diagnostic only. Requested
tokens containing a literal `*` are classified first and compared by exact
membership in `scopes_supported`; narrower recognized SMART FHIR scopes may be
covered by broader advertised scopes. Unrecognized syntax uses exact membership.
Missing, malformed, or insufficient advertisements produce separate aggregated
warnings while the server remains authoritative for negotiation. Registration
and modification move to exact wildcard enforcement in v0.5.0; cancellation
remains warning-only so an existing registration can still be removed.

For warning suppression only, compatible advertised FHIR permission fragments
may collectively cover a requested permission set. STU2 does not guarantee that
the server accepts the combined token, so this permissive inference must not be
reused as a hard-failure decision without a separate normative rule.

SMART Backend Services scope intent remains client-owned. In v0.4.x, Safire
preserves the historical `system/*.rs` fallback only for compatibility and
logs a deprecation warning whenever it is used. Callers should configure or
pass scopes explicitly; absent scopes become a runtime `ConfigurationError` in
v0.6.0. SMART discovery `scopes_supported` is non-exhaustive and is not used as
an exact allow-list for token requests.

`system/` scopes are the normal Backend Services context. The
[SMART STU2.2 Backend Services scope requirements](https://hl7.org/fhir/smart-app-launch/STU2.2/backend-services.html#scopes)
also state that `user/` and `patient/` scopes are not prohibited when context
is established through out-of-band coordination. Safire therefore preserves
and submits explicit non-system scopes without warning or rejection. The
library cannot determine whether the caller completed that external
coordination, and must not make a permitted healthy path noisy based on missing
local evidence.

Scope diagnostics log only the requested scope category and count, never the
raw token values. SMART v2 scopes may carry FHIR search constraints, and opaque
custom scopes may encode equally sensitive application context in forms Safire
cannot safely redact. Count-and-category logging preserves the operational and
migration signal without copying caller-controlled authorization details into
application logs.

The classifications below were checked against the published
[SMART App Launch STU2.2 conformance and discovery rules](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html),
[SMART App Launch workflow](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html),
[SMART Backend Services profile](https://hl7.org/fhir/smart-app-launch/STU2.2/backend-services.html),
[RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591),
[UDAP Security STU2 discovery](https://hl7.org/fhir/us/udap-security/STU2/discovery.html),
and [UDAP Security STU2 registration](https://hl7.org/fhir/us/udap-security/STU2/registration.html).

## Operation Matrix

This matrix covers the public protocol operations currently implemented by the
`Safire::Client` facade.

| Operation | Client obligation | Required capability or input | Runtime hard failure | Runtime warning or negotiation | Explicit diagnostic | Server-owned decision |
|-----------|-------------------|------------------------------|----------------------|--------------------------------|---------------------|-----------------------|
| SMART `server_metadata` | Request and consume the well-known JSON object over a protected connection | FHIR base URL | Transport or HTTP failure; unusable JSON-object body | None | Caller may invoke `SmartMetadata#valid?` | Advertised endpoints and capabilities |
| SMART `authorization_url` | Supply client ID, redirect URI, scopes, and launch context as applicable; Safire adds state and S256 PKCE | Usable authorization endpoint; caller selects GET or POST | Invalid request method; missing client ID, scopes, or redirect URI; missing, malformed, or insecure endpoint | None | Metadata capability helpers and `SmartMetadata#valid?` remain caller-invoked | User authorization, launch context, accepted request method, and granted scopes |
| SMART `request_access_token` | Supply the authorization code, matching PKCE verifier, redirect URI, and client credentials required by the configured client type | Usable token endpoint | Missing credentials; invalid JWT assertion configuration; missing, malformed, or insecure endpoint; transport, OAuth, unusable response, or missing access-token failure | None | Caller may invoke `token_response_valid?` | Code acceptance and issued token contents |
| SMART `refresh_token` | Supply the refresh token and authenticate the client; any requested scopes must not exceed the original grant | Usable token endpoint | Missing credentials; invalid JWT assertion configuration; missing, malformed, or insecure endpoint; transport, OAuth, unusable response, or missing access-token failure | None | Caller may invoke `token_response_valid?` | Refresh-token acceptance and issued scope |
| SMART `request_backend_token` | Supply client ID, a registered signing identity, and explicit scope intent | Usable token endpoint and pre-authorized asymmetric client registration | Missing identity or signing credentials; invalid JWT assertion configuration; missing, malformed, or insecure endpoint; transport, OAuth, unusable response, or missing access-token failure | The v0.4.x legacy scope fallback warns; explicit scopes remain subject to server negotiation | Caller may invoke `token_response_valid?(flow: :backend_services)` | Out-of-band context, client authentication, requested scope, and token issuance |
| SMART `register_client` | Supply RFC 7591 client metadata and any required initial access token | Explicit or discovered HTTPS registration endpoint | Missing or unsafe endpoint; transport or OAuth failure; unusable response or missing/invalid client ID | None | Discovery capability helpers and `SmartMetadata#valid?` remain caller-invoked | Registration policy, accepted metadata, and issued credentials |
| SMART `token_response_valid?` | Choose whether to require the optional conformance diagnostic | Token-response Hash and selected flow | None; this method is not an operational gate | Logs each diagnosed response defect and returns `false` | This method is the explicit diagnostic | Caller decides how to handle a failed diagnostic |
| UDAP `server_metadata` | Supply the intended community and production trust/revocation policy; validate signed metadata before any later workflow | UDAP well-known endpoint and a trusted signed-metadata chain | Transport, HTTP, or 204 outcome; unusable JSON object; failed signature, chain, revocation, issuer, time, or endpoint validation | None | Caller may invoke `UdapMetadata#valid?` or explicitly re-run `signed_metadata_valid?` | Community-specific profiles and capabilities |
| UDAP `register_client` | Supply conformant metadata, client URI, certifications when required, and a matching private key/certificate chain | Trusted discovery; `udap_dcr`; authoritative registration endpoint; usable algorithm and certification-requirement metadata | Unsafe or unusable readiness data; invalid caller metadata or signing identity; transport or server rejection; pending or malformed completion response | Missing RS256 advertisement and unconfirmed scope support warn in v0.4.1 | Caller may invoke `UdapMetadata#valid?`; it is not a blanket gate | Registration policy, scope and certification acceptance, effective metadata, and issued client ID |
| UDAP `cancel_registration` | Supply the same stable client URI and trust-community identity; preserve local state until cancellation is confirmed | Registration readiness above and an existing registration to remove | Registration hard failures above; any response that does not provide final 2xx body confirmation with the client ID and empty grants | Scope compatibility and malformed scope advertisements remain warning-only so cleanup can proceed | Caller may invoke `UdapMetadata#valid?`; it is not a blanket gate | Cancellation policy and the confirmation response |

SMART cancellation and UDAP authorization, token, refresh, backend-token, and
token-response operations are not implemented. They raise
`NotImplementedError` through the shared protocol contract rather than implying
runtime support.

### Rules for Future Operations

Every new public protocol operation must update the matrix and apply these
questions in order:

1. Which normative actor owns the requirement: client, authorization server,
   resource server, or trust community?
2. Does a failure prevent Safire from constructing a conformant request,
   selecting a trusted endpoint, protecting credentials, or confirming the
   operation's result? If so, fail before signing or network activity whenever
   the condition is locally knowable.
3. Can Safire still send a safe, conformant request while the server remains
   authoritative for policy or negotiation? If so, preserve the request and use
   a warning only when it gives the caller actionable information.
4. Is the check broad server conformance rather than operation readiness? Keep
   it in an explicit diagnostic and do not call it automatically.
5. Is untrusted response data consumed by the operation? Validate its type and
   shape before use, and translate failure into the protocol-specific Safire
   error rather than leaking a Ruby implementation exception.
6. Does an error prove rejection, or only an unavailable, malformed, pending,
   or otherwise unconfirmed outcome? Use only the strongest description the
   evidence supports.
7. Does the implementation invent client intent, retry a possibly committed
   operation, or log caller credentials or authorization details? If so, stop
   and require an explicit, documented policy instead.

Shared helpers may encode mechanism, such as JSON-object parsing or
warning-only UDAP scope coverage, but must not silently promote a diagnostic
inference into a hard-failure rule for another workflow.

## Consequences

**Benefits:**

- Runtime failures now have an operation or security rationale rather than
  serving as blanket server certification.
- Callers retain explicit tools for enforcing stricter server conformance.
- Shared JSON-object parsing is total for untrusted adapter output and preserves
  protocol-specific error ownership.
- Valid raw JSON objects remain usable even when response content-type handling
  is imperfect.

**Trade-offs:**

- The same metadata defect can be diagnostic in one flow and fatal in another
  when the latter needs the affected field to proceed safely.
- Tolerating a raw JSON object can hide an HTTP content-type defect unless the
  caller separately audits server conformance.
- The operation matrix must be updated whenever a public protocol operation or
  runtime gate is added or materially changed.
