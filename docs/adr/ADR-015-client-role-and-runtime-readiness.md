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

Scope diagnostics log only the requested scope category and count, never the
raw token values. SMART v2 scopes may carry FHIR search constraints, and opaque
custom scopes may encode equally sensitive application context in forms Safire
cannot safely redact. Count-and-category logging preserves the operational and
migration signal without copying caller-controlled authorization details into
application logs.

## Operation Matrix

This matrix covers the public protocol operations currently implemented by the
`Safire::Client` facade.

| Protocol operation | Runtime hard failures | Warning or explicit diagnostic | Server-owned decision |
|--------------------|-----------------------|--------------------------------|-----------------------|
| SMART `server_metadata` | Transport/HTTP failure or a body that cannot be used as a JSON object | `SmartMetadata#valid?` is caller-invoked | Advertised capabilities |
| SMART `authorization_url` | Invalid method; missing client ID, scopes, redirect URI, or usable authorization endpoint | Metadata diagnostics remain explicit | User authorization, launch context, and granted scopes |
| SMART `request_access_token` | Missing client credentials; unusable token endpoint; OAuth error; malformed token response or missing access token | `token_response_valid?` is caller-invoked | Code acceptance and issued token contents |
| SMART `refresh_token` | Missing client credentials; unusable token endpoint; OAuth error; malformed token response or missing access token | `token_response_valid?` is caller-invoked | Refresh-token acceptance and issued scope |
| SMART `request_backend_token` | Missing client ID or signing credentials; unusable token endpoint; OAuth error; malformed token response or missing access token | `token_response_valid?(flow: :backend_services)` is caller-invoked | Client authentication, requested scope, and token issuance |
| SMART `register_client` | Missing or unsafe registration endpoint; OAuth error; malformed response or missing/invalid client ID | SMART metadata diagnostics remain explicit | Registration policy and issued credentials |
| SMART `token_response_valid?` | None; this is not an operational gate | Warns and returns `false` for response conformance defects | Caller decides whether a failed diagnostic is acceptable |
| UDAP `server_metadata` | Transport/HTTP/204 failure; non-object JSON; failed signed-metadata signature, chain, revocation, issuer, time, or endpoint validation | `UdapMetadata#valid?` is caller-invoked | Supported communities, profiles, and capabilities |
| UDAP `register_client` | Untrusted discovery; unusable DCR profile, endpoint, algorithm, or certification-requirement metadata; invalid client metadata, signing identity, or response; server rejection | Missing RS256 and unconfirmed scope support warn; `UdapMetadata#valid?` remains caller-invoked | Registration policy, scope and certification acceptance, and issued client ID |
| UDAP `cancel_registration` | The registration gates above plus a response that does not positively confirm the client ID and empty grants | Scope compatibility remains warning-only for lifecycle-safe cleanup; `UdapMetadata#valid?` remains caller-invoked | Cancellation policy and confirmation response |

SMART cancellation and UDAP authorization, token, refresh, backend-token, and
token-response operations are not implemented. They raise
`NotImplementedError` through the shared protocol contract rather than implying
runtime support.

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
