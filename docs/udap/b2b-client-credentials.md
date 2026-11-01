---
layout: default
title: B2B Client Credentials
parent: UDAP
nav_order: 2
permalink: /udap/b2b-client-credentials/
description: "Request UDAP Security STU2 B2B access tokens with the client credentials grant."
---

# B2B Client Credentials

{: .no_toc }

Safire implements the UDAP Security STU2
[B2B client credentials flow](https://hl7.org/fhir/us/udap-security/STU2/b2b.html#obtaining-an-access-token)
through `Safire::Client#request_backend_token` on a `protocol: :udap` client.
The same facade method performs SMART Backend Services for `protocol: :smart`
clients; the grant is chosen by the method, not by a configuration flag.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Prerequisites

- **A registered `client_id`.** Register the client with
  `grant_types: ['client_credentials']` using
  [Dynamic Client Registration]({% link udap/dynamic-client-registration/index.md %})
  and store the returned `client_id`. Safire uses it as the Authentication
  Token `iss` and `sub`.
- **The same signing identity used for registration:** `private_key` and a
  leaf-first `certificate_chain`.
- **Server trust inputs** for discovery: `trusted_anchors:` plus `crls:` or a
  `revocation_checker:`, and `community:` when the server serves several trust
  communities.

## Configuration

```ruby
client = Safire::Client.new(
  {
    base_url:          'https://fhir.example.com',
    client_id:         stored_client_id,
    scopes:            ['system/Patient.rs', 'system/Observation.rs'],
    private_key:       File.read('client-key.pem'),
    certificate_chain: [File.read('client-cert.pem'), File.read('issuing-ca.pem')]
  },
  protocol: :udap
)
```

`jwt_algorithm` is optional. When omitted, Safire picks a key-compatible
algorithm advertised in `token_endpoint_auth_signing_alg_values_supported`,
preferring RS256 for RSA keys.

## Requesting a token

```ruby
token_data = client.request_backend_token(
  b2b: {
    organization_id:   'https://fhir.example.com/Organization/123',
    organization_name: 'Example Clinic',
    purpose_of_use:    ['urn:oid:2.16.840.1.113883.5.8#TREAT']
  },
  trusted_anchors: [udap_ca],
  crls:            [udap_crl]
)

token_data['access_token']
```

Keyword arguments:

| Keyword | Purpose |
|---------|---------|
| `scopes:` | Array of scope strings or a space-delimited String. Falls back to configured `scopes` when it yields no scope |
| `b2b:` | **Required.** Members of the `hl7-b2b` B2B Authorization Extension Object |
| `extensions:` | Optional Hash of additional Authorization Extension Objects keyed by extension name. Must not contain `hl7-b2b` |
| `community:` | Optional trust-community URI for discovery |
| `trusted_anchors:`, `crls:`, `revocation_checker:`, `verify_chain:` | Server trust policy for `signed_metadata`, as in discovery and registration |
| `private_key:`, `certificate_chain:`, `jwt_algorithm:` | Per-call overrides of the configured signing identity |

What Safire sends (STU2 b2b §5.2.2): a form-encoded POST to the authoritative
signed `token_endpoint` with exactly `grant_type=client_credentials`, `scope`,
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
`client_assertion`, and `udap=1`. Clients "SHALL NOT include an HTTP
Authorization header or client secret", so Safire sends neither, and does not
send `client_id` in the body.

The `client_assertion` is an Authentication Token signed with `alg` and `x5c`
headers. Its claims are `iss` and `sub` (the `client_id`), `aud` (the token
endpoint exactly as published in signed metadata), `iat`, `exp` (exactly 300
seconds later, the STU2 maximum), a fresh `jti`, and `extensions`.

Safire validates its inputs before any network request, then discovers and
validates signed metadata, checks token-request readiness, signs, and POSTs
once. It never retries a token request.

### Scopes

STU2 marks `scope` **required** for client credentials token requests. Safire
has no default scope: if neither `scopes:` nor the configured `scopes` yields a
scope, it raises `ConfigurationError` before discovery. Values are split on
whitespace, and blanks and duplicates are removed.

Scope negotiation follows
[General §7.3](https://hl7.org/fhir/us/udap-security/STU2/general.html#scope-negotiation):
"A client application MAY request a wildcard scope only if wildcards are
specified in the server's `scopes_supported` metadata list." Safire treats any
scope containing `*` as a wildcard. An unadvertised wildcard raises
`ValidationError` before the token request is signed or sent. Non-wildcard
scopes are left to the server, and Safire logs at most one warning that
contains a count but no scope values. The server may grant fewer, more, or
different scopes, so check the `scope` field in the response.

## The `hl7-b2b` extension

STU2 b2b §5.2.1 says the B2B Authorization Extension Object "is required for B2B
client apps using the `client_credentials` flow". Safire therefore always
sends `extensions['hl7-b2b']`, even when the server does not list `hl7-b2b` in
`udap_authorization_extensions_supported`. In that case it logs a value-free
warning.

| Member | STU2 rule (normative) | Safire behavior |
|--------|-----------------------|-----------------|
| `version` | Fixed value `"1"` | Added by Safire; you may omit it or pass `"1"` |
| `organization_id` | Required; "SHALL be a Uniform Resource Identifier (URI)" | Must be a non-blank absolute URI. Which URI schemes are allowed and whether URLs resolve is up to the trust community and cannot be checked by Safire |
| `purpose_of_use` | Required; "An array of one or more strings" | Must be a non-empty array of non-blank strings. Code values are not checked |
| `organization_name` | Optional | Non-blank string |
| `subject_name` | "required if known" | Optional. Safire cannot know whether it is known |
| `subject_id`, `subject_role` | Required if known for human requestors when `subject_name` is present | Optional. *Safire choice:* rejected without `subject_name` |
| `consent_policy` | Optional; array of URIs | Non-empty array of absolute URIs |
| `consent_reference` | Array of absolute URLs; "Omit if `consent_policy` is not present" | Requires `consent_policy`; each entry must be an absolute HTTP(S) URL |

*Safire choice:* unknown members are rejected. Validation errors name the member
but never its value.

Other implementation guides "MAY define additional Authorization Extension
Objects". Pass them with `extensions:`:

```ruby
client.request_backend_token(
  b2b:        b2b_context,
  extensions: { 'example-ext' => { 'version' => '1' } } # defined by another IG or community
)
```

Each entry must be a non-empty Hash with JSON-compatible values. Safire does not
interpret its contents.

### One token per authorization context

STU2 b2b §5.2.3: "A client application SHALL only use an access token in a
manner consistent with any assertions made when requesting that token." When
the requestor, purpose of use, consent, or other asserted context changes,
request a new token with a new `b2b:` object. Safire does not cache tokens, and
each call signs a new Authentication Token.

## Discovery readiness

Before signing, Safire requires trusted discovery. If `signed_metadata` fails
validation, the request stops, because the client "SHALL NOT proceed". Safire
then checks only what the token request needs:

| Condition | Result |
|-----------|--------|
| `udap_authn` missing from `udap_profiles_supported` | `DiscoveryError` |
| `client_credentials` missing from `grant_types_supported` (an empty array means "NOT supported") | `DiscoveryError` |
| `token_endpoint` missing, not absolute HTTPS, or has a fragment (HTTP loopback only with `allow_insecure_localhost`) | `DiscoveryError` |
| `token_endpoint_auth_methods_supported` is not an array including `private_key_jwt` | `DiscoveryError` |
| `token_endpoint_auth_signing_alg_values_supported` is not a non-empty array of strings | `DiscoveryError` |
| `udap_authorization_extensions_required` present but not an array of strings | `DiscoveryError` |
| A required extension key is not in the request | `ValidationError` (attribute `:extensions`, names the missing keys) |
| Unadvertised wildcard scope, or unusable `scopes_supported` with a wildcard | `ValidationError` / `DiscoveryError` |
| No advertised algorithm is compatible with the signing key | `ConfigurationError` |
| RS256 not advertised | Warning; proceeds with another compatible algorithm |
| `udap_authz` not advertised | Warning; proceeds (STU2 says servers SHALL include it when they support client credentials) |
| Sent extension key not in `udap_authorization_extensions_supported` | Warning; proceeds (the server "MAY ignore any unrecognized claims") |

Warnings never include scope values, extension contents, or key names. Full
structural conformance remains available through `UdapMetadata#valid?`.

## Error handling

```ruby
begin
  token_data = client.request_backend_token(b2b: b2b_context, trusted_anchors: [udap_ca], crls: [udap_crl])
rescue Safire::Errors::ConfigurationError => e
  # missing client_id, scopes, private_key, certificate_chain; incompatible algorithm
rescue Safire::Errors::ValidationError => e
  # invalid b2b/extensions/scope input, required extension missing, unadvertised wildcard
rescue Safire::Errors::DiscoveryError => e
  # untrusted or unusable discovery metadata
rescue Safire::Errors::CertificateError => e
  # client certificate chain cannot support signing
rescue Safire::Errors::TokenError => e
  # server rejection (e.error_code such as 'invalid_scope', 'invalid_client')
  # or a success body without a non-blank access_token
rescue Safire::Errors::NetworkError => e
  # connection, TLS, timeout, or blocked redirect
end
```

`TokenError` keeps the OAuth `error` and `error_description` from the server.
A success response must be a JSON object with a non-blank `access_token`, or
Safire raises `TokenError`. STU2 says servers issue access tokens with a
lifetime of no more than 60 minutes and does not constrain the token type.
Safire returns `expires_in` and `token_type` as sent and does not enforce them.

## Limitations

- Only the client credentials grant is implemented. The UDAP authorization
  code and refresh token grants and Tiered OAuth raise `NotImplementedError`.
- Safire's behavior is covered by unit and mocked integration tests. It has
  not been conformance-tested against an external UDAP authorization server or
  a certification harness.
- Trust-community rules, such as allowed `organization_id` schemes, NPI and
  NUCC vocabularies, and PurposeOfUse value sets, cannot be checked locally and
  are the caller's responsibility.
