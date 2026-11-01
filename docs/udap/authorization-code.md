---
layout: default
title: Authorization Code
parent: UDAP
nav_order: 3
permalink: /udap/authorization-code/
description: "Run the UDAP Security STU2 authorization code flow for consumer-facing and interactive B2B apps."
---

# Authorization Code

{: .no_toc }

Safire implements the UDAP Security STU2
[authorization code flow](https://hl7.org/fhir/us/udap-security/STU2/general.html#authorization-code-flow)
on a `protocol: :udap` client through the same facade methods as SMART:
`Safire::Client#authorization_url`, `#request_access_token`, and `#refresh_token`.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Consumer-facing and interactive B2B apps

STU2 defines the same authorization request for
[consumer-facing apps (§4.1)](https://hl7.org/fhir/us/udap-security/STU2/consumer.html#obtaining-an-authorization-code)
and for
[B2B apps registered for the authorization code grant (§5.1)](https://hl7.org/fhir/us/udap-security/STU2/b2b.html#obtaining-an-authorization-code).
Both defer to the constraints in General §7.2. Safire has one implementation
for both. There is no `flow:` or app-type option.

| Use | Registration `grant_types` | Typical scopes |
|-----|----------------------------|----------------|
| Consumer-facing app (patient or consumer user) | `['authorization_code']` (add `refresh_token` if the server issues refresh tokens) | `patient/` scopes, `openid`, `fhirUser` |
| Interactive B2B app (a user at the requesting organization) | `['authorization_code']` (plus `refresh_token`) | `user/` scopes, `openid`, `fhirUser` |
| Automated B2B app (no user) | `['client_credentials']` | `system/` scopes; use [B2B Client Credentials]({% link udap/b2b-client-credentials.md %}) instead |

General §7.5.5 expects apps that also use SMART scopes to request "SMART
user-level or patient-specific scopes when using the `"authorization_code"`
grant type". The B2B `hl7-b2b` extension belongs to client credentials. STU2
b2b §5.2.1 says to "omit [it] for client apps using the `authorization_code`
flow".

## Prerequisites

- **A registered `client_id`** whose registration includes
  `authorization_code` in `grant_types` and the `redirect_uris` you will use.
  See [Dynamic Client Registration]({% link udap/dynamic-client-registration/index.md %}).
- **A configured `redirect_uri`** that is one of the registered redirection
  URIs. `ClientConfig` requires HTTPS without a fragment. HTTP is allowed only
  for loopback hosts with `allow_insecure_localhost: true`.
- **Scopes**, configured or passed per call.
- **Server trust inputs** for discovery: `trusted_anchors:` plus `crls:` or a
  `revocation_checker:`, and `community:` when the server serves several trust
  communities.

## Configuration

```ruby
client = Safire::Client.new(
  {
    base_url:          'https://fhir.example.com',
    client_id:         stored_client_id,
    redirect_uri:      'https://app.example.com/callback',
    scopes:            ['openid', 'fhirUser', 'patient/Patient.rs', 'patient/Observation.rs'],
    private_key:       File.read('client-key.pem'),
    certificate_chain: [File.read('client-cert.pem'), File.read('issuing-ca.pem')]
  },
  protocol: :udap
)
```

A configured `authorization_endpoint` or `token_endpoint` is ignored for UDAP.
Safire uses the endpoints from validated `signed_metadata`.

## Step 1: authorization request

```ruby
auth = client.authorization_url(trusted_anchors: [udap_ca], crls: [udap_crl])

session[:udap_state]         = auth[:state]
session[:udap_code_verifier] = auth[:code_verifier]

redirect_to auth[:auth_url]
```

Keyword arguments:

| Keyword | Purpose |
|---------|---------|
| `scopes:` | Array of scope strings or a space-delimited String. Falls back to configured `scopes` when it yields no scope |
| `idp:` | Optional base URL of a preferred OpenID Connect IdP. Requests [Tiered OAuth](#tiered-oauth) |
| `community:` | Optional trust-community URI for discovery |
| `trusted_anchors:`, `crls:`, `revocation_checker:`, `verify_chain:` | Server trust policy for `signed_metadata`, as in discovery and registration |

The return value has the same shape as SMART:
`{ auth_url:, state:, code_verifier: }`.

What Safire builds (General §7.2: requests "**SHALL** include the following
parameters"): a GET URL on the authoritative signed `authorization_endpoint`
with exactly:

| Parameter | Value |
|-----------|-------|
| `response_type` | `code` |
| `client_id` | configured `client_id` |
| `redirect_uri` | configured `redirect_uri` |
| `scope` | space-delimited requested scopes |
| `state` | 32 random bytes, URL-safe Base64, new on every call |
| `code_challenge` | `BASE64URL(SHA256(code_verifier))` |
| `code_challenge_method` | `S256` |

Notes:

- STU2 marks `redirect_uri` conditional ("**REQUIRED** when the client
  application registered more than one redirection URI"). Safire always sends
  the configured value, so the token request can send the identical value.
- If the signed `authorization_endpoint` already has a query component, Safire
  keeps it and appends the parameters.
- Safire does not add SMART's `aud` or `launch` parameters. They are not in the
  STU2 §7.2 table. To request SMART launch context, include scopes such as
  `launch/patient` (General §7.5.6).
- Safire builds GET URLs only. STU2 does not define POST-based authorization
  requests, so there is no `method: :post` option as there is for SMART.

### Scopes

STU2 marks `scope` **required** in the authorization request. Safire has no
default scope: if neither `scopes:` nor the configured `scopes` yields a scope,
it raises `ConfigurationError` before discovery.

[General §7.3](https://hl7.org/fhir/us/udap-security/STU2/general.html#scope-negotiation)
says a client "**MAY** request a wildcard scope only if wildcards are specified
in the server's `scopes_supported` metadata list". Its constraints "apply for
both registration requests and access token requests". Authorization requests
are not named. In `authorization_url`, Safire therefore logs a warning for a
wildcard that is not listed exactly in `scopes_supported`, and still builds the
URL. The authorization server decides. Warnings contain a count, not scope
values. Registration and client credentials token requests keep the hard
`ValidationError`.

### Tiered OAuth

To ask the data holder to authenticate the user at a preferred OpenID Connect
IdP ([STU2 §6](https://hl7.org/fhir/us/udap-security/STU2/user.html)), pass
`idp:`. Safire adds the `udap` scope and the `idp` query parameter, and
requires the server to advertise `udap_to` and the `udap` scope. Register
with `udap` in `scope` first, and be ready for an `invalid_idp` error on the
callback. See [Tiered OAuth]({% link udap/tiered-oauth.md %}).

## Step 2: callback and `state`

Safire does not receive the callback. Your application must check `state`
before it exchanges the code. General §7.2.1:

> The client application **SHALL NOT** proceed if the `state` parameter is not
> included in the authorization response or its value does not match the value
> provided by the client application in the corresponding authorization request.

```ruby
expected = session.delete(:udap_state)
unless expected && params[:state].is_a?(String) &&
       OpenSSL.secure_compare(params[:state], expected)
  halt 401, 'state mismatch'
end
halt 400, params[:error] if params[:error]
```

Use each `state` once and keep it bound to the user's session. If the response
has an `error` parameter (RFC 6749 §4.1.2.1), handle it without exchanging a
code.

## Step 3: exchange the code

```ruby
token_data = client.request_access_token(
  code:            params[:code],
  code_verifier:   session.delete(:udap_code_verifier),
  trusted_anchors: [udap_ca],
  crls:            [udap_crl]
)

token_data['access_token']
token_data['refresh_token'] # present only if the server issued one
```

Keyword arguments:

| Keyword | Purpose |
|---------|---------|
| `code:` | **Required.** Authorization code from the callback (non-blank String) |
| `code_verifier:` | **Required.** The `:code_verifier` from step 1 (RFC 7636: 43–128 unreserved characters) |
| `extensions:` | Optional Hash of Authorization Extension Objects. Must not contain `hl7-b2b`. Omitted by default |
| `community:`, `trusted_anchors:`, `crls:`, `revocation_checker:`, `verify_chain:` | Discovery and server trust policy; use the same values as step 1 |
| `private_key:`, `certificate_chain:`, `jwt_algorithm:` | Per-call overrides of the configured signing identity |

What Safire sends
([consumer §4.2.2](https://hl7.org/fhir/us/udap-security/STU2/consumer.html#submitting-a-token-request),
[b2b §5.2.2.1](https://hl7.org/fhir/us/udap-security/STU2/b2b.html#authorization-code-grant)):
a form-encoded POST to the authoritative signed `token_endpoint` with exactly
`grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`,
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
`client_assertion`, and `udap=1`.

- `redirect_uri` is the configured value. STU2: it "**SHALL** be present only
  if the `redirect_uri` parameter was included in the authorization request
  ... and their values **SHALL** be identical". Step 1 always sends it, so
  step 3 always sends the same value. Do not change the configured
  `redirect_uri` between the two steps.
- `code_verifier`: clients "**SHALL** include a `code_verifier` parameter and
  value in the token request as per Section 4.5 of RFC 7636".
- No `Authorization` header, `client_id`, or `client_secret`. Clients
  "**SHALL NOT** include an HTTP Authorization header or client secret".

The `client_assertion` is an Authentication Token with `alg` and `x5c`
headers and claims `iss` and `sub` (the `client_id`), `aud` (the signed token
endpoint, unchanged), `iat`, `exp` (300 seconds later), and a fresh `jti`. It
has no `extensions` claim unless you pass `extensions:`. STU2 b2b §5.2.1 says
the B2B Authorization Extension Object is "required for B2B client apps using
the `client_credentials` flow; omit for client apps using the
`authorization_code` flow". Safire therefore rejects `hl7-b2b` here with
`ValidationError`.

Token readiness for this grant matches
[B2B Client Credentials]({% link udap/b2b-client-credentials.md %}#discovery-readiness)
(`udap_authn`, `authorization_code` in `grant_types_supported`, usable signed
`token_endpoint`, `private_key_jwt`, signing algorithms), with one difference.
If `udap_authorization_extensions_required` lists extensions that the request
does not send, Safire logs a warning with a count and proceeds. Discovery §2.2
calls them "required ... in every token request", but b2b §5.2.1 says to omit
`hl7-b2b` for this flow. Safire does not fail on this conflict. The server
decides.

The response is returned as sent once it is a JSON object with a non-blank
`access_token`. It may include `refresh_token`, `id_token`, `scope`, and SMART
context such as `patient`. The server "**MAY** grant all scopes requested ...
or a subset thereof" (§7.3), so read `scope`.

## Step 4: refresh the access token

```ruby
refreshed = client.refresh_token(
  refresh_token:   stored_refresh_token,
  trusted_anchors: [udap_ca],
  crls:            [udap_crl]
)

stored_refresh_token = refreshed['refresh_token'] || stored_refresh_token
```

STU2 lets servers issue refresh tokens to consumer-facing apps
([§4.3](https://hl7.org/fhir/us/udap-security/STU2/consumer.html#refresh-tokens))
and to B2B apps that use the authorization code grant
([§5.3](https://hl7.org/fhir/us/udap-security/STU2/b2b.html#refresh-tokens)).
"Refresh tokens are not used with the client credentials grant type." Clients
"authenticate to the Authorization Server for refresh requests by constructing
and including an Authentication Token in the same manner as for initial token
requests".

Safire POSTs `grant_type=refresh_token`, `refresh_token`, optional `scope`,
`client_assertion_type`, `client_assertion`, and `udap=1` to the signed
`token_endpoint`. It sends no `Authorization` header, `client_id`, or client
secret. The Authentication Token is built as in step 3, with no `extensions`
claim by default and `hl7-b2b` rejected. Keywords match step 3, except that
`refresh_token:` replaces `code:` and `code_verifier:`, and `scopes:` is
optional.

- **Scope.** `scope` is sent only when `scopes:` yields a scope. Configured
  scopes are **not** used. RFC 6749 §6 treats an omitted scope as the scope
  originally granted, and a requested scope must not exceed it. If you send
  scopes, the token-request rule in §7.3 applies: an unadvertised wildcard
  raises `ValidationError` before anything is signed, and unusable
  `scopes_supported` raises `DiscoveryError` when a wildcard is sent. This is
  stricter than step 1, which only warns.
- **Grant advertisement.** If `grant_types_supported` does not list
  `refresh_token`, Safire logs a warning and still sends the request. The
  server issued the refresh token, so it decides whether to accept it. Other
  readiness checks raise as in step 3. If `udap_authorization_extensions_required`
  lists extensions, Safire warns as in step 3.
- **Rotation.** If the response contains a new `refresh_token`, store it in
  place of the old one.

## Discovery readiness

Before it builds the URL, Safire validates `signed_metadata` and then checks:

| Condition | Result | Basis |
|-----------|--------|-------|
| `grant_types_supported` does not include `authorization_code` (including empty or non-array) | `DiscoveryError` | Discovery §2.2: clients "**SHALL** interpret an empty array value to mean that the corresponding capability is NOT supported" |
| `authorization_endpoint` missing | `DiscoveryError` | Discovery §2.2: it "**SHALL** be present if ... `grant_types_supported` ... includes ... `"authorization_code"`" |
| `authorization_endpoint` not absolute HTTPS, no host, or has a fragment | `DiscoveryError` | Safire choice, as for SMART endpoints. HTTP loopback only with `allow_insecure_localhost` |
| Requested wildcard not listed exactly, or `scopes_supported` unusable | Warning | Safire choice. §7.3 does not name authorization requests |

Token-endpoint readiness (`udap_authn`, `private_key_jwt`, signing algorithms)
is checked when the code is exchanged, not here.

## Error handling

```ruby
begin
  token_data = client.request_access_token(code:, code_verifier:, trusted_anchors: [udap_ca], crls: [udap_crl])
rescue Safire::Errors::ConfigurationError => e
  # missing client_id, redirect_uri, private_key, certificate_chain; incompatible algorithm
rescue Safire::Errors::ValidationError => e
  # blank code, invalid code_verifier, invalid or hl7-b2b extensions
rescue Safire::Errors::DiscoveryError => e
  # untrusted or unusable discovery metadata
rescue Safire::Errors::CertificateError => e
  # client certificate chain cannot support signing
rescue Safire::Errors::TokenError => e
  # server rejection (e.error_code such as 'invalid_grant', 'invalid_client')
  # or a success body without a non-blank access_token
rescue Safire::Errors::NetworkError => e
  # connection, TLS, timeout, or blocked redirect
end
```

Error messages name the attribute, never the code, verifier, or token value.
Safire never retries a token request. An authorization code is single-use, so
start a new authorization request after a failed exchange.

## Limitations

- Safire does not parse the callback or compare `state` for you.
- Tiered OAuth covers the client-app request only; see
  [Tiered OAuth]({% link udap/tiered-oauth.md %}#limitations).
- Tests use WebMock. They do not exercise a real UDAP authorization server, a
  consent UI, or trust-community certificate policies.
