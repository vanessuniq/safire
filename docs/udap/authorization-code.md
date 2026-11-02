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
`Safire::Client#authorization_url`.

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

## Step 2: callback and `state`

Safire does not receive the callback. Your application must check `state`
before it exchanges the code. General §7.2.1:

> The client application **SHALL NOT** proceed if the `state` parameter is not
> included in the authorization response or its value does not match the value
> provided by the client application in the corresponding authorization request.

```ruby
expected = session.delete(:udap_state)
unless expected && params[:state].is_a?(String) &&
       Rack::Utils.secure_compare(params[:state], expected)
  halt 401, 'state mismatch'
end
halt 400, params[:error] if params[:error]
```

Use each `state` once and keep it bound to the user's session. If the response
has an `error` parameter (RFC 6749 §4.1.2.1), handle it without exchanging a
code.

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

## Limitations

- Safire does not parse the callback or compare `state` for you.
- Tiered OAuth (`idp` parameter, `udap` scope) is not implemented.
- Tests use WebMock. They do not exercise a real UDAP authorization server, a
  consent UI, or trust-community certificate policies.
