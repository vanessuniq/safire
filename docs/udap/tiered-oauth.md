---
layout: default
title: Tiered OAuth
parent: UDAP
nav_order: 4
permalink: /udap/tiered-oauth/
description: "Ask a UDAP data holder to authenticate the user at a preferred OpenID Connect IdP (UDAP Tiered OAuth, client-app side)."
---

# Tiered OAuth

{: .no_toc }

UDAP Security STU2
[§6 Tiered OAuth for User Authentication](https://hl7.org/fhir/us/udap-security/STU2/user.html)
lets a client app name a preferred OpenID Connect identity provider (IdP) in
its authorization request. If the data holder supports Tiered OAuth and trusts
that IdP, the data holder asks the IdP to authenticate the user. "Note that the
client application does not interact directly with the IdP as part of this
workflow."

Safire implements the client-app side: the `idp:` keyword on
`Safire::Client#authorization_url` for a `protocol: :udap` client. Everything
else in the [authorization code flow]({% link udap/authorization-code.md %})
is unchanged.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Scope

| Part of STU2 §6 | Who does it | In Safire |
|-----------------|-------------|-----------|
| [Client authorization request to data holder](https://hl7.org/fhir/us/udap-security/STU2/user.html#client-authorization-request-to-data-holder) (`udap` scope, `idp` parameter) | Client app | Yes: `authorization_url(idp:)` |
| Handling an `invalid_idp` error on the redirect URI | Client app | Your application (guidance below) |
| [Data holder authentication request to IdP](https://hl7.org/fhir/us/udap-security/STU2/user.html#data-holder-authentication-request-to-idp) (IdP discovery, registration, OIDC request, ID token validation) | Data holder | No. Out of scope for a client library |
| [Data holder interaction with user after authentication](https://hl7.org/fhir/us/udap-security/STU2/user.html#data-holder-interaction-with-user-after-authentication) | Data holder | No |

## Prerequisites

- Everything listed for the [authorization code flow]({% link udap/authorization-code.md %}#prerequisites).
- **Register with the `udap` scope.** STU2 §6.1: "client apps that intend to
  use the Tiered OAuth workflow **SHALL** include `udap` in the list of scopes
  requested in the `scope` parameter of their registration request." Safire
  cannot know at registration time whether you will use Tiered OAuth, so it
  does not add `udap` to registration metadata. Add it yourself:

  ```ruby
  client.register_client(
    { client_name: 'My App', grant_types: ['authorization_code'],
      contacts: ['mailto:security@app.example.com'],
      redirect_uris: ['https://app.example.com/callback'],
      logo_uri: 'https://app.example.com/logo.png',
      scope: 'openid fhirUser patient/Patient.rs udap' },
    client_uri: 'https://app.example.com', trusted_anchors: [udap_ca], crls: [udap_crl]
  )
  ```

- **The IdP base URL.** STU2 §6.1: "The IdP's base URL is the URL listed in
  the `iss` claim of ID tokens issued by the IdP", per OpenID Connect Core 1.0
  §2.

## Authorization request

```ruby
auth = client.authorization_url(
  idp:             'https://idp.example.com/oidc',
  trusted_anchors: [udap_ca],
  crls:            [udap_crl]
)

session[:udap_state]         = auth[:state]
session[:udap_code_verifier] = auth[:code_verifier]

redirect_to auth[:auth_url]
```

STU2 §6.1 says the client app modifies the normal authorization request "as
follows":

> 1. Add `udap` to the list of scopes provided in the value of the `scope`
>    query parameter, and
> 1. Add the extension query parameter `idp` with a value equal to the base
>    URL of the preferred OIDC IdP.

With `idp:`, Safire:

- appends `udap` to the requested scopes (configured or `scopes:`) unless it is
  already there. It never duplicates `udap` and keeps the order of the other
  scopes. STU2: "The meaning of the extension parameter `idp` is undefined if
  `udap` is absent from the list of requested scopes", so Safire always adds it.
- adds `idp=<IdP base URL>` to the query. The value is sent exactly as given.
- keeps every other parameter as in the
  [standard request]({% link udap/authorization-code.md %}#step-1-authorization-request),
  including a fresh `state` and S256 PKCE.

Without `idp:` (or with `idp: nil`), the request is unchanged: no `udap` scope
is added and Tiered OAuth readiness is not checked.

### `idp` validation

Before discovery, Safire checks `idp` and raises `ValidationError` with
`attribute == :idp` when it is:

| Value | `reason` |
|-------|----------|
| not a String (including `URI` objects) | `must be a String` |
| blank, relative, or without a host | `must be an absolute URL` |
| not HTTPS (HTTP is allowed only for `localhost`/`127.0.0.1` with `allow_insecure_localhost: true`) | `must use HTTPS` |
| has a fragment | `must not include a fragment` |

This is a Safire choice: the IdP base URL is the IdP's OIDC issuer (`iss`),
and OpenID Connect Core 1.0 §2 requires issuer identifiers to use `https`
(that text was not fetched while writing this page). Error messages never
include the value.

## Discovery readiness

In addition to the
[standard checks]({% link udap/authorization-code.md %}#discovery-readiness),
a request with `idp:` requires:

| Condition | Result | Basis |
|-----------|--------|-------|
| `udap_profiles_supported` does not include `udap_to` (including empty or non-array) | `DiscoveryError` | Discovery §2.2: if the server supports the workflow, the array "**SHALL** also include ... `"udap_to"`" |
| `scopes_supported` does not include `"udap"` (including empty or non-array) | `DiscoveryError` | STU2 §6.1: "A data holder that supports UDAP Tiered OAuth **SHALL** include `"udap"` in the array of scopes returned for the `scopes_supported` parameter" |

Failing hard is a Safire choice. STU2 says client apps "**MAY** use this
workflow with data holders that support it, as indicated in the data holder's
UDAP metadata", so Safire does not send a Tiered OAuth request to a server
whose metadata does not advertise it. A warning that still sends the request
was considered and not chosen. To fall back, rescue `DiscoveryError` and call
`authorization_url` without `idp:`, or check
`client.server_metadata(...).supports_tiered_oauth?` first.

## Callback: `invalid_idp`

The data holder may reject the requested IdP. STU2 §6.2: "If the IdP is not
trusted by the data holder, or if the data holder does not have and cannot
obtain a client_id to use with the IdP, the data holder **MAY** reject the
client app's authorization request by returning an error as per Section
4.1.2.1 of RFC 6749, using the extension error code of `invalid_idp`." The
error arrives on your redirect URI, which Safire does not see:

```text
https://app.example.com/callback?error=invalid_idp&error_description=...&state=...
```

Check `state` first, as for any callback. Then:

> A client app that receives an error code of `invalid_idp` **MAY** attempt to
> obtain authorization again by specifying a different IdP base URL in the
> `idp` authorization request parameter, or by making a new authorization
> request without using the Tiered OAuth workflow.

```ruby
expected = session.delete(:udap_state)
halt 401, 'state mismatch' unless expected && params[:state].is_a?(String) &&
                                  OpenSSL.secure_compare(params[:state], expected)

if params[:error] == 'invalid_idp'
  # Choose another IdP, or omit idp: to use the data holder's own login.
  auth = client.authorization_url(trusted_anchors: [udap_ca], crls: [udap_crl])
  session[:udap_state]         = auth[:state]
  session[:udap_code_verifier] = auth[:code_verifier]
  redirect_to auth[:auth_url]
elsif params[:error]
  halt 400, params[:error]
end
```

Each retry is a new authorization request with a new `state` and
`code_verifier`. The data holder may also choose another IdP or its own login
instead of returning `invalid_idp`, and may return `access_denied` if it cannot
match the authenticated user (STU2 §6.3).

## Token exchange

A successful callback is handled exactly as in the
[authorization code flow]({% link udap/authorization-code.md %}#step-3-exchange-the-code).
The token request does not carry `idp`. The response may include an
`id_token` from the data holder; Safire returns it unchanged and does not
validate it.

## Limitations

- Safire does not parse the callback, compare `state`, or choose an IdP.
- Safire does not discover, register with, or validate ID tokens from the IdP.
  Those are data-holder steps (STU2 §6.2–§6.3).
- The registration `udap` scope is not added for you (see Prerequisites).
- Tests use WebMock. They do not exercise a real data holder or IdP.
