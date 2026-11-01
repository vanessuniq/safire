# Safire Demo Application

A Sinatra-based web application that demonstrates the Safire gem for SMART authorization, UDAP discovery, UDAP Dynamic Client Registration, UDAP B2B client credentials tokens, and the UDAP authorization code flow.

## Features

- **SMART Dynamic Client Registration**: Register this application with a SMART server at runtime using RFC 7591 to obtain a `client_id` automatically
- **Server Management**: Add, edit, and remove FHIR server configurations with protocol-aware SMART and UDAP sections
- **SMART Discovery**: View server capabilities from `/.well-known/smart-configuration` including supported scopes, capabilities, and endpoints
- **UDAP Discovery**: Fetch `/.well-known/udap`, validate `signed_metadata`, inspect STU2 fields, and run community-scoped discovery
- **UDAP Dynamic Client Registration**: Register and cancel a certificate-backed UDAP client, store the returned UDAP client identifier separately from SMART credentials, and inspect filtered registration responses
- **UDAP B2B Token Request**: Request a UDAP STU2 B2B `client_credentials` access token with an `hl7-b2b` authorization extension, using the stored UDAP client ID, and inspect a masked token response
- **UDAP Authorization Code**: Run the UDAP STU2 `authorization_code` flow with PKCE through the demo callback, optionally with a Tiered OAuth preferred IdP, exchange the code with a signed Authentication Token, refresh the token, and inspect masked token responses
- **Authorization Flows**: Test multiple launch types:
  - Provider Standalone Launch
  - Patient Standalone Launch
  - EHR Launch (requires EHR/portal to initiate)
  - Patient Portal Launch
- **Authentication Types**:
  - Public Client (PKCE only)
  - Confidential Symmetric (client_secret with Basic Auth)
  - Confidential Asymmetric (private_key_jwt with JWT assertion)
- **Token Management**: View obtained tokens and test token refresh functionality
- **Backend Services**: Request system-to-system access tokens via the `client_credentials` grant (no user interaction) when the server advertises support
- **Session Reset**: Clear all OAuth and token session data via the "Reset Session" button in the navigation bar
- **JWKS Endpoint**: Serves the app's public key at `/.well-known/jwks.json` for asymmetric auth and backend services

## Quick Start

From the project root:

```bash
bin/demo
```

`bin/demo` installs the demo bundle, creates `examples/sinatra_app/.env` when
needed, and fills missing local-only secrets, SMART asymmetric demo credentials,
UDAP client signing credentials, and grant-specific sample self-signed
certification JWTs. The sample certifications are never submitted unless they
are explicitly selected in the registration form.
Existing nonblank `.env` values are preserved.

Or from this directory:

```bash
bundle install
bundle exec ruby bin/setup_env.rb
# Edit .env if you need production-style trust material or external credentials
bundle exec puma config.ru -p 4567
```

Then visit http://localhost:4567

When the demo runs on local HTTP loopback, it opts Safire clients into
`allow_insecure_localhost: true` only for localhost/127.0.0.1 URLs. This keeps
the local SMART callback and local test servers usable while preserving
Safire's HTTPS-only default for remote hosts.

## Configuration

### Environment Variables

`bin/demo` and `bundle exec ruby bin/setup_env.rb` both prepare `.env`
idempotently. They fill the local demo defaults below when values are absent,
but they do not generate production UDAP trust anchors or CRLs.

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 4567) |
| `SESSION_SECRET` | No | Session encryption key (generated for local demo use when absent) |
| `ASYMMETRIC_PRIVATE_KEY_PEM` | No | Private key in PEM format for asymmetric auth (generated for local demo use when absent) |
| `ASYMMETRIC_KID` | No | Key ID matching your registered JWKS (generated for local demo use when absent) |
| `UDAP_TRUST_ANCHORS_PEM` | No | PEM-encoded UDAP server signing certificate trust anchors |
| `UDAP_CRLS_PEM` | No | PEM-encoded CRLs for UDAP server signing certificate revocation checks |
| `UDAP_VERIFY_CHAIN` | No | Optional override for UDAP signed metadata chain validation (`1/true/yes/on` or `0/false/no/off`; unknown values raise a configuration error) |
| `UDAP_CLIENT_PRIVATE_KEY_PEM` | No | PEM-encoded client private key for UDAP software-statement signing (generated for local demo use when absent) |
| `UDAP_CLIENT_CERTIFICATE_CHAIN_PEM` | No | Leaf-first PEM certificate chain for UDAP software-statement signing (generated for local demo use when absent) |
| `UDAP_REGISTRATION_SIGNING_ALGORITHM` | No | Optional explicit UDAP registration signing algorithm (`RS256`, `RS384`, `ES256`, or `ES384`; defaults to generated `RS256`) |
| `UDAP_CLIENT_NAME` | No | Client name prefilled in the UDAP registration form |
| `UDAP_CLIENT_CONTACTS` | No | Comma, space, or newline-separated contact URIs prefilled in the UDAP registration form |
| `UDAP_CLIENT_LOGO_URI` | No | Logo URI prefilled for authorization-code UDAP registration; generated as the demo logo endpoint when absent |
| `UDAP_CLIENT_CERTIFICATIONS_FILE` | No | File containing compact JWS certification or endorsement JWTs, one per line; matching JWTs are submitted only when explicitly selected, the managed development sample is generated when absent, and custom paths must identify an existing non-empty file |

### Setting Up Asymmetric Authentication

Asymmetric authentication uses JWT assertions signed with a private key. This is more secure than shared secrets.

1. **Generate a key pair** (RSA or EC):
   ```bash
   # RSA (recommended)
   openssl genrsa -out private_key.pem 2048

   # EC P-384
   openssl ecparam -name secp384r1 -genkey -noout -out private_key.pem
   ```

2. **Configure environment variables**:
   ```bash
   # In .env file
   ASYMMETRIC_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----
   ...your key content...
   -----END PRIVATE KEY-----"

   ASYMMETRIC_KID=my-app-key-001
   ```

3. **Register with the authorization server**:
   - Provide your JWKS URL: `http://localhost:4567/.well-known/jwks.json`
   - Or extract and upload your public key:
     ```bash
     openssl rsa -in private_key.pem -pubout -out public_key.pem
     ```

4. **Test**: The "Confidential Asymmetric" option will appear in the authorization form when the server supports it.

### Setting Up UDAP signed_metadata Validation

The UDAP Discovery screen always verifies the `signed_metadata` JWT signature and claims. When
complete trust material is unavailable, or when `UDAP_VERIFY_CHAIN=false` is configured, it sets
`verify_chain: false` and displays a visible warning because X.509 chain and revocation checks are
skipped.

For production-style testing, configure both trust anchors and CRLs:

```bash
UDAP_TRUST_ANCHORS_PEM="-----BEGIN CERTIFICATE-----
...trusted anchor certificate...
-----END CERTIFICATE-----"

UDAP_CRLS_PEM="-----BEGIN X509 CRL-----
...certificate revocation list...
-----END X509 CRL-----"
```

When both values are present, the demo enables chain and revocation validation by default. Set `UDAP_VERIFY_CHAIN=false` only for local development or test scenarios. Unknown `UDAP_VERIFY_CHAIN` values raise a configuration error instead of silently disabling validation.

### Setting Up UDAP Client Signing Credentials

UDAP Dynamic Client Registration uses a client signing identity in the
`software_statement` JWT. This is the opposite trust direction from
`UDAP_TRUST_ANCHORS_PEM`: trust anchors validate the **server** metadata JWT,
while the client private key and certificate chain identify **this demo app**
to a UDAP registration endpoint.

`bin/demo` generates local signing credentials suitable for development at
`http://localhost:4567`. Configure your own signing credentials when testing
with externally issued certificates or a different client URI:

For interoperability testing against UDAP test tools or public/community
servers, prefer an issued UDAP test certificate over the generated self-signed
demo certificate. UDAP.org's Testing Resources section links to UDAP Developer
account registration for obtaining test certificates and Test Tool access:
https://www.udap.org/

```bash
UDAP_CLIENT_NAME="Safire Demo App"
UDAP_CLIENT_CONTACTS="mailto:admin@example.com"
UDAP_CLIENT_LOGO_URI="http://localhost:4567/safire-demo-logo.png"
UDAP_CLIENT_CERTIFICATIONS_FILE="data/udap_self_signed_certification.jwt"

UDAP_CLIENT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----
...client private key...
-----END PRIVATE KEY-----"

UDAP_CLIENT_CERTIFICATE_CHAIN_PEM="-----BEGIN CERTIFICATE-----
...leaf certificate whose URI SAN matches the client URI...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
...optional issuing certificate...
-----END CERTIFICATE-----"

UDAP_REGISTRATION_SIGNING_ALGORITHM="RS256"
```

Leave `UDAP_REGISTRATION_SIGNING_ALGORITHM` blank to let Safire select a
compatible algorithm from UDAP discovery and the configured key type. The leaf
certificate must contain a URI SAN that exactly matches the `client_uri` value
submitted by the registration form. For local testing, run the demo at
`http://localhost:4567` or edit the form's client URI to match your certificate.

Generated UDAP demo credentials and the sample self-signed certification JWTs
expire after one year. `bin/demo` intentionally preserves non-empty `.env`
values and caller-managed certification files so it does not overwrite issued
test credentials. To refresh only the generated local demo identity, blank both
`UDAP_CLIENT_PRIVATE_KEY_PEM` and `UDAP_CLIENT_CERTIFICATE_CHAIN_PEM` together,
blank `UDAP_REGISTRATION_SIGNING_ALGORITHM` unless it is still compatible with
the regenerated key, leave `UDAP_CLIENT_CERTIFICATIONS_FILE` blank or set to the
managed default, and rerun `bin/demo`.

The setup script generates certification JWTs only at its managed default
path, `data/udap_self_signed_certification.jwt`. A custom
`UDAP_CLIENT_CERTIFICATIONS_FILE` must already identify a non-empty file; the
script never creates or replaces caller-managed certification files. The
managed file contains separate STU2-shaped self-declarations for the
`client_credentials` and `authorization_code` demo flows. Selecting the
configured file in the registration form submits only the JWT matching the
chosen flow. The sample uses the example certification URI and is not evidence
that a server or trust community recognizes its framework or issuer. The setup
script validates managed samples and regenerates legacy, expired, malformed, or
signing-key-mismatched files. It never performs that replacement for a custom
path.

### Adding a FHIR Server

The home page offers protocol-specific SMART and UDAP dynamic registration,
plus manual server setup.

**SMART Dynamic Registration (RFC 7591)** creates the server entry as part of
registration when the SMART server advertises a `registration_endpoint`:

1. Click "Register with a Server" on the home page
2. Enter the server name and base URL
3. Choose grant types, authentication method, and optional scope
4. Click "Register Client" — the app POSTs your metadata to the server, receives a `client_id`, and saves the server entry automatically

**UDAP Dynamic Registration (STU2)** starts from an existing UDAP-enabled server
entry because discovery, protocol selection, and optional community context
belong to that server:

1. Add a UDAP server manually if it is not already configured
2. Use the home-page UDAP action or open the server detail page
3. Review the prepopulated client metadata and choose a grant profile
4. Register the certificate-backed software statement; the returned
   `udap_client_id`, exact client URI, and community are stored on that server

Once a UDAP client ID is stored, registration actions become lifecycle
management actions. The demo prevents duplicate registration and offers
cancellation when the stored registration also has the client URI context
needed to reproduce its issuer identity.

**Add Server Manually** — for SMART credentials, UDAP discovery, or both:

1. Click "Add Server" on the home page
2. Enter the server details:
   - **Name**: Display name for the server
   - **Base URL**: FHIR server base URL
   - **Protocols**: SMART App Launch, UDAP Security, or both
   - **Client ID**: OAuth client ID registered with the server for SMART workflows
   - **UDAP Client ID**: (Optional) Client ID assigned by a UDAP registration endpoint
     when the demo client was registered outside this app
   - **UDAP Client URI**: Exact client URI used as the registration software
     statement issuer; required with a UDAP Client ID
   - **UDAP Community URI**: (Optional) Community used for the original UDAP
     registration
   - **Client Secret**: (Optional) For confidential symmetric clients only
   - **Scopes**: Space or comma-separated list of OAuth scopes

## Demo Workflows

### Testing with SMART Health IT Sandbox

The app works with the SMART Health IT sandbox server for testing.

#### Standalone Launch

1. Select a server from the server list
2. Click "Start Authorization"
3. Choose your settings:
   - **Launch Type**: Provider Standalone or Patient Standalone
   - **Client Type**: Public, Confidential Symmetric, or Confidential Asymmetric
4. Click "Start Authorization"
5. In the SMART sandbox, select a patient and practitioner
6. View the obtained tokens

#### EHR Launch

To test EHR launch with the SMART sandbox:

1. Go to https://launch.smarthealthit.org/
2. Select "EHR Launch" mode
3. Enter `http://localhost:4567/launch` as the App Launch URL
4. Configure other options as needed
5. Click "Launch"
6. The demo app will handle the authorization flow automatically

**Optional:** Specify client type by appending `client_type` parameter:
- `http://localhost:4567/launch?client_type=public` - Public client (default)
- `http://localhost:4567/launch?client_type=confidential_symmetric` - Confidential client with Basic Auth
- `http://localhost:4567/launch?client_type=confidential_asymmetric` - Confidential client with JWT assertion

### Backend Services Token Request

If a SMART server advertises `client_credentials` grant support, the "Backend Services" card appears in the SMART section of the server detail page:

1. Navigate to a server detail page
2. Click "Request Backend Token"
3. Review or edit the configured `system/` scopes prefilled from the server configuration
4. Click "Request Token"
5. View the access token, expiry, granted scopes, and SMART compliance check result

Requires `ASYMMETRIC_PRIVATE_KEY_PEM` and `ASYMMETRIC_KID` to be configured (same key pair used for confidential asymmetric App Launch).
The demo rejects an empty scope submission and preserves the requested scopes
when requesting another token, so it never relies on Safire's deprecated
implicit Backend Services fallback. It also rejects non-system scopes because
the demo does not establish the out-of-band user or patient context that SMART
permits advanced Backend Services integrations to coordinate.

### UDAP Discovery

Navigate to a UDAP-enabled server detail page and use the UDAP Security section to fetch `/.well-known/udap`.

The page displays:

- Structural `valid?` status and signed metadata validation status
- Every UDAP Security STU2 metadata field Safire exposes
- Profile-only helpers such as `dynamic_registration_profile?`
- Capability helpers such as `supports_dynamic_registration?`
- An optional `community` query parameter for community-scoped discovery

### UDAP Dynamic Client Registration

Navigate to an unregistered UDAP-enabled server detail page and open
**UDAP Registration**, or use the home page's Dynamic Registration section to
choose an unregistered UDAP server. The demo prepopulates client-owned fields
from the running app and `.env`, signs a UDAP `software_statement` with
`UDAP_CLIENT_PRIVATE_KEY_PEM` and `UDAP_CLIENT_CERTIFICATE_CHAIN_PEM`, and uses
`UdapTrustPolicy` for community-scoped server discovery.

The registration screen supports:

- `client_credentials` registration for system access
- `authorization_code` registration with the demo callback URI, logo URI, and
  Safire-generated `response_types: ["code"]`
- editable scopes prepopulated from the selected server; when none are
  configured, the operator must enter the access this demo client intends to
  request before registration
- optional `community`, pasted certification or endorsement JWTs, and explicit
  selection of grant-matched JWTs from the configured file
- persistence of the returned `client_id`, effective registration scope, exact
  client URI, and optional community so cancellation uses the original
  registration context
- cancellation only when the server confirms the same returned `client_id`

The page displays only allowlisted registration metadata fields. Unknown fields
and structurally unexpected values are replaced with `[FILTERED]`; software
statements, access tokens, private keys, certificate chains, assertions, and
other credential or signing material are never rendered.

If server metadata advertises `udap_certifications_required`, the registration
request must include matching certification or endorsement JWTs in the
`certifications` array. The metadata value is a required certification URI; it is
not itself the JWT to submit. Point `UDAP_CLIENT_CERTIFICATIONS_FILE` at a local
ignored file and explicitly select it, or paste JWTs into the form for one-off
testing. For cancellation, paste any certifications required by the server into
the cancellation form; certification JWTs are intentionally not persisted with
the server record.

### UDAP B2B Token Request

Navigate to a UDAP-enabled server detail page and open **Request B2B Token**
in the UDAP Security section. The page calls
`Safire::Client#request_backend_token` on a `protocol: :udap` client (UDAP
Security STU2 B2B client credentials flow) and signs the Authentication Token
with the same `UDAP_CLIENT_PRIVATE_KEY_PEM` and
`UDAP_CLIENT_CERTIFICATE_CHAIN_PEM` used for registration.
`UDAP_REGISTRATION_SIGNING_ALGORITHM`, when set, also applies to the token
request. Server trust uses the same `UdapTrustPolicy` as discovery and
registration.

The form provides:

- the UDAP client ID, prefilled from the server's stored UDAP registration
  (register a `client_credentials` client first, or enter a client ID issued
  elsewhere)
- scopes, prefilled from the stored registration scope or the server scopes
- the community URI, prefilled from the stored registration
- `hl7-b2b` members: `organization_id` and `purpose_of_use` (required), and
  optional `organization_name`, `subject_name`, `subject_id`, `subject_role`,
  `consent_policy`, and `consent_reference`. Blank optional fields are omitted;
  list fields accept values separated by spaces, commas, or new lines. Safire
  adds `version: "1"` and validates the members

The result shows the token type, expiry, and granted scopes. The access token
is masked (only its first and last four characters and its length are shown),
and every other non-allowlisted response field, such as `refresh_token`, is
replaced with `[FILTERED]`. The demo does not store the token in the session.
Configuration, validation, discovery, certificate, token (including the OAuth
`error` code), and network errors are shown on the same page.

### UDAP Authorization Code

Navigate to a UDAP-enabled server detail page and open **Start Authorization
Code** in the UDAP Security section. The page uses a `protocol: :udap`
`Safire::Client` configured with the stored UDAP client ID, the demo callback
as `redirect_uri`, and the same `UDAP_CLIENT_PRIVATE_KEY_PEM` /
`UDAP_CLIENT_CERTIFICATE_CHAIN_PEM` signing identity used for registration.
Server trust uses the same `UdapTrustPolicy` as the other UDAP pages.

Prerequisites:

- a UDAP client registered with the `authorization_code` grant and the demo
  callback (`http://localhost:4567/callback` when running locally) in its
  `redirect_uris`. The UDAP registration form prefills this callback; it is
  the same callback the SMART flows use
- the server advertises `authorization_code` in `grant_types_supported` and
  signs an `authorization_endpoint`

The flow:

1. **Start.** The form prefills the client ID, scopes, and community from the
   stored registration. Submitting it calls `authorization_url`, stores the
   returned `state` and `code_verifier` in the session, and redirects to the
   signed `authorization_endpoint`
2. **Callback.** `/callback` compares the returned `state` with the stored
   value using a constant-time comparison. If `state` is missing or does not
   match, the response is refused and no token is requested (UDAP STU2
   General §7.2.1: the client "SHALL NOT proceed if the `state` parameter is
   not included in the authorization response or its value does not match").
   The pending `state` and `code_verifier` are removed on every callback, so
   each `state` is used once. If the response carries `error`, the page shows
   the escaped `error` and `error_description` and requests no token.
   Otherwise the demo calls `request_access_token` with the code and stored
   `code_verifier`
3. **Refresh.** When a refresh token was issued, **Refresh Token** calls
   `refresh_token` with it and an optional narrower scope (blank keeps the
   original grant). A rotated refresh token replaces the stored one

The result shows the token type, expiry, and granted scopes. The access token
is masked (first and last four characters plus length), the refresh token is
shown only as issued or not, and `id_token` and other non-allowlisted fields
are replaced with `[FILTERED]`. The demo keeps only the refresh token and its
client context in the session; it does not store the access token, and it does
not log tokens. Configuration, validation, discovery, certificate, token
(including the OAuth `error` code), and network errors are shown on the same
page. **Reset Session** discards a pending authorization and the stored
refresh token.

#### Tiered OAuth (preferred IdP)

The start form has an optional **Preferred IdP (Tiered OAuth)** field. Leave
it blank for a standard request. When it is set, the demo passes it as `idp:`
to `authorization_url`, and Safire adds the `udap` scope and the `idp` query
parameter (UDAP STU2 User §6.1). See the
[Tiered OAuth guide](../../docs/udap/tiered-oauth.md).

Additional prerequisites:

- the client was registered with `udap` in its registration `scope` (STU2
  §6.1: clients that intend to use Tiered OAuth "SHALL include `udap` in the
  list of scopes requested in the `scope` parameter of their registration
  request"). Add `udap` to the scope on the UDAP registration form
- the server advertises `udap_to` in `udap_profiles_supported` and `udap` in
  `scopes_supported`

Errors shown on the start page, with no redirect:

- `ValidationError` (attribute `idp`) when the IdP is not an absolute HTTPS
  URL with a host and no fragment. HTTP is accepted only for
  `localhost`/`127.0.0.1` when the demo runs with a loopback callback
- `DiscoveryError` when the server does not advertise `udap_to` or the `udap`
  scope

If the data holder rejects the IdP, it returns `error=invalid_idp` to the
callback. The demo checks `state` first, exactly as for any callback, then
shows a specific message: per STU2 §6.2 the client "MAY attempt to obtain
authorization again by specifying a different IdP base URL in the `idp`
authorization request parameter, or by making a new authorization request
without using the Tiered OAuth workflow". No token is requested; start a new
authorization from the form. The demo does not retry automatically.

### Token Refresh

After completing an authorization flow, if the server issued a refresh token:

1. Navigate to the server detail page
2. Click "Test Token Refresh"
3. View the refreshed tokens

### Resetting Session

Click the **"Reset Session"** button in the top navigation bar to clear all OAuth and token data from the current session. This is useful when:

- Switching between authentication types or servers
- Recovering from stale session state (e.g., after restarting the app)
- Starting a fresh authorization flow

## File Structure

```
examples/sinatra_app/
├── app.rb              # Main Sinatra application
├── config.ru           # Rack configuration
├── Gemfile             # Demo app dependencies
├── .env.example        # Environment variable template
├── bin/
│   └── setup_env.rb    # Idempotent local environment bootstrap
├── data/
│   └── servers.yml     # Server configurations (YAML storage)
├── models/
│   ├── fhir_server.rb                # Server model with YAML persistence
│   ├── udap_authorization_code_presenter.rb # UDAP authorization code presentation model
│   ├── udap_b2b_token_presenter.rb   # UDAP B2B token presentation model
│   ├── udap_client_credentials.rb    # UDAP demo client signing credential loader
│   ├── udap_discovery_presenter.rb   # UDAP discovery presentation model
│   ├── udap_pem_parsing.rb           # Shared UDAP demo PEM parsing helper
│   ├── udap_registration_presenter.rb # UDAP registration presentation model
│   ├── udap_token_display.rb         # Shared UDAP token masking and error labels
│   └── udap_trust_policy.rb          # UDAP signed_metadata server trust policy
├── public/
│   ├── css/
│   │   └── style.css   # Application styles
│   └── js/
│       └── app.js      # Small progressive UI behaviors
└── views/              # ERB templates
    ├── layout.erb
    ├── index.erb
    ├── servers/
    │   ├── show.erb
    │   ├── new.erb
    │   ├── edit.erb
    │   └── register.erb
    └── demo/
        ├── discovery.erb
        ├── authorize.erb
        ├── tokens.erb
        ├── refresh.erb
        ├── udap_discovery.erb
        ├── udap_registration.erb
        ├── udap_token.erb
        ├── udap_authorization.erb
        └── backend_token.erb
```

## Endpoints

| Path | Description |
|------|-------------|
| `/.well-known/jwks.json` | JWKS endpoint serving the app's public key |
| `GET /register` | SMART Dynamic Client Registration form |
| `POST /register` | Submits a SMART registration request and saves the new server entry |
| `/launch` | EHR/Portal launch endpoint |
| `/callback` | OAuth2 callback handler for the SMART and UDAP authorization code flows; refuses a missing or unmatched `state` |
| `GET /demo/:id/discovery` | SMART discovery result page |
| `GET /demo/:id/udap-discovery` | UDAP discovery result page |
| `GET /demo/:id/udap-registration` | UDAP Dynamic Client Registration form and result page |
| `POST /demo/:id/udap-registration` | Submits a UDAP Dynamic Client Registration request |
| `POST /demo/:id/udap-registration/cancel` | Submits a UDAP registration cancellation request |
| `GET /demo/:id/udap-token` | UDAP B2B token request form |
| `POST /demo/:id/udap-token` | Submits a UDAP B2B `client_credentials` token request |
| `GET /demo/:id/udap-authorization` | UDAP authorization code start form |
| `POST /demo/:id/udap-authorization` | Builds the UDAP authorization request and redirects to the server |
| `POST /demo/:id/udap-authorization/refresh` | Submits a UDAP refresh token request |
| `GET /demo/:id/backend-token` | Backend Services token request form |
| `POST /demo/:id/backend-token` | Submits the backend services token request |
| `POST /reset-session` | Clears all OAuth and token session data |

## License

Apache 2.0
