# Safire Demo Application

A Sinatra-based web application that demonstrates the Safire gem for SMART authorization, UDAP discovery, and UDAP Dynamic Client Registration.

## Features

- **Dynamic Client Registration**: Register this application with a SMART server at runtime using RFC 7591 to obtain a `client_id` automatically
- **Server Management**: Add, edit, and remove FHIR server configurations with protocol-aware SMART and UDAP sections
- **SMART Discovery**: View server capabilities from `/.well-known/smart-configuration` including supported scopes, capabilities, and endpoints
- **UDAP Discovery**: Fetch `/.well-known/udap`, validate `signed_metadata`, inspect STU2 fields, and run community-scoped discovery
- **UDAP Dynamic Client Registration**: Register and cancel a certificate-backed UDAP client, store the returned UDAP client identifier separately from SMART credentials, and inspect filtered registration responses
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
UDAP client signing credentials, and a sample self-signed certification JWT.
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
| `UDAP_CLIENT_CERTIFICATIONS_FILE` | No | Optional file containing compact JWS certification or endorsement JWTs, one per line; generated as a local self-signed demo file when absent |

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

Generated UDAP demo credentials and the sample self-signed certification JWT
expire after one year. `bin/demo` intentionally preserves non-empty `.env`
values and certification files so it does not overwrite issued test
credentials. To refresh only the generated local demo identity, blank both
`UDAP_CLIENT_PRIVATE_KEY_PEM` and `UDAP_CLIENT_CERTIFICATE_CHAIN_PEM` together,
blank `UDAP_REGISTRATION_SIGNING_ALGORITHM` unless it is still compatible with
the regenerated key, remove or empty the file named by
`UDAP_CLIENT_CERTIFICATIONS_FILE`, and rerun `bin/demo`.

### Adding a FHIR Server

The home page offers dynamic SMART registration or manual server setup.

**Register Dynamically (RFC 7591)** — if the server advertises a `registration_endpoint`:

1. Click "Register with a Server" on the home page
2. Enter the server name and base URL
3. Choose grant types, authentication method, and optional scope
4. Click "Register Client" — the app POSTs your metadata to the server, receives a `client_id`, and saves the server entry automatically

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
3. Optionally enter custom scopes (defaults to `system/*.rs`)
4. Click "Request Token"
5. View the access token, expiry, granted scopes, and SMART compliance check result

Requires `ASYMMETRIC_PRIVATE_KEY_PEM` and `ASYMMETRIC_KID` to be configured (same key pair used for confidential asymmetric App Launch).

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
- optional `community` and certification or endorsement JWTs
- persistence of the returned `client_id`, exact client URI, and optional
  community so cancellation uses the original registration identity
- cancellation only when the server confirms the same returned `client_id`

The page displays filtered registration metadata. It never renders the software
statement, private key, certificate chain, or other signing material.

If server metadata advertises `udap_certifications_required`, the registration
request must include matching certification or endorsement JWTs in the
`certifications` array. The metadata value is a required certification URI; it is
not itself the JWT to submit. Point `UDAP_CLIENT_CERTIFICATIONS_FILE` at a local
ignored file, or paste JWTs into the form for one-off testing.

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
├── data/
│   └── servers.yml     # Server configurations (YAML storage)
├── models/
│   ├── fhir_server.rb                # Server model with YAML persistence
│   ├── udap_client_credentials.rb    # UDAP demo client signing credential loader
│   ├── udap_discovery_presenter.rb   # UDAP discovery presentation model
│   ├── udap_pem_parsing.rb           # Shared UDAP demo PEM parsing helper
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
        └── backend_token.erb
```

## Endpoints

| Path | Description |
|------|-------------|
| `/.well-known/jwks.json` | JWKS endpoint serving the app's public key |
| `GET /register` | Dynamic Client Registration form |
| `POST /register` | Submits the registration request and saves the new server entry |
| `/launch` | EHR/Portal launch endpoint |
| `/callback` | OAuth2 callback handler |
| `GET /demo/:id/discovery` | SMART discovery result page |
| `GET /demo/:id/udap-discovery` | UDAP discovery result page |
| `GET /demo/:id/udap-registration` | UDAP Dynamic Client Registration form and result page |
| `POST /demo/:id/udap-registration` | Submits a UDAP Dynamic Client Registration request |
| `POST /demo/:id/udap-registration/cancel` | Submits a UDAP registration cancellation request |
| `GET /demo/:id/backend-token` | Backend Services token request form |
| `POST /demo/:id/backend-token` | Submits the backend services token request |
| `POST /reset-session` | Clears all OAuth and token session data |

## License

Apache 2.0
