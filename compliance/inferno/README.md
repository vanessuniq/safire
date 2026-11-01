# Inferno SMART App Launch STU2.2 harness

Runs Safire as a SMART client against the
[Inferno SMART App Launch test kit](https://github.com/inferno-framework/smart-app-launch-test-kit)
**client** suite (`smart_client_stu2_2`, "SMART App Launch STU2.2 Client"). In
that suite Inferno plays the authorization server and FHIR server, and grades
the client's requests.

- **Phase 1** (`backend_services_run.rb`): discovery and SMART Backend Services
  (`client_credentials` with a `private_key_jwt` client assertion).
- **Phase 2** (`app_launch_run.rb`): the authorization code flow, as a
  standalone launch and as an EHR launch, for public, confidential symmetric,
  and confidential asymmetric clients, plus two negative controls.

## Running

Requirements: Docker with the compose plugin, Ruby, `bundle install` done.
No gems beyond the main Gemfile are needed.

```sh
bin/inferno-smart
```

The script:

1. Clones the test kit at tag `v1.0.3` into `tmp/smart-app-launch-test-kit` and
   checks that it resolves to commit `980e54e4ed632b28267d797013399a8588772174`
   (skipped if the image `safire-inferno-smart:<commit>` already exists).
2. Builds and starts a single Inferno container (`docker-compose.yml`) on
   `http://localhost:4567` and waits for it to be healthy.
3. Runs `backend_services_run.rb` (writes `tmp/inferno/results.json` and
   `tmp/inferno/report.html`), then `app_launch_run.rb` (writes
   `tmp/inferno/app-launch/results.json` and `tmp/inferno/app-launch/report.html`).
   It exits non-zero unless both drivers report a pass.
4. Stops the container (set `INFERNO_KEEP=1` to keep it, e.g. to browse the
   sessions in the Inferno UI). `INFERNO_SCENARIOS=standalone-public,ehr-public`
   limits Phase 2 to the named scenarios.

The `Inferno SMART` GitHub Actions workflow runs the same script on manual
dispatch and weekly, and uploads the four report files as the
`inferno-smart-client` artifact. It does not run on pull requests.

## Phase 1: Backend Services

For each run the driver generates a fresh RSA key pair and a random `client_id`
in memory. Neither is written to disk. Then it:

1. Creates an Inferno session for `smart_client_stu2_2` with the suite option
   *SMART Backend Services Confidential Asymmetric Client*.
2. Starts the suite with inputs `client_id`, `smart_jwk_set` (the public JWKS,
   inline), and a one-Patient `fhir_read_resources_bundle`. Inferno checks the
   registration, then waits for the client.
3. Calls Safire `server_metadata` against Inferno's
   `/custom/smart_client_stu2_2/fhir/.well-known/smart-configuration` and
   `request_backend_token(scopes: ['system/Patient.rs'])` against the discovered
   token endpoint, with `allow_insecure_localhost: true`.
4. Reads `Patient/example` from Inferno's FHIR endpoint with the issued token,
   then calls Inferno's continuation URL so the waiting test completes.
5. Fetches the session results from the Inferno JSON API.

**Inferno-driven checks** (prefix `smart_client_stu2_2-`):

| Inferno test id | What Inferno checks |
|---|---|
| `smart_client_registration_bsca-smart_client_registration_bsca_verification` | The registered JWKS has at least one usable key |
| `smart_client_access-smart_client_access_bsca_interaction` | Wait step: the client gets a token and accesses data |
| `smart_client_access-smart_client_token_request_bsca_verification` | Each token request: `grant_type=client_credentials`, `client_assertion_type`, non-empty `scope`, assertion `typ`, `iss`/`sub` = client_id, `aud` = token URL, `exp` and unique `jti` present, signature verifies against the registered JWKS |
| `smart_client_access-smart_client_token_use_verification` | A token Inferno issued was used on an access request |

**Local checks** (Safire's own helpers, not Inferno assertions):
`discovery.smart_metadata_valid` (`SmartMetadata#valid?`),
`backend.request_backend_token` (the call completed), and
`backend.token_response_valid` (`token_response_valid?(flow: :backend_services)`).

## Phase 2: authorization code (standalone and EHR launch)

### How Inferno's simulated authorization server behaves

Read from the test kit source at `v1.0.3`
(`lib/smart_app_launch/endpoints/mock_smart_server/*`):

- The authorization endpoint (`GET`/`POST /custom/smart_client_stu2_2/auth/authorization`)
  renders no login or consent page. It answers at once with `302` to the
  request's `redirect_uri`, adding `code` and the echoed `state`. It uses no
  cookies or JavaScript.
- The token endpoint accepts the code for 10 minutes. It authenticates the
  client according to the session's client type: none for public, HTTP Basic
  against `smart_client_secret`, or a `private_key_jwt` assertion verified
  against `smart_jwk_set`. It checks PKCE (S256) only when a `code_verifier`
  is sent. It issues a refresh token when `offline_access` or `online_access`
  was requested, and merges the `launch_context` input into the token response.
- For an EHR launch, Inferno does not redirect anything itself. When launch URLs
  are registered, the waiting test outputs `launch_urls`
  (`<launch url>?iss=<fhir base>&launch=<random key>`) and shows them as links
  for the tester to open. The authorization-request test then requires a
  `launch` parameter, if sent, to equal that key.
- Registration requires `https` redirect and launch URIs. An `http` URI is
  recorded as an error.

### Why a plain HTTP user agent, not a browser

The authorization endpoint answers with a bare `302`, so a browser would only
follow `Location` headers. `user_agent.rb` does the same with `Net::HTTP`.
It records each hop (scheme, host, port, path, status; no query strings). This
makes the same front-channel requests a browser would (app, then Inferno
authorize, then app callback). Capybara or Playwright would add a browser and
dependencies without covering more of Inferno's behavior, so neither is used.
If a later kit version adds a consent page, this choice has to be revisited.

### The app under test

`launch_app.rb` is a small HTTPS server on `127.0.0.1` (random port) that plays
the SMART app. It uses a self-signed `localhost` certificate generated in
memory for each run (`tls_identity.rb`). Only the harness user agent trusts it.
The Sinatra demo app is not used. The routes call Safire:

| Route | Behavior |
|---|---|
| `GET /start` | Standalone launch: `server_metadata` on Inferno's FHIR base, then `302` to `authorization_url` |
| `GET /launch?iss&launch` | EHR launch: accept only the expected `iss`, then `302` to `authorization_url(launch:)` |
| `GET /callback?code&state` | Check `state`, call `request_access_token(code:, code_verifier:)`, then `refresh_token` when a refresh token was issued |

Safire is configured with `base_url` = `iss` (Inferno's FHIR base), the
callback as `redirect_uri`, `allow_insecure_localhost: true`, and the scenario's
`client_type`. Scopes are `launch/patient offline_access patient/Patient.rs`
(standalone) or `launch offline_access patient/Patient.rs` (EHR).

### Scenarios

Each scenario uses its own Inferno session, because the client type is a
session-level suite option. Client ids, client secrets, RSA keys, and the TLS
identity are generated at runtime and never written to disk.

| Scenario | Launch | `client_type` suite option | Expectation |
|---|---|---|---|
| `standalone-public` | standalone | `SMART,authorization_code,public` | all pass |
| `standalone-confidential-symmetric` | standalone | `SMART,authorization_code,confidential_symmetric` | all pass |
| `standalone-confidential-asymmetric` | standalone | `SMART,authorization_code,confidential_asymmetric` | all pass |
| `ehr-public` | EHR | `SMART,authorization_code,public` | all pass |
| `ehr-confidential-symmetric` | EHR | `SMART,authorization_code,confidential_symmetric` | all pass |
| `ehr-confidential-asymmetric` | EHR | `SMART,authorization_code,confidential_asymmetric` | all pass |
| `negative-wrong-code-verifier` | standalone | public | token request test `fail`; Safire raises `TokenError` |
| `negative-wrong-client-secret` | standalone | confidential symmetric | token request test `fail` or `error` (see Limitations); Safire raises `TokenError` |

Inferno inputs are `client_id`, `smart_redirect_uris` (the callback),
`smart_launch_urls` (EHR scenarios only), `smart_client_secret` or
`smart_jwk_set` (inline JWKS) depending on client type, `launch_context`
(`{"patient":"example"}`), and a one-Patient `fhir_read_resources_bundle`.

For each scenario the driver:

1. Creates the session and starts the suite.
2. Waits for Inferno's access test to reach `waiting`.
3. Sends the user agent to `/start` (standalone) or to Inferno's `launch_urls`
   output (EHR).
4. Reads `Patient/example` with the latest access token. The harness does this
   because Safire has no FHIR client.
5. Follows Inferno's continuation URL, waits for `done`, and fetches the results.

**Inferno-driven checks** (prefix `smart_client_stu2_2-`; `<t>` is `alp` for
public, `alcs` for confidential symmetric, `alca` for confidential asymmetric):

| Inferno test id | What Inferno checks |
|---|---|
| `smart_client_registration_<t>-smart_client_registration_<t>_verification` | Redirect and launch URIs are valid `https` URIs; for `alca`, the JWKS has a usable key |
| `smart_client_access-smart_client_access_<t>_interaction` | Wait step: the client launches and accesses data |
| `smart_client_access-smart_client_authorization_request_<t>_verification` | Each authorization request: `response_type=code`, `client_id`, registered `redirect_uri`, `state`, `aud` = FHIR base, `code_challenge` with `code_challenge_method=S256`, non-empty `scope`, and `launch` equal to Inferno's key when present |
| `smart_client_access-smart_client_token_request_<t>_verification` | Each token request (code and refresh): `grant_type`, a `code` issued in this session, `redirect_uri` equal to the authorization request's, PKCE verifier matches the challenge; plus `client_id` (public), Basic credentials (`alcs`), or assertion `typ`/`iss`/`sub`/`aud`/`exp`/unique `jti`/signature (`alca`) |
| `smart_client_access-smart_client_token_use_verification` | A token Inferno issued was used on an access request |

A positive scenario passes only if all five tests and the suite result are
present and `pass`, every other Inferno result is `pass`, and every local check
passes. An empty or partial result set fails. A negative control passes only if
its target test has the expected result and Safire raised `TokenError`. Any
orchestration error (Inferno unreachable, polling timeout, missing
`launch_urls`) fails that scenario and is written to the report.

**Local checks** (not Inferno assertions): `launch.iss_expected` (EHR only),
`discovery.smart_metadata_valid`, `authorize.authorization_url`,
`callback.state_matches`, `token.request_access_token`,
`token.token_response_valid` (`token_response_valid?(flow: :app_launch)`),
`token.patient_context`, `refresh.refresh_token`,
`refresh.token_response_valid`, and `refresh.patient_context`. Negative controls
replace the token checks with `token.wrong_code_verifier_rejected` or
`token.wrong_client_secret_rejected`.

## Limitations

- **Inferno's mock token endpoint.** It returns the requested scope and the
  configured launch context without enforcing scope semantics. Token *response*
  conformance is checked only by the local `token_response_valid?` helper.
  Inferno grades the requests.
- **PKCE is optional at Inferno's token endpoint.** The endpoint checks only a
  verifier that is sent. A missing verifier is flagged by the token request
  test, not rejected by the endpoint.
- **A wrong client secret ends in `error`.** At kit `v1.0.3`,
  `AuthenticationVerification#check_authorization_header` interpolates an
  undefined `e`, so the token request test raises `NameError` instead of
  failing. The mock token endpoint still rejects the request with `401`, which
  the local check records. The negative control accepts `fail` or `error`.
- **No id_token checks.** `openid` and `fhirUser` are not requested, and Safire
  does not validate id_tokens.
- **GET authorization only.** `authorization_url(method: :post)` (the
  `authorize-post` capability) is not exercised.
- **Inline JWKS.** The JWKS is passed inline rather than through a `jwks_uri`.
  Inferno accepts this but records the warning "Providing the JWK Set directly
  is strongly discouraged." The `jku` header path is not exercised.
- **RSA only.** Only RS384 is exercised. ES384 is not.
- **No validator.** The container runs without the HL7 validator, Redis, or
  Sidekiq (`INITIALIZE_VALIDATOR_SESSIONS=false`, `ASYNC_JOBS=false`). The
  client-suite tests used here do not validate FHIR resources.
- **TLS only on the app side.** Inferno is reached over `http://localhost` with
  `allow_insecure_localhost: true`. The app's redirect and launch URIs use
  `https` with a throwaway certificate.
- **Discovery is local only.** Inferno serves the discovery document but has no
  test that grades the client's discovery request.
- **Value-free reports.** Inferno input and output values are left out of the
  reports. Client secrets, codes, states, PKCE verifiers, launch keys, and
  tokens are redacted from Inferno and Safire messages.
