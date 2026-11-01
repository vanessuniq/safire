# Inferno SMART App Launch STU2.2 harness (Phase 1)

Runs Safire as a SMART client against the
[Inferno SMART App Launch test kit](https://github.com/inferno-framework/smart-app-launch-test-kit)
**client** suite (`smart_client_stu2_2`, "SMART App Launch STU2.2 Client"). In
that suite Inferno plays the authorization server and FHIR server, and grades
the client's requests.

Phase 1 covers HTTP-only flows: discovery and SMART Backend Services
(`client_credentials` with a `private_key_jwt` client assertion). Authorization
code flows need browser automation and are Phase 2.

## Running

Requirements: Docker with the compose plugin, Ruby, `bundle install` done.

```sh
bin/inferno-smart
```

The script:

1. Clones the test kit at tag `v1.0.3` into `tmp/smart-app-launch-test-kit` and
   checks that it resolves to commit `980e54e4ed632b28267d797013399a8588772174`
   (skipped if the image `safire-inferno-smart:<commit>` already exists).
2. Builds and starts a single Inferno container (`docker-compose.yml`) on
   `http://localhost:4567` and waits for it to be healthy.
3. Runs `backend_services_run.rb`, which writes `tmp/inferno/results.json` and
   `tmp/inferno/report.html`, and exits non-zero unless every check passed.
4. Stops the container (set `INFERNO_KEEP=1` to keep it, e.g. to browse the
   session in the Inferno UI).

The `Inferno SMART (Phase 1)` GitHub Actions workflow runs the same script on
manual dispatch and weekly, and uploads both report files as the
`inferno-smart-backend-services` artifact. It does not run on pull requests.

## What the run does

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

## Inferno-driven checks and local checks

The report keeps these in separate sections.

**Inferno-driven checks.** These are the results Inferno records for the session,
keyed by Inferno test id:

| Inferno test id (prefix `smart_client_stu2_2-`) | What Inferno checks |
|---|---|
| `smart_client_registration_bsca-smart_client_registration_bsca_verification` | The registered JWKS has at least one usable key |
| `smart_client_access-smart_client_access_bsca_interaction` | Wait step: the client gets a token and accesses data |
| `smart_client_access-smart_client_token_request_bsca_verification` | Each token request: `grant_type=client_credentials`, `client_assertion_type`, non-empty `scope`, assertion `typ`, `iss`/`sub` = client_id, `aud` = token URL, `exp` and unique `jti` present, signature verifies against the registered JWKS |
| `smart_client_access-smart_client_token_use_verification` | A token Inferno issued was used on an access request |

**Local checks.** These are Safire's own helpers. They are not Inferno assertions:

- `discovery.smart_metadata_valid`: `SmartMetadata#valid?` on Inferno's
  discovery document (the Phase 1 discovery gate).
- `backend.request_backend_token`: the Safire call completed without raising.
- `backend.token_response_valid`: `token_response_valid?(flow: :backend_services)`
  on Inferno's token response.

The FHIR read in step 4 is done by the harness, because Safire has no FHIR
client. Inferno's token-use test therefore checks that the token Safire obtained
is usable. It does not test Safire's own FHIR behavior.

## Limitations

- **Inferno's mock token endpoint.** It answers `client_credentials` with whatever
  `scope` was requested. Token *response* conformance is therefore checked only by
  the local `token_response_valid?` helper. Inferno grades the request.
- **Inline JWKS.** The JWKS is passed inline rather than through a `jwks_uri`.
  Inferno accepts this but records the warning "Providing the JWK Set directly is
  strongly discouraged." The `jku` header path is not exercised.
- **RSA only.** Only RS384 is exercised. ES384 is not.
- **No validator.** The container runs without the HL7 validator, Redis, or
  Sidekiq (`INITIALIZE_VALIDATOR_SESSIONS=false`, `ASYNC_JOBS=false`). The
  Backend Services client tests do not validate FHIR resources.
- **Plain HTTP on loopback.** The run uses `http://localhost` with
  `allow_insecure_localhost: true`. TLS is not exercised.
- **Discovery is local only.** Inferno serves the discovery document but has no
  test that grades the client's discovery request; only `SmartMetadata#valid?`
  checks it.
- **Phase 2 not covered.** Authorization code flows (standalone and EHR launch)
  are not run.
- **Value-free reports.** Inferno input and output values (keys, tokens) are
  left out of the reports.
