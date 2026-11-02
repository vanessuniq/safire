# Inferno UDAP client-suite validation: Safire v0.5.0 B2B client_credentials

Date: 2026-11-01. Validator role only: no repository files were modified or pushed.

## Read this first: scope and the STU1 caveat

- **The test kit grades against UDAP Security STU1 (1.0.0), not STU2.** Suite
  `udap_security_client` declares requirement set `hl7.fhir.us.udap-security_1.0.0`
  and links to `https://hl7.org/fhir/us/udap-security/STU1/`
  (`lib/udap_security_test_kit/client_suite.rb`). Safire implements STU2 (2.0.0).
  Every "pass" below is an **STU1-labelled Inferno result**. For the checks this
  suite actually runs, the analysis below compares them line by line with the STU2
  text in `/tmp/specs/udap-ig/input/pagecontent`. For those checks, STU1 and STU2
  agree.
- This is **external interoperability evidence**, not a certification. Inferno is a
  mock server. It never grades Safire's discovery or trust processing, and several
  STU2-only behaviours are not exercised (listed under "What could not run / is not
  covered").
- **One configuration deviation from the stock kit was needed for any positive run.**
  The kit's mock `signed_metadata` breaks the STU1 and STU2 `iss`/SAN rule, so
  Safire, correctly, rejects it. The kit's own env overrides
  (`UDAP_TEST_KIT_CERT_FILE`, `UDAP_TEST_KIT_PRIVATE_KEY_FILE`) were used to swap in
  a mock-server signing certificate with a correct SAN. No kit source was changed.
  Details are in §4.

## 1. Versions

| Item | Value |
|---|---|
| Safire | `origin/feature/udap-b2b-client-credentials` (draft PR #358), detached at **`51d621050403070e95ef708c72ceb287d620c49e`** ("Merge feature/udap-token-readiness"). `lib/safire/version.rb` still reads `0.4.1` (the v0.5.0 bump is not on this branch). |
| Test kit | `inferno-framework/udap-security-test-kit` tag **v0.12.2**, commit **`ba81acba089444f4c0e34a545d599d57ff8f6ab9`** (shallow clone at `/tmp/udap-kit`) |
| inferno_core | 1.2.2 (`/api/version`; Gemfile.lock) |
| Docker image | `safire-inferno-udap:v0.12.2`, id `sha256:85e8da54c0b39262f2cb2670f37b5182f1f7521a541d107afe7d718307623fa1` |
| Ruby (driver) | 3.3.6, `bundle exec` from the Safire worktree (Safire loaded from source) |

## 2. Harness (all files under /tmp; none in the repo)

- `/tmp/udap-build/kit/`: a copy of the kit without `.git`, plus
  `Dockerfile.sandbox` and `sandbox-ca.crt`. `Dockerfile.sandbox` is the upstream
  Dockerfile with two changes: the MITRE PKI `wget` step is removed, and the sandbox
  proxy CA (`/root/.ccr/ca-bundle.crt`) is trusted so `bundle install` can reach
  rubygems through the proxy. This is the same trick used for the SMART kit image.
  The build log is at `/tmp/udap-build/build.log`.
- `/tmp/udap-scripts/start_inferno.sh stock|override`: runs one container,
  `safire-udap-inferno`, on `127.0.0.1:4600`. It sets `INFERNO_HOST=http://localhost:4600`
  (which must match the URL the driver uses, because Inferno embeds it in discovery and
  in the expected registration and token `aud`), `ASYNC_JOBS=false` and
  `INITIALIZE_VALIDATOR_SESSIONS=false`, as the SMART harness in
  `origin/feature/inferno-smart-phase1:compliance/inferno/docker-compose.yml` does.
  The command is `inferno migrate && puma`. There is no validator, Redis, or Sidekiq.
  The `override` mode also mounts `/tmp/udap-pki` and sets the kit's two cert env
  overrides.
- `/tmp/udap-scripts/gen_certs.rb`: writes sandbox PKI to `/tmp/udap-pki`:
  - `server.pem`/`server.key`: the mock-server signing cert. It is issued by the
    kit's own test CA (`certs/InfernoCA.pem` + `InfernoCA.key`, both shipped in the
    kit) with SAN `URI:http://localhost:4600/custom/udap_security_client/fhir`.
  - `inferno_ca.crl`: an empty CRL signed by the kit CA.
  - `rogue.pem`/`rogue.key`: a self-signed cert that carries the same SAN as the
    kit's `TestClient.pem` but a different key. It is used for the negative control.
- `/tmp/udap-scripts/drive.rb SCENARIO OUT.json`: the Safire driver, described in §3.
- `/tmp/udap-scripts/inspect_requests.rb SESSION_ID`: a value-free dump of what
  Inferno recorded. It shows parameter and claim names, fixed values, JWT header
  shape and lifetime. It does not show tokens, keys or signatures.

Exact commands:

```sh
cp -a /tmp/udap-kit /tmp/udap-build/kit && rm -rf /tmp/udap-build/kit/.git
cp /root/.ccr/ca-bundle.crt /tmp/udap-build/kit/sandbox-ca.crt
cd /tmp/udap-build/kit && docker build -f Dockerfile.sandbox -t safire-inferno-udap:v0.12.2 .
ruby /tmp/udap-scripts/gen_certs.rb /tmp/udap-kit/lib/udap_security_test_kit/certs /tmp/udap-pki \
     http://localhost:4600/custom/udap_security_client/fhir
# stock kit config
sh /tmp/udap-scripts/start_inferno.sh stock
cd <safire worktree> && bundle exec ruby /tmp/udap-scripts/drive.rb stock /tmp/udap-out/stock.json
# kit config with mock-server signing cert override
sh /tmp/udap-scripts/start_inferno.sh override
bundle exec ruby /tmp/udap-scripts/drive.rb positive       /tmp/udap-out/positive.json
bundle exec ruby /tmp/udap-scripts/drive.rb neg_wrong_key  /tmp/udap-out/neg_wrong_key.json
bundle exec ruby /tmp/udap-scripts/drive.rb neg_no_b2b_raw /tmp/udap-out/neg_no_b2b_raw.json
bundle exec ruby /tmp/udap-scripts/drive.rb positive       /tmp/udap-out/positive2.json   # repeat
ruby /tmp/udap-scripts/inspect_requests.rb ec1ePybHryL > /tmp/udap-out/positive-requests.json
docker rm -f safire-udap-inferno   # only the container this run started
```

(`ruby`/`bundle` = `/opt/rbenv/versions/3.3.6/bin/...`.) The raw outputs are in
`/tmp/udap-out/*.json` and `*.log`.

## 3. What the driver does

1. It creates a session for `udap_security_client` with the suite option
   `client_type = "udap,client_credentials"` (UDAP Client Credentials Client).
2. It starts group `udap_client_registration_cc` with input
   `udap_client_uri = https://inferno.com/udap_security_test_kit/ac`. That URI is
   the SAN of the kit's `certs/TestClient.pem`.
   - Inferno does **not** check client certificate trust. It verifies the
     signature with the `x5c` leaf and checks that `iss` is in the leaf's SAN
     (`MockUDAPServer.udap_reg_signature_verification`). The kit's own client cert,
     which is issued by `InfernoCA`, was used anyway.
3. It runs Safire against `base_url = http://localhost:4600/custom/udap_security_client/fhir`
   with `allow_insecure_localhost: true`:
   - `server_metadata(trusted_anchors: [InfernoCA], crls: [empty CA CRL], verify_chain: true)`
   - `register_client({client_name, contacts: ['mailto:…'], grant_types: ['client_credentials'], scope: 'system/*.read'}, client_uri:, <same trust>)`
     with `private_key` = `TestClientPrivateKey.key` and `certificate_chain` = `[TestClient.pem]`.
4. It calls `resume_pass?token=<client_id>`. Then it starts group
   `udap_client_access_cc` with `client_id` and `udap_registration_jwt` taken from
   the session data, plus a one-Patient `fhir_read_resources_bundle`.
5. It calls Safire
   `request_backend_token(scopes: 'system/*.read', b2b: {organization_id, organization_name, purpose_of_use: ['urn:oid:2.16.840.1.113883.5.8#TREAT']}, <same trust>)`
   on a client configured with the returned `client_id`.
   - `system/*.read` is used because Inferno's `scopes_supported` is
     `['openid','system/*.read','user/*.read','patient/*.read']`, and Safire only
     sends wildcard scopes that are advertised exactly.
6. The harness reads `GET …/fhir/Patient/example` with the issued Bearer token,
   because Safire has no FHIR client. It then calls `resume_pass` again and fetches
   `/api/test_sessions/:id/results`.

The visual-inspection/attestation group (`udap_client_v100_visual_inspection_and_attestation`)
was **not run**. It contains 17 manual self-attestation tests that need a human, not
machine checks.

## 4. Results

### 4a. Stock kit configuration (session `4nWNzZuaU7J`): Safire stops at discovery, which is correct behaviour

| Step | Outcome |
|---|---|
| `server_metadata(verify_chain: true, anchor + CRL)` | `DiscoveryError: signed_metadata validation failed`. Warning: `iss 'http://localhost:4600/custom/udap_security_client/fhir' does not match any uriName SAN in the leaf certificate` |
| `server_metadata(verify_chain: false)` | Same `DiscoveryError`. The SAN rule is enforced regardless of `verify_chain` |
| `register_client(..., verify_chain: false)` | Same `DiscoveryError`. No registration request was sent |
| Inferno `…registration_cc-udap_client_registration_interaction` | pass (only the wait step) |
| Inferno `…registration_cc-udap_client_registration_cc_verification` | **skip**: "No UDAP Registration Requests made for client uri 'https://inferno.com/udap_security_test_kit/ac'." |

Root cause (kit, not Safire): the stock mock server signs `signed_metadata` with
`certs/TestClient.pem`. Its only SAN is `URI:https://inferno.com/udap_security_test_kit/ac`,
but `iss` is `{INFERNO_HOST}/custom/udap_security_client/fhir`
(`MockUDAPServer.udap_signed_metadata_jwt`).

- STU2 discovery.md, signed metadata `iss`: "This **SHALL** match the value of a
  uniformResourceIdentifier entry in the Subject Alternative Name extension of the
  server's certificate included in the `x5c` JWT header, and **SHALL** be equal to
  the server's {baseURL}".
- STU2 changelog FHIR-49242: "Clarify that clients will terminate workflow if server
  metadata is not trusted".
- The kit's own STU1 requirement list has the same rule, as reqs 49 and 50
  (`requirements/udap_security_test_kit_requirements.csv`).

So this is **not an STU1/STU2 difference**. The stock mock server's metadata
violates both versions, and the client suite never grades a client's discovery
processing. Rejecting the metadata is the conformant client behaviour. No setting
in Safire bypasses the SAN check (`verify_chain: false` skips only X.509 chain
validation). Running the suite against a stock kit therefore **cannot** produce a
positive result for Safire.

Workaround used for all later runs: the kit supports overriding the mock server's
signing cert and key through `UDAP_TEST_KIT_CERT_FILE` and
`UDAP_TEST_KIT_PRIVATE_KEY_FILE` (`mock_udap_server.rb#test_kit_cert`). The new cert
is issued by the kit's own `InfernoCA` and its SAN equals the mock FHIR base URL.
This let Safire run with **`verify_chain: true`** against trust anchor
`InfernoCA.pem` and revocation input = an empty CRL signed by `InfernoCA`.

### 4b. Positive run, override config (session `ec1ePybHryL`; repeated as `llf3jAxdAIh` with identical results)

Inferno results (test ids are prefixed `udap_security_client-`):

| Inferno test id | Result | STU1 reqs claimed by the test (`verifies_requirements`) |
|---|---|---|
| `udap_client_registration_cc-udap_client_registration_interaction` | pass (wait step) | none |
| `udap_client_registration_cc-udap_client_registration_cc_verification` | **pass**, no messages; `POST …/auth/register -> 201` | 1.0.0 @1,2,3,7,8,66,71–81,83,85–87,92,95–97,101–104 |
| `udap_client_registration_cc` (group) | pass | |
| `udap_client_access_cc-udap_client_access_cc_interaction` | pass (wait step) | none |
| `udap_client_access_cc-udap_client_token_request_cc_verification` | **pass**, no messages; `POST …/auth/token -> 200` | 1.0.0 @1,2,3,7,8,67,69,186,192–198,202,212,214,215,223,225–228 |
| `udap_client_access_cc-udap_client_token_use_verification` | **pass**; `GET …/fhir/Patient/example -> 200` (harness read with Safire's token) | none |
| `udap_client_access_cc` (group) | pass | |
| `udap_security_client` (suite roll-up) | pass. This rolls up only the groups that ran; the attestation group was not run | |

Local (Safire-side) observations:

- `server_metadata` accepted the signed metadata with `verify_chain: true`. The signed
  `token_endpoint` and `registration_endpoint` equal Inferno's.
- `register_client` returned the Inferno-derived `client_id`, which is the base64url
  of the client URI.
  - Inferno's registration response echoes `iss, sub, aud, exp, iat, jti`. That
    conflicts with STU2's "**SHOULD NOT** be included in the response" (registration.md;
    changelog FHIR-48921). It is caused by a kit bug: `.except(['iss', …])` is passed
    an array. Safire tolerated it.
- `request_backend_token` returned `access_token`, `token_type: Bearer` and
  `expires_in`.
- The only Safire warnings were the expected `allow_insecure_localhost`
  development-only warning. There were no scope or extension warnings.
- `token_response_valid?(flow: :backend_services)` raises `NotImplementedError` on a
  `protocol: :udap` client, so it was not used. This is not a defect: the method is
  SMART-only by design in Behaviours. It is mentioned so nobody assumes it was
  checked.

What Inferno recorded from Safire (value-free; `/tmp/udap-out/positive-requests.json`):

- **Registration POST**:
  - Body keys: exactly `software_statement` and `udap` (`"1"`).
  - Software statement header: `alg: RS256`, `x5c` with 1 cert (TestClient leaf).
  - Claims: `aud, client_name, contacts, exp, grant_types, iat, iss, jti, scope, sub, token_endpoint_auth_method`.
  - `iss == sub`; `aud` = Inferno registration URL; `exp - iat = 300` s;
    `grant_types: ["client_credentials"]`; `token_endpoint_auth_method: private_key_jwt`.
  - No `redirect_uris` or `response_types`.
- **Token POST**:
  - Headers: no `Authorization` header.
  - Form params: exactly `client_assertion, client_assertion_type, grant_type, scope, udap`,
    with `grant_type=client_credentials`,
    `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `udap=1`.
  - Assertion header: `alg: RS256`, `x5c` with the same leaf.
  - Assertion claims: `aud, exp, extensions, iat, iss, jti, sub`, with `aud` = the
    signed token endpoint and lifetime exactly 300 s.
  - `extensions.hl7-b2b = {version: "1", organization_name, organization_id (URI), purpose_of_use: [..]}`.

### 4c. Negative controls

**N1: wrong signing key (Safire-built request); session `90CL4LsuWKI`.** Registration
used the kit's TestClient cert. `request_backend_token` used `rogue.key` and `rogue.pem`
(same SAN, different key).

| Item | Outcome |
|---|---|
| Safire | `TokenError: Token request failed — HTTP 401 — invalid_client — signing cert does not match registration cert` (the server's OAuth error was preserved) |
| `…registration_cc_verification` | pass |
| `…udap_client_token_request_cc_verification` | **fail**: "Invalid token requests received." Message: `error: Signature validation failed on token request 1: signing cert does not match registration cert`; `POST …/auth/token -> 401` |
| `…udap_client_token_use_verification` | skip: "No token requests made." |
| Suite roll-up | **fail** |

**N2: missing `hl7-b2b`; session `9sJv5JwUBHg`.**

| Item | Outcome |
|---|---|
| Safire `request_backend_token` without `b2b:` | Refused locally before any network I/O: `ValidationError: Validation failed for b2b: is required: UDAP Security STU2 requires the hl7-b2b extension…`. Inferno recorded **no** request from this call (the only token request in the session is the harness one below) |
| Harness-built (not Safire) token request: same TestClient key, RS256 + `x5c`, all params including `udap=1`, assertion **without** `extensions` | Inferno's mock token endpoint returned 200. It checks only the signature at issue time |
| `…udap_client_token_request_cc_verification` | **fail**: `error: client assertion jwt on token request 1 missing the \`hl7-b2b\` extension.` |
| `…udap_client_token_use_verification` | pass (the harness used the token) |
| Suite roll-up | **fail** |

N2 shows that Inferno detects a missing `hl7-b2b`. It also shows that Safire cannot
emit such a request: the only way to put one on the wire was to bypass Safire.

## 5. STU1 (kit) vs STU2 (Safire) analysis for the checks actually run

The kit grades each item below against STU1 1.0.0. Each was checked against the
STU2 text, and for every item the STU2 requirement is the same, so a pass is
meaningful for STU2 on that item.

**Registration** (`registration_request_verification.rb` vs STU2 registration.md "Software Statement"):
- `udap` = "1".
- `iss`/`sub` = client URI, with `iss` in the `x5c` leaf SAN.
- `aud` = registration URL.
- `exp` ≤ `iat` + 5 min, and not expired.
- `jti`, `client_name`, and `contacts` with a `mailto` entry.
- `token_endpoint_auth_method` = `private_key_jwt`; `scope` present.
- `grant_types` includes `client_credentials` and not `authorization_code`, and has
  no `refresh_token` without `authorization_code`.
- `redirect_uris` and `response_types` absent for client_credentials.

All are STU2 SHALL/required items with the same wording.

**Token request** (`token_request_verification.rb` vs STU2 b2b.md §5.2.1 and §5.2.2):
- `grant_type=client_credentials`.
- `client_assertion_type` = jwt-bearer.
- `udap` = "1". STU2 lists it as "required, Fixed value: 1".
- Assertion `iss`/`sub` = `client_id`; `aud` = token URL.
- `exp` ≤ `iat` + 300 s. STU2: "`exp` minus the value of `iat` **SHALL** NOT exceed 300 seconds".
- Unique `jti`.
- `extensions.hl7-b2b` with `version` "1", `organization_id` (URI) and
  `purpose_of_use` (required in STU2's B2B Authorization Extension Object table).
- Signature by the registered `x5c` leaf.

**Gaps in Inferno's checks relative to STU2.** These are not failures. Inferno simply
does not test them:

- Inferno checks `purpose_of_use` only for presence. It does not check that it is
  an array of strings, which is STU2's wording.
- Inferno does not check that no `Authorization` header or client secret is sent.
  STU2 b2b.md: "**SHALL NOT** include an HTTP Authorization header or client secret".
  The value-free request dump confirms Safire sends no `Authorization` header and no
  `client_id`/`client_secret` parameters.
- Inferno does not check `scope` presence on the token request, which STU2 marks
  required. The dump shows Safire sends it.

**The STU1 → STU2 changes that could cause a failure** did not cause one in this
suite. The only failure seen, the stock-config discovery rejection, comes from a rule
present in both versions (STU1 reqs 49 and 50; STU2 discovery.md), so it is not a
version difference.

## 6. Safire defects found

**None.** No Inferno check failed on a Safire-built request in the positive runs. Both
negative controls behaved as the spec requires: Safire refuses missing `hl7-b2b`
(b2b.md §5.2.1: the B2B extension object "is required for B2B client apps using the
`client_credentials` flow"), and Safire surfaces the server's `invalid_client`. The
stock-config discovery failure is correct STU2 behaviour (discovery.md signed metadata
`iss` rule; FHIR-49242), not a defect.

Minor observation, not a defect: `Client#token_response_valid?` is unimplemented
for `:udap`. Callers of the UDAP B2B flow get no response-shape helper beyond what
`request_backend_token` already enforces (a JSON object with a non-blank
`access_token`).

## 7. What could not run / is not covered

- **The stock kit cannot produce a positive Safire run** (§4a). All positive evidence
  depends on the kit-supported cert override. That override replaces only the mock
  server's signing cert and key; the issuing CA and kit code are unchanged.
- **Visual inspection and attestation group**: not run. It is 17 human
  self-attestation tests.
- **The STU1 requirement set**: Inferno's requirement IDs are STU1 1.0.0. There is no
  STU2 version of this kit in the clone.
- **Discovery and trust are not graded by Inferno.** Safire's `verify_chain: true`
  acceptance with a CRL, and its stock-config rejection, are local observations.
- **Not exercised**:
  - TLS: plain HTTP on loopback with `allow_insecure_localhost: true`.
  - ES384: the kit's client cert is RSA, so only RS256 was used.
  - The `community` parameter, `certifications`, registration modification and
    cancellation.
  - Intermediate-CA chains: `x5c` had one cert.
  - Scope narrowing by the server: Inferno echoes no `scope`.
  - The experimental `jku` path.
  - The authorization-code client type and Tiered OAuth.
- **Inferno's token endpoint grades signatures only at issue time.** Other
  token-request checks happen in the verification test afterwards, which is why N2
  got a 200 and then a failed verification.
- Client cert trust is not checked by Inferno (leaf signature and SAN only). Using
  the kit's CA-issued `TestClient.pem` was a choice, not a requirement.
- **Branch version**: `version.rb` on the tested SHA says 0.4.1. The results apply
  to commit `51d6210`, not to a released v0.5.0 gem.

## 8. Cleanup

Only container `safire-udap-inferno` (started by this run) was removed. The image
`safire-inferno-udap:v0.12.2` is kept for reuse. No other containers were touched.
The worktree is clean (`git status` empty) at `51d6210`.
