# Safire v0.6.0 pre-release alignment audit (combined stack)

> **Point-in-time snapshot.** `/tmp/audit/...` paths were sandbox scratch files; commands and outputs are quoted inline. Finding status is tracked in [README.md](README.md).

- **Inspected commit:** `origin/docs/v0.6.0-release-notes` (draft PR #393), checked out detached at
  `9a006892b15fbef1eb83f6dbececdebb14cd2db4` ("Merge feature/demo-udap-authorization-code"). This is the expected `9a00689`.
  It contains release-0.5.0 (#389) plus #359, #380, #381, #382, #390, #391 and #393.
- **Mode:** read-only. No repository files were changed and nothing was pushed. Generated artifacts were removed:
  `.yardoc/`, `docs/api/`, `docs/.jekyll-cache/`, the demo `.env` and `data/`, `spec/examples.txt`, `/tmp/site-v6`, and the built gem.
  `git status --short --ignored` is empty. The demo `Gemfile.lock` was unchanged by `bundle install`.
- **Plans:** `.github/plans/v0.6.0.md` and `decisions.md` (D-12, D-13 revised, D-14, D-16, D-20), read from `origin/docs/roadmap-execution-plan`.
- **Specs:** UDAP STU2 `/tmp/specs/udap-ig/input/pagecontent` and SMART 2.2.0 `/tmp/specs/smart-ig/input/pages`. Section numbers follow heading order (D-17).
- **Scratch files and logs:**
  - `/tmp/audit/v6/`: `rspec.log`, `as71.log`, `rubocop.log`, `audit-{root,demo,as71}.log`, `yard.log`, `jekyll.log`, `linkcheck.out`, `demo-install.log`, `gemx/files.txt`.
  - `/tmp/audit/v6scratch/`:
    - `verify_authz.rb` and `.out`: README/doc examples run against the real PKI from `fscratch/pki.rb` with WebMock.
    - `verify_smart_backend.rb` and `.out`.
    - `fake_udap_ac.ru`: a fake UDAP+SMART server that checks PKCE and redirect_uri, plus its log `fake_udap_ac.log`.
    - `probe_demo.sh` and `.out`, and `demo.server.log`.

## Check results

| Check | Command | Result |
|---|---|---|
| Full suite | `bundle exec rspec` | **1735 examples, 0 failures** (v0.5.0 stack: 1544) |
| AS 7.1 floor | `BUNDLE_GEMFILE=gemfiles/activesupport_71.gemfile bundle exec rspec` | **1735 examples, 0 failures** |
| Demo specs | `bundle exec rspec spec/examples` | 193 examples, 0 failures (v0.5.0: 160) |
| New UDAP authorization code specs | 5 spec files (url, access token, refresh, readiness, integration) | 114 examples, 0 failures |
| Lint | `bundle exec rubocop` | 105 files, no offenses |
| Advisories (root) | `bundler-audit check --update` | No vulnerabilities. The DB was already up to date (92c25ce, 2026-10-31). |
| Advisories (demo) | `--gemfile-lock examples/sinatra_app/Gemfile.lock` | No vulnerabilities |
| Advisories (AS 7.1) | `--gemfile-lock gemfiles/activesupport_71.gemfile.lock` | activesupport 7.1.6: CVE-2026-33169/33170/33176. This is the known D-21 exception; no 7.1.x fix exists. |
| YARD | `bin/docs` | Exit 0, 82.35% documented, navigation patched. 4 pre-existing ATTRIBUTES warnings. **6** unresolved `{#…}` links in `client.rb` (lines 48, 54×2, 55, 62, 67); v0.5.0 had 2 (E-1). |
| Jekyll | `cd docs && bundle exec jekyll build -d /tmp/site-v6` | Exit 0, no warnings. The `udap/authorization-code/` page is built. |
| Link check | `ruby -E UTF-8 /tmp/audit/scratch/linkcheck.rb /tmp/site-v6` | **0 broken internal links or anchors** |
| STU2 anchors | All 11 unique `udap-security/STU2/*.html#…` anchors in lib/docs/README/CHANGELOG/demo | All exist in the IG headings |
| SMART anchors | `backend-services.html#request`, `#scopes` | `#request` targets the wrong section (G-03) |
| Spec quotes | Every SHALL/MAY quote in `authorization-code.md`, `udap.rb` YARD, CHANGELOG, ADR-015 | Exact against the source (ellipses used correctly) |
| Gem build | `gem build safire.gemspec` | `safire-0.5.0`, **108 files**. This is the v0.5.0 list plus `docs/udap/authorization-code.md` and `lib/safire/protocols/udap_authorization_request_readiness.rb`. No `spec/`, `compliance/` or `examples/`. `docs/`, `.claude/` and `gemfiles/` are still shipped (E-14). |
| Version | `Safire::VERSION` | `0.5.0`, as expected before 6.R. CHANGELOG has `[Unreleased]`. The demo and AS 7.1 locks pin `safire (0.5.0)`. |

## Wire behavior vs STU2 (real PKI, signed metadata really validated, only HTTP stubbed)

The README and `docs/udap/authorization-code.md` examples ran verbatim (config, step 1, step 3, step 4, error-handling snippet). Output is in `verify_authz.out`.

**Authorization request: `authorization_url` (general §7.2, §7.2.1, §7.2.2)**
- Builds a GET on the **signed** `authorization_endpoint`. A different unsigned value is ignored, and an existing query (`?tenant=a`) is preserved.
- The URL carries exactly `client_id, code_challenge, code_challenge_method=S256, redirect_uri, response_type=code, scope, state`.
- `state` is 43 characters (32 bytes) and is new on every call. `code_challenge` = BASE64URL(SHA256(verifier)). The verifier is 128 characters.
- No POST is sent. Return shape is `{auth_url:, state:, code_verifier:}`.
- Missing scopes, `redirect_uri` or `client_id` raise `ConfigurationError` with 0 HTTP calls.
- Fails with `DiscoveryError` when:
  - `authorization_code` is not advertised;
  - `authorization_endpoint` is missing;
  - the endpoint is unsigned only (signed_metadata validation fails);
  - the endpoint is HTTP (rejected already at signed-metadata validation).
- An unadvertised wildcard only warns (D-13 revised). The warning carries a count and does not include the scope value.

**Code exchange: `request_access_token` (consumer §4.2, b2b §5.2.2.1)**
- The form is exactly `grant_type=authorization_code, code, redirect_uri` (identical to step 1), plus `code_verifier, client_assertion_type, client_assertion, udap=1`.
- No Authorization header. `Content-Type` is `application/x-www-form-urlencoded`. The POST goes to the signed `token_endpoint`.
- Authentication Token (AnT):
  - Header is `alg` (RS256) plus a leaf-first `x5c`.
  - Claims are `iss` = `sub` = `client_id`, `aud` = token endpoint, `iat`, `exp` (300 s), and a fresh `jti`.
  - There is no `extensions` claim by default (D-20).
- `hl7-b2b` raises `ValidationError`. Other extensions are embedded as given.
- When `udap_authorization_extensions_required` lists extensions that are not sent, Safire warns (count only) and proceeds.
- A short verifier, a blank code, or a missing `redirect_uri` fail before any HTTP call.
- A missing `udap_authn` profile or an unadvertised grant raises `DiscoveryError`.
- `invalid_grant` raises `TokenError` after exactly 1 POST (no retry).
- No code, verifier, access token or refresh token appears in the logs.

**Refresh: `refresh_token` (b2b §5.3, consumer §4.3)**
- The form is `grant_type=refresh_token, refresh_token, client_assertion_type, client_assertion, udap=1`. `scope` is sent only with `scopes:`; configured scopes are not used.
- The AnT is the same as for the code exchange.
- An unadvertised wildcard on refresh raises `ValidationError` with 0 POSTs. An advertised wildcard passes.
- If `refresh_token` is not in `grant_types_supported`, Safire warns and proceeds.
- `hl7-b2b` and a blank refresh token are rejected.

**Release scope:** `authorization_url(idp:)` raises `ArgumentError` (unknown keyword). `token_response_valid?` raises `NotImplementedError` on UDAP, as documented. No file claims that Tiered OAuth is implemented.

**SMART Backend Services (D-16; output in `verify_smart_backend.out`):**
- No scope at all, configured `[]`, or configured `['',' ']` raises `ConfigurationError`. `missing_attributes == [:scopes]`, the message is the documented value-free text, and **0 HTTP calls** are made (discovery included).
- A blank per-call value (`nil`, `[]`, `['']`, `''`) falls back to the configured scopes. A per-call String or Array overrides them.
- Explicit `system/*.rs` (the documented migration) and `patient/` scopes are sent unchanged, with no warning.
- The scope check runs after the `client_id` check: with neither set, `missing_attributes` is `[:client_id]`. It runs before the key check: with no key and no scope, `missing_attributes` is `[:scopes]`.
- The README Backend Services example works.

**Demo:** puma on 127.0.0.1:4652 with the fake server on 4713. Development trust mode, real signed metadata and AnT verification.
- **Normal flow:**
  - The start form returns 303 to the authorization endpoint with the 7 parameters.
  - The callback with a matching `state` exchanges the code. The fake server saw PKCE OK, `redirect_uri` matched, `udap=1`, no Authorization header and no `extensions`.
  - The page masks the access token and filters `refresh_token` and `id_token`.
  - Refresh with a blank scope sends no `scope`. Refresh with a narrower scope sends `scope`. The rotated refresh token is kept.
- **Error paths:**
  - Replaying the used callback is refused (302 /).
  - A tampered `state` or a missing `state` returns 302 / with "Invalid or missing state … no token was requested". The fake server logged **no** token request.
  - `error=access_denied` with an HTML description renders the escaped text, and no token is requested.
- **SMART Backend Services:**
  - An empty scope returns 422 "Enter at least one scope…" (the demo validates before calling Safire).
  - A `patient/` scope returns 422.
  - `system/Patient.rs` returns 200.
- **Logs:** the demo log contains no tokens, codes or `state` values.

## Spot-check of v0.5.0 findings

| ID | Status at 9a00689 |
|---|---|
| B-01 | Still fixed: no `exchange_code_for_token`, positional `refresh_token(hash)` or `ssl_options` in docs/README |
| B-02 | Still fixed (`token-exchange.md:193` uses `ConfigurationError` and `missing_attributes`) |
| B-03 | Still fixed (`client-errors.md:281` says "sends no `iat` claim") |
| B-04 | Still fixed (`discovery/index.md:79/85/97` uses `NetworkError`) |
| B-05 | Still fixed (0 broken links) |
| B-06 | Still fixed in docs. Residual runtime wording E-F5 is unchanged. |
| B-07 | Still fixed (`CONTRIBUTION.md:84`, `README.md:289`) |
| B-08 | Still fixed (`user_agent` documented; `ssl_options` exists only in internal `HTTPClient`) |
| B-09 | Still fixed (`public-client/token-exchange.md:153`) |
| B-10 | Still fixed (`ROADMAP.md:19`) |
| B-11 | Demo lock audits clean and the lock is unchanged by install. AS 7.1 is the D-21 exception. At 6.R both locks must be re-locked to 0.6.0. |
| B-12 | Still fixed (no §8.1 or `flow:` text). The new `client.rb` grant contract is accurate, apart from G-04's typo. |
| B-13 | Still fixed (`security.md:243-247` rotation; `supports_*_auth?` used) |
| F-01 | Still fixed (no `5.2.3` citation in lib/docs) |
| F-02 | Still fixed (ADR-016:145). It is now incomplete for v0.6.0 (see G-02). |
| F-03 | Fixed for v0.5.0 content. **The same class recurs for v0.6.0 content (G-02).** |
| F-04 | Not defined in either prior report (`feature-v0.5.0.md` stops at F-03), so there was nothing to check. |

## Confirmed defects (release blockers under the audit policy; all docs-only and small)

### G-01: `docs/udap.md` comparison table says UDAP implements only registration and B2B
- **Files:**
  - `docs/udap.md:214`: the table row "Implemented client flows | … | Registration lifecycle and B2B client credentials".
  - `docs/udap.md:5`: front-matter `description` "UDAP Security STU2 discovery, Dynamic Client Registration, and B2B client credentials in Safire."
- **Expected:** both name the authorization code flow with refresh, matching the page intro (`udap.md:14-20`), `udap.md:204-206`, the CHANGELOG, the gemspec and `client-setup.md:74`.
- **Actual:** the table contradicts the same page's "UDAP clients support `authorization_url`, `request_access_token`, and `refresh_token`".
- **Repro:** `grep -n "Implemented client flows\|^description" docs/udap.md`.
- **Spec:** n/a (scope accuracy). The feature is consumer §4.1–4.2 / b2b §5.1–5.3.
- **Fix:** change the row to "Registration lifecycle, B2B client credentials, and authorization code with refresh". Add "and the authorization code flow" to the description.
- **Acceptance:** no published page lists UDAP's implemented flows without the authorization code flow.

### G-02: Release-scope omissions for the v0.6.0 headline feature (same class as v0.5.0 F-03)
- **Files and lines:**
  - `README.md:8`: the intro lists "discovery, certificate-backed Dynamic Client Registration, and B2B `client_credentials` access tokens" and omits the authorization code flow.
  - `README.md:265`: the demo paragraph omits the UDAP authorization code workflow added in #391.
  - `docs/index.md`:
    - `:6` front-matter `description`;
    - `:13` intro;
    - `:21` quick-nav UDAP row ("discovery, certificate-backed Dynamic Client Registration, and B2B client credentials");
    - `:63-65` demo blurb, which omits the UDAP authorization code workflow.
  - `docs/configuration/index.md`:
    - `:58-60`: "`certificate_chain` and the UDAP algorithm values are used by `register_client`, `#cancel_registration`, and `#request_backend_token`". It omits `#request_access_token` and `#refresh_token`.
    - `:45`: the `redirect_uri` row says "required for App Launch flows" and omits that it is also required by UDAP `authorization_url`/`request_access_token`.
  - `docs/adr/ADR-016-udap-authentication-token.md:145-146`: Consequences says the AnT is built by `request_backend_token` for client_credentials only. It is also built by `request_access_token` and `refresh_token`.
- **Expected:** every summary of UDAP capability names the authorization code flow with refresh, matching the CHANGELOG, gemspec, `udap.md` intro, `client-setup.md:74` and the `docs/index.md:48` features bullet.
- **Repro:** `grep -n "Dynamic Client Registration" README.md docs/index.md`, then read the demo paragraphs. Also `sed -n 56,60p docs/configuration/index.md` and `sed -n 140,147p docs/adr/ADR-016*`.
- **Fix:**
  - Add "and the authorization code flow (with refresh)" to each summary.
  - Add "UDAP authorization code launch, callback, and refresh" to both demo blurbs.
  - Extend the config sentence and the `redirect_uri` row.
  - Extend ADR-016 Consequences to name `request_access_token`/`refresh_token`.
- **Acceptance:** `grep -n "Dynamic Client Registration" README.md docs/index.md`: every summary line also names the authorization code flow. Both demo blurbs name it.

### G-03: SMART "token request" citation links to the discovery `Request` section
- **Files:**
  - `docs/adr/ADR-015-client-role-and-runtime-readiness.md:117`;
  - `docs/smart-on-fhir/backend-services/token-request.md:41`.
  Both are new in #359.
- **Expected:** the link labelled "SMART STU2.2 token request" targets the token request section (the `scope` "required" row is at backend-services.md:134).
- **Actual:** `backend-services.html#request`. The source has two `#### Request` headings:
  - line 72, under "Retrieve `.well-known/smart-configuration`";
  - line 110, under "Obtain access token".
  Kramdown auto-ids give the first `request` and the second `request-1`. The source also defines an explicit `<a id="step-3-access-token">` at line 83.
- **Repro:** `grep -nE "^#+ |id=\"step" /tmp/specs/smart-ig/input/pages/backend-services.md`.
- **Spec:** SMART 2.2.0 backend-services.md token request table: `scope` is "required".
- **Fix:** use `https://hl7.org/fhir/smart-app-launch/STU2.2/backend-services.html#step-3-access-token` in both places.
- **Acceptance:** `grep -rn "backend-services.html#request" docs lib` returns nothing.
- **Limitation:** hl7.org was not fetched. The conclusion comes from the IG source's heading order and explicit anchors.

### G-04: Stale or inaccurate statements about the removed fallback and Tiered OAuth
- **`examples/sinatra_app/README.md:292-293`:** "so it never relies on Safire's deprecated implicit Backend Services fallback". The fallback no longer exists in v0.6.0. Suggested wording: "…matching Safire, which raises `ConfigurationError` without scopes since v0.6.0".
- **`lib/safire/client.rb:17-18` (public YARD):** "SMART Backend Services callers should must configure or pass scopes explicitly" has a doubled modal. Drop "should".
- **`lib/safire/protocols/udap.rb:21-22` ("Tiered OAuth raises +NotImplementedError+") and `docs/adr/ADR-015…md:174-176` ("UDAP Tiered OAuth … raise `NotImplementedError` through the shared protocol contract"):**
  - Actual: there is no Tiered OAuth entry point. `client.authorization_url(idp: …)` raises `ArgumentError: unknown keyword: :idp` (`verify_authz.out`). `NotImplementedError` applies only to `token_response_valid?` (UDAP) and SMART `cancel_registration`.
  - Fix: "Tiered OAuth (`idp:`) is not implemented" in both places. Keep `NotImplementedError` for the two methods it really covers.
- **Acceptance:** `grep -rn "should must\|deprecated implicit\|Tiered OAuth raises" lib docs examples` returns nothing.

No runtime defects were found. Implementation, tests, CHANGELOG, `authorization-code.md`, ADR-015 matrix rows, `client-setup.md`, the configuration diagram and the demo all agree with each other and with STU2/SMART for the behavior above.

## Optional enhancements (not blockers)

- **E-1:** the `Client` YARD `{#authorization_url}`, `{#request_access_token}`, `{#refresh_token}`, `{#request_backend_token}` and `{#register_client}` links do not resolve (delegated methods), which gives 6 YARD warnings. Use `{Safire::Protocols::Udap#…}` or `+…+`. This continues v0.5.0 E-F3.
- **E-2:** formatting.
  - The ADR-015 matrix rows are separated by blank lines (`:166`, `:170`). Kramdown renders them as header-less extra tables, and GitHub renders them as raw pipe text. The v0.5.0 `request_backend_token` row already did this.
  - In `docs/index.md:45-49` a blank line splits the UDAP feature list into two lists.
- **E-3:** `ROADMAP.md:119` has a grammar slip: "…B2B client credentials implemented; and authorization code flows with refresh implemented; …".
- **E-4:** fallback history wording is inconsistent.
  - `smart.rb:197-198`, `token-request.md:47` and ADR-015:119 say "v0.4.x and v0.5.x".
  - README, `client.rb` and `docs/configuration/index.md` say "v0.4.1–v0.5.x".
  - In fact the fallback existed since 0.2.0 (CHANGELOG:257) and the deprecation warning since 0.4.1. Harmonize to "fallback (deprecated since v0.4.1)".
- **E-5:** CHANGELOG `[Unreleased]` omits two warning-only behaviors that ADR-015 and `authorization-code.md` document: the refresh `grant_types_supported` warning, and that authorization-code token readiness hard-fails like client_credentials (`udap_authn`, grant, `private_key_jwt`).
- **E-6:** in `docs/configuration/index.md:55-56`, the `authorization_endpoint`/`token_endpoint` rows say "Override the discovered endpoint". For UDAP they are ignored in favor of signed metadata, as `authorization-code.md:77` says.
- **E-7:** `authorization-code.md:16-17` says "the same facade methods as SMART", but the scope keyword differs: SMART uses `custom_scopes:` and UDAP uses `scopes:`. A one-line note would prevent `ArgumentError` for protocol switchers.
- **E-8:** the `ClientConfig` HTTPS error text says "SMART App Launch 2.2.0 requires TLS" even for `protocol: :udap` `redirect_uri`. This is pre-existing.
- **E-9:** the demo validates empty Backend Services scopes itself, so Safire's v0.6.0 `ConfigurationError` text is never shown there. That is fine; optionally mention the breaking change in the demo README.
- **Carried from v0.5.0:**
  - E-F1, E-F2, E-F4–E-F9 are unchanged. E-F7 is the confusing "received fields: access_token" text for a blank access token. E-F8 is that CI audits only the root lock.
  - E-14 is unchanged: the gem ships `docs/`, `.claude/` and `gemfiles/`, now 108 files.

## Release-prep items for 6.R (not defects at this commit)
- Bump `VERSION` to 0.6.0 and convert `[Unreleased]` to `[0.6.0] - <date>`.
- Re-lock the demo and the AS 7.1 lock to `safire (0.6.0)`.
- Clear the ROADMAP "on `main`, unreleased" markers at `:25`, `:57` and `:67`.
- D-21 (AS 7.1 advisories) is still a maintainer decision.

## Verified as matching (no action)
- **Plan decisions:**
  - D-12: one implementation; no `flow:` option.
  - D-13 revised: authorization warns, refresh and token requests hard-fail.
  - D-14: `state` returned and compared by the app; docs carry the §7.2.1 quote and a constant-time example.
  - D-16: breaking `ConfigurationError` with `[:scopes]` before any HTTP call; migration `scopes: ['system/*.rs']` documented in CHANGELOG, README, `backend-services/index.md`, `token-request.md`, troubleshooting and ADR-015.
  - D-20: no `extensions` by default; `hl7-b2b` rejected; required extensions only warn.
- **Breaking-change notice:** CHANGELOG `### Removed` has "**Breaking:**", the exact exception, the attribute, the timing (before HTTP) and the migration. No doc still promises the fallback, apart from the G-04 demo README wording.
- **Supported specs and compatibility:** SMART 2.2.0, UDAP STU2 2.0.0, Ruby ≥ 3.2, ActiveSupport ≥ 7.1 < 9. The suite passes on both the AS 7.1 floor and the current lock.
- **Release scope:** Tiered OAuth is described as planned or not implemented in README, docs index, `udap.md`, `authorization-code.md`, `b2b-client-credentials.md`, `client-setup.md`, the config diagram, `client.rb` and ROADMAP (v0.7.0). There is no `idp:` parameter. The gemspec description is accurate.
- **`authorization-code.md` cross-checks:**
  - Section citations §4.1/§4.2.2/§4.3/§5.1/§5.2.1/§5.2.2.1/§5.3/§7.2/§7.2.1/§7.3/§7.5.5/§7.5.6 and Discovery §2.2 match the heading order.
  - The discovery-readiness table matches `UdapAuthorizationRequestReadiness`.
  - The error-handling classes match the runtime.
  - The `ClientConfig` `redirect_uri` claim (HTTPS, no fragment, loopback only with the flag) is verified.

## Not run / limitations
- **No live servers.** There was no real UDAP or SMART authorization server, consent UI or trust-community policy. All checks used WebMock or a local fake server, with real X.509 and signed-metadata validation (harness `verify_chain: true` with CA and CRL). The demo ran in development trust mode (`verify_chain: false`).
- **Inferno UDAP suite** was not re-run on this stack. The v0.5.0 evidence does not cover the authorization code flow.
- **Demo setup:**
  - `bin/demo` itself was not run (port 4567 is reserved). Its steps were run manually (`bundle install`, `setup_env.rb`, puma on 4652).
  - Demo UDAP registration was not exercised for authorization_code (the client ID was seeded in `data/servers.yml`).
  - The SMART App Launch authorization flows were not re-exercised in the demo.
- **Rendering:** the YARD HTML and the Jekyll site were not visually inspected.
- **External text:** hl7.org, udap.org and RFC text were not fetched; the IG source at the release tags was used. G-03's anchor conclusion is derived from source headings.
