# Safire v0.5.0 feature audit: combined stack (UDAP B2B client credentials)

> **Point-in-time snapshot** of the feature audit at `b19a92f`. `/tmp/audit/...` paths were sandbox scratch files; commands and outputs are quoted inline.

- **Inspected commit:** `origin/docs/v0.5.0-release-notes` (draft PR #379), checked out detached at
  `b19a92f8a19f413843f19867573597ad4f008559` ("Merge fix/refresh-demo-and-ci-lockfiles"). This is the expected `b19a92f`.
- **Mode:** read-only. No repository files were changed and nothing was pushed. Generated artifacts were removed: `.yardoc/`, `docs/api/`, `docs/.jekyll-cache/`, the demo `.env` and `data/`, the built gem, and `/tmp/site-579`. The worktree is clean apart from the ignored `spec/examples.txt`. The demo `Gemfile.lock` was unchanged by `bundle install`.
- **Scratch files and logs:**
  - `/tmp/audit/fscratch/`:
    - `pki.rb`: a real CA, server and client PKI with WebMock stubs. Signed metadata is really validated, not stubbed.
    - `verify_b2b_docs.rb`, `verify_alg.rb`, `quotes.rb`, `fake_udap.ru`, `probe_token.sh`.
    - Outputs: `*.out`, `fake_udap.log`, `demo.server.log`.
  - `/tmp/audit/f-*.log`: rspec, rubocop, yard, jekyll, bundler-audit.
  - `/tmp/audit/f-linkcheck.out`.
  - `/tmp/audit/fgem/*.txt`: gem file lists.
- **Specs:**
  - UDAP Security STU2 `/tmp/specs/udap-ig/input/pagecontent`.
  - SMART 2.2.0 `/tmp/specs/smart-ig/input/pages`.
  - Section numbers are derived from the heading order, per D-17.

## Check results

| Check | Command | Result |
|---|---|---|
| Full suite | `bundle exec rspec` | **1544 examples, 0 failures** (baseline 1395) |
| Demo specs | `bundle exec rspec spec/examples` | 160 examples, 0 failures (baseline 137) |
| Lint | `bundle exec rubocop` | 95 files, no offenses |
| Advisories (root) | `bundle exec bundler-audit check --update` | No vulnerabilities (db 92c25ce, 2026-10-31) |
| Advisories (demo) | `bundler-audit check --gemfile-lock examples/sinatra_app/Gemfile.lock` | **No vulnerabilities** |
| Advisories (AS 7.1) | `bundler-audit check --gemfile-lock gemfiles/activesupport_71.gemfile.lock` | activesupport 7.1.6: CVE-2026-33169/33170/33176. No 7.1.x fix exists. This is the documented exception D-21 (open maintainer decision). |
| YARD | `bin/docs` | Exit 0, 81.95% documented. The 4 pre-existing `Undocumentable ATTRIBUTES` warnings remain. There are **2 new** warnings: `client.rb:48` cannot resolve `{#request_backend_token}` and `client.rb:54` cannot resolve `{#register_client}` (E-F3). |
| Jekyll | `cd docs && bundle install && bundle exec jekyll build -d /tmp/site-579` | Exit 0, no warnings |
| Link check | `ruby -E UTF-8 /tmp/audit/scratch/linkcheck.rb /tmp/site-579` | **0 broken internal links or anchors.** The script needs `-E UTF-8` and fails with an encoding error without it. |
| STU2 anchors cited | headings in the spec source | All 10 cited `udap-security/STU2/*.html#…` anchors exist |
| Spec quotes | `/tmp/audit/fscratch/quotes.rb` plus manual grep | Every quoted SHALL/SHOULD/MAY phrase matches the STU2 text. One **section number** is wrong (F-01). |
| Gem build | `gem build safire.gemspec` | `safire-0.4.1.gem`, 106 files. **No `compliance/`.** Two files are new compared with the baseline: `docs/udap/b2b-client-credentials.md` and `lib/safire/protocols/udap_token_request_readiness.rb`. `.claude/skills/…`, `docs/`, `gemfiles/` and the Gemfiles are still shipped (pre-existing E-14). |
| Version | `ruby -Ilib -e "require 'safire'; puts Safire::VERSION"` | `0.4.1`, as expected before 5.R |
| Runtime vs Inferno evidence | `git diff 51d6210 b19a92f -- lib` | Comment-only changes, so the external Inferno UDAP run on `51d6210` covers the same runtime code |

## Part A: baseline findings B-01 to B-13

| ID | Issue | Status | Evidence |
|---|---|---|---|
| B-01 | #360 | **Resolved in stack** | `advanced.md` contains no `exchange_code_for_token`, positional `refresh_token(hash)`, `/timeout/` branch, or HTTPClient claim. The retry example rescues `NetworkError`/`TokenError`, and line 180 warns that authorization codes are single-use. `/tmp/docfix/verify_b1*.rb` passes on this commit: cache, TokenManager, retry (3 POSTs; `invalid_grant` is not retried), and registry examples. |
| B-02 | #361 | **Resolved** | `token-exchange.md` "Missing credentials" rescues `ConfigurationError` and documents `missing_attributes`. `verify_b2.rb` gives `[:configuration_error, "Configuration missing: kid", [:kid]]` and 0 POSTs. |
| B-03 | #362 | **Resolved** | The mermaid diagram says `exp: now + 300 s (max 5 minutes)`. `client-errors.md:281` says Safire "sends no `iat` claim". The actual claims are `iss,sub,aud,exp,jti`. |
| B-04 | #363 | **Resolved** | `discovery/index.md` moves the timeout case to `rescue NetworkError`. `dcr/response.md` lists 4 classes, including `ConfigurationError`, and comments that an unreachable server raises `NetworkError`. `verify_b2.rb` shows `[register http endpoint] ConfigurationError` and `[register unreachable] NetworkError`. |
| B-05 | #364 | **Resolved** | `{% link %}` is used for client-setup and logging, and the anchor is fixed. The link check reports 0 problems. |
| B-06 | #365 | **Resolved** (docs) | README, CHANGELOG and `client-errors.md` now quote the §7.3 item 3 rule and label exact advertisement as Safire's stricter check. Residual (E-F5, not a blocker): the runtime `ValidationError` text says "(UDAP Security STU2 permits requesting a wildcard scope only when it is advertised)", which loosely paraphrases "only if wildcards are specified". |
| B-07 | #366 | **Resolved** | `CONTRIBUTION.md` now has a sign-off bullet (`git commit -s`, trailers allowed). The README now says "including the `Signed-off-by` trailer". |
| B-08 | #367 | **Resolved** | `user_agent` is documented in `configuration/index.md` (Global Configuration), and the page states that TLS/SSL options are not exposed. README and the `security.md` footer no longer mention SSL or `ssl_options`. `verify_b3.rb` shows the UA header is sent and the default is `"Safire v0.4.1"`. |
| B-09 | #368 | **Resolved** | The example config adds `allow_insecure_localhost: Rails.env.development?` with an explanatory note. `verify_b2.rb`: dev with http localhost works; production with http raises `ConfigurationError`; production with https works. |
| B-10 | #369 | **Resolved** | ROADMAP now says "Public Client — PKCE-only authorization code flow (no client authentication)". |
| B-11 | #370 | **Resolved for the demo; AS 7.1 is an accepted exception** | The demo lock audits clean and records `safire (0.4.1)` = VERSION. `bundle install` and `setup_env.rb` left the lock unchanged. The AS 7.1 lock still has 3 activesupport advisories with no 7.1.x fix. This is documented only in `decisions.md` D-21 (coordinator branch), marked open for maintainer decision. Still pending: at 5.R the demo lock must be re-locked to `safire (0.5.0)`. |
| B-12 | #371 | **Resolved** | `client.rb` has no "§8.1 unregistered client" text and no `flow:` `@note`. The grant-by-method contract now documents `request_backend_token` for both protocols and states that authorization code, refresh and Tiered OAuth raise `NotImplementedError`. |
| B-13 | #372 | **Resolved** | The `security.md` rotation example wraps `refresh_token(client_secret:)`. `verify_b1.rb` shows `[rotation …] "via-old"`, 2 POSTs. `authorization.md` and `client-errors.md` (both places) use `supports_symmetric_auth?`/`supports_asymmetric_auth?` and explain how an absent list is treated. |

## Part B: alignment audit of the new v0.5.0 scope

### Verified as matching (no action)

**Wire behavior** (README and docs examples run against real PKI; only HTTP is stubbed, signed metadata is really validated):
- The POST body has exactly `grant_type, scope, client_assertion_type, client_assertion, udap=1`.
- No `Authorization` header and no `client_id`.
- AnT header is `alg,x5c` with the leaf first; the full chain is sent.
- AnT claims are `iss=sub=client_id`, `aud` = signed `token_endpoint` exactly, `iat`, `exp-iat=300`, a fresh `jti` per call, and `extensions.hl7-b2b` with `version:"1"`.
- This matches b2b.md §5.2.1, §5.2.2(.2), and general.md §7.1.3–7.1.5.

**Docs examples run:**
- README B2B example (verbatim, `File.read` of generated PEMs): OK.
- `b2b-client-credentials.md` configuration and request: OK.
- The `extensions:` example plus trust inputs: OK; the extension is sent and a value-free warning is logged.
- The error-handling block: `TokenError` with `error_code=invalid_scope`, status 400.
- The `Client` YARD B2B example is the same shape.

**Input validation before any network request** (0 GETs observed): missing `b2b`, `hl7-b2b` inside `extensions:`, missing scopes, and missing `client_id` all fail first.

**Readiness table matches runtime:**
- `DiscoveryError` cases: `udap_authn` missing, grant missing, `private_key_jwt` missing, empty algorithm list.
- `ValidationError` cases: missing required extension (names the key), unadvertised wildcard.
- `ConfigurationError`: EC key against an RS256-only server.
- Warnings: RS256 absent, `udap_authz` absent, unlisted extension, non-wildcard scope coverage.
- All warnings are value-free; no scope values or key names were seen in the log.

**Other runtime behavior:**
- `TokenError` on a blank or missing `access_token` and on a 500 with a non-JSON body.
- `NetworkError` on timeout.
- Scope string splitting and dedup work, and `scopes: []` falls back to the configured scopes.
- Non-RFC 6749 scope characters raise `ValidationError`.
- An explicit unadvertised `jwt_algorithm` raises `ConfigurationError`.
- A key/cert mismatch raises `CertificateError`.

**hl7-b2b rules match b2b.md §5.2.1.1 and the docs table:**
- `organization_id` must be a URI.
- `purpose_of_use` must have at least 1 entry.
- `consent_reference` requires `consent_policy`.
- `subject_*` without `subject_name` is rejected (labelled as a Safire choice).
- Unknown members are rejected.

**No UDAP authorization code, refresh or Tiered OAuth claimed:**
- README, `docs/index.md`, `udap.md`, `b2b-client-credentials.md`, `client-setup.md`, `configuration/index.md`, CHANGELOG, ROADMAP, the `Udap`/`Client` YARD, ADR-015 and the demo all say these are planned or raise `NotImplementedError`.
- At runtime, `authorization_url`, `request_access_token`, `refresh_token` and `token_response_valid?` all raise `NotImplementedError`.

**CHANGELOG `[Unreleased]`:** Added, Changed and Fixed match the implementation.

**ROADMAP:** the Implemented section, the compatibility row and the planned v0.6.0/v0.7.0 sections are consistent. The "on `main`, unreleased" markers are cleared at 5.R per #336.

**Gemspec summary and description:** accurate.

**ADR-015 matrix row** for UDAP `request_backend_token` matches the runtime classification.

**Demo UDAP token page.** Demo booted on 127.0.0.1:4612 with a local fake UDAP server on 4711 (real signed metadata, development trust mode):
- Success: the access token is masked `xxxx...yyyy (64 characters)`. `refresh_token` shows `[FILTERED]`, and the raw value is absent from the HTML.
- The fake server log confirms the wire shape and the `hl7-b2b` contents.
- Error paths render on the same page with the correct label and message:
  - `invalid_client` and server `invalid_scope`: `TokenError` plus the OAuth code.
  - Unadvertised wildcard, missing or invalid `organization_id`, `consent_reference` without policy: `ValidationError`.
  - Empty `client_id`, empty scope, invalid community: `ConfigurationError`.
  - Server down: `NetworkError`.
- A POST without CSRF returns 403.
- The demo log has no token or assertion values.
- The demo README section matches this behavior.

### New findings: confirmed defects (release blockers under the audit policy; all docs-only, small)

#### F-01: STU2 section mis-citation for "Client application use of access tokens"
- **Files:**
  - `docs/udap/b2b-client-credentials.md:157` ("STU2 b2b §5.2.3: …")
  - `lib/safire/protocols/udap.rb:275` (YARD, "STU2 b2b §5.2.3: …")
- **Expected:** §5.2.4.
- **Actual:** §5.2.3.
- **Repro:** `grep -nE '^#+ ' /tmp/specs/udap-ig/input/pagecontent/b2b.md`. Under "### Obtaining an access token" (5.2), the `####` headings are:
  1. Constructing Authentication Token (5.2.1)
  2. Submitting a token request (5.2.2)
  3. Server processing of token requests (5.2.3)
  4. Client application use of access tokens (**5.2.4**)

  The IG's own "Section 5.2.1.3 below" reference confirms this numbering scheme.
- **Spec:** b2b.md "Client application use of access tokens": "A client application **SHALL** only use an access token in a manner consistent with any assertions made when requesting that token." The quote itself is exact.
- **Fix:** change `§5.2.3` to `§5.2.4` in both places, optionally linking `b2b.html#client-application-use-of-access-tokens`.
- **Acceptance:** `grep -rn "5\.2\.3" lib docs` returns no hits attached to this quote.

#### F-02: ADR-016 says the AnT builder is not wired into token requests
- **File:** `docs/adr/ADR-016-udap-authentication-token.md:145`.
- **Expected:** the Consequences section reflects v0.5.0: `Udap#request_backend_token` builds an AnT per request. ADR-015 was updated in the stack the same way.
- **Actual:** "The builder is not yet wired into token requests."
- **Repro:** `grep -n "not yet wired" docs/adr/ADR-016*`. Compare `lib/safire/protocols/udap.rb#build_authentication_token`.
- **Fix:** replace the line with "The builder is used by `Udap#request_backend_token` for client_credentials token requests", or delete it.
- **Acceptance:** no published doc says the AnT is unused.

#### F-03: Release-scope omissions on the docs home page, README demo blurb, and config reference
These are leftovers from the baseline release-scope checklist. Each statement is incomplete rather than false, but together they under-describe the headline v0.5.0 feature.
- **`docs/index.md`:**
  - Front-matter `description` (line 6) and intro (line 14) still say "discovery and Dynamic Client Registration".
  - Quick-nav UDAP row (line 23): "UDAP Security discovery plus certificate-backed Dynamic Client Registration".
  - Demo blurb (line 60–61): "UDAP signed metadata discovery, and the UDAP registration lifecycle".
- **`README.md:257`:** the demo paragraph omits the UDAP B2B token request.
- **`docs/configuration/index.md`:**
  - The `certificate_chain` row says "for UDAP software-statement signing".
  - Line 58 says "`certificate_chain` and the UDAP algorithm values are used by `Safire::Client#register_client`".
  - Both omit `request_backend_token`. The neighboring `private_key`/`jwt_algorithm` rows were updated.
- **Expected:** these list B2B client credentials alongside discovery and DCR, matching the README intro, `udap.md`, the gemspec and the CHANGELOG.
- **Fix:** add "and B2B client credentials" (or equivalent) to each.
- **Acceptance:** `grep -n "Dynamic Client Registration" docs/index.md` shows every summary line also naming B2B client credentials. The config rows name both software statements and Authentication Tokens.

None of these affects runtime behavior. The code, tests, CHANGELOG, ROADMAP, gemspec and feature pages are aligned.

### Optional enhancements (not blockers)

- **E-F1:** the `b2b-client-credentials.md` "Limitations" bullet says Safire "has not been conformance-tested against an external UDAP authorization server or a certification harness". There is external Inferno udap-security-test-kit v0.12.2 evidence (STU1-graded mock; runtime code identical to this commit). Consider "validated outside CI against the Inferno UDAP client test kit (graded against STU1); no STU2 conformance claim". The current text is conservative, not wrong.
- **E-F2:** the `extensions:` example in `b2b-client-credentials.md` omits trust inputs. Run as written, the default `verify_chain: true` with no anchors raises `DiscoveryError`. Add `trusted_anchors:`/`crls:` or a comment.
- **E-F3:** the `Client` class YARD links `{#request_backend_token}` and `{#register_client}` do not resolve (methods come from `def_delegators`). Use `{Safire::Protocols::Udap#request_backend_token}` or `+request_backend_token+`. These are 2 new YARD warnings.
- **E-F4:** the `Client` YARD key list still says `:private_key`/`:certificate_chain`/`:jwt_algorithm` are for "UDAP software-statement signing" only (`ClientConfig` was updated). `:base_url` says "used for SMART discovery".
- **E-F5:** the `UdapScopeNegotiation::UNADVERTISED_WILDCARD_RULE` runtime message paraphrases STU2 as "only when it is advertised". Consider "(UDAP Security STU2 permits wildcards only if listed in scopes_supported; Safire requires an exact match)". This is the residual from B-06.
- **E-F6:** the `request_backend_token` YARD `@raise ConfigurationError`, the docs keyword table and the error-handling comment do not mention an invalid `community:` URI (it raises `ConfigurationError`).
- **E-F7:** the `blank access_token` error reads "Missing access token in response; received fields: access_token", which is confusing. Consider saying "blank".
- **E-F8:** the CI audits only the root lockfile. Adding `--gemfile-lock` audits for the demo and AS 7.1 locks, with the D-21 exception, is still proposed rather than done.
- **E-F9:** the link-check script needs `ruby -E UTF-8`; consider adding `# encoding` or `File.read(f, encoding: 'UTF-8')` if it is ever committed.
- Baseline E-01–E-14 remain as recorded. E-14 (the gem ships `docs/`, `.claude/`, `gemfiles/`) is unchanged, with 2 more `docs`/`lib` files.

### Open maintainer decisions (not defects)
- D-06: keep the `request_backend_token` name for UDAP B2B.
- D-21: the AS 7.1 floor keeps 3 advisories.
- 5.R: bump VERSION, re-lock the demo to 0.5.0, and clear the ROADMAP "on main, unreleased" markers.

## Not run / limitations
- No real UDAP authorization server and no live services. All B2B checks used WebMock or a local fake server, with real X.509 and signed-metadata validation.
- The Inferno UDAP suite was not re-run on `b19a92f`. Existing evidence is on `51d6210` (runtime-identical; comment-only lib diff). It is graded against STU1, and the attestation tests were not run.
- `bin/demo` was not run itself; port 4567 is reserved. Its steps were run manually: `bundle install` (lock unchanged), `setup_env.rb`, and puma on 4612.
- The demo was exercised with production trust mode off (development mode, `verify_chain: false`). Production trust mode is covered by the harness scripts instead (`verify_chain: true` with CA and CRL).
- The YARD HTML and the Jekyll site were not visually inspected.
- hl7.org, udap.org and RFC text were not fetched; IG source at the release tags was used.
