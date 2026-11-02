# Safire v0.7.0 pre-release alignment audit (combined stack)

> **Point-in-time snapshot.** `/tmp/audit/...` paths were sandbox scratch files; commands and outputs are quoted inline. Finding status is tracked in [README.md](README.md).

- **Inspected commit:** `origin/docs/v0.7.0-release-notes`, checked out detached at
  `98f168a40dab78d4451f1d13d1a95618b79f07de` ("Consolidate v0.7.0 release notes and docs"), the expected `98f168a`.
  It contains release-0.6.0 (#400, including the v0.5.0 and v0.6.0 stacks) plus #392 (`authorization_url(idp:)`),
  #394 (demo IdP field, `invalid_idp`), and the v0.7.0 release notes. The incremental diff against `origin/release-0.6.0` touches 27 files (+1015/−38).
- **Mode:** read-only. No repository files were changed and nothing was pushed. Generated artifacts were removed:
  `.yardoc/`, `docs/api/`, `docs/.jekyll-cache/`, the demo `.env` and `data/`, `spec/examples.txt`, `/tmp/site-v7`, and the built gem.
  `git status --short --ignored` is empty. The demo `Gemfile.lock` was unchanged by `bundle install` (compared with `cmp`).
- **Plans:** `.github/plans/v0.7.0.md` and `decisions.md` D-15 (client side only), read from `origin/docs/roadmap-execution-plan`.
- **Specs:** UDAP STU2 `user.md` (§6 Tiered OAuth: §6.1 client request, §6.2 data holder ↔ IdP, §6.3 after authentication) and `discovery.md` §2.2 (Required UDAP Metadata).
- **Scratch files and logs:**
  - `/tmp/audit/v7/`: `rspec.log`, `as71.log`, `rubocop.log`, `audit-{root,demo,as71}.log`, `yard.log`, `jekyll.log`, `linkcheck.out` (empty, meaning no broken links), `demo-install.log`, `gemx/files.txt`.
  - `/tmp/audit/v7scratch/`:
    - `verify_tiered.rb` and `.out`: wire checks with the real PKI from `fscratch/pki.rb` and WebMock.
    - `fake_tiered.ru`: a fake server that advertises `udap_to` and the `udap` scope and has an `invalid_idp` mode. Its log is `fake_tiered.log`.
    - `probe_demo.sh` and `.out`, `demo.server.log`, and `quotes.out`.

## Check results

| Check | Command | Result |
|---|---|---|
| Full suite | `bundle exec rspec` | **1804 examples, 0 failures** (v0.6.0: 1735) |
| AS 7.1 floor | `BUNDLE_GEMFILE=gemfiles/activesupport_71.gemfile bundle exec rspec` | **1804 examples, 0 failures** |
| Demo specs | `bundle exec rspec spec/examples` | 204 examples, 0 failures (v0.6.0: 193) |
| New and changed Tiered specs | `udap_tiered_authorization_request_spec`, `udap_authorization_url_spec`, `udap_authorization_request_readiness_spec` | 108 examples, 0 failures |
| Lint | `bundle exec rubocop` | 107 files, no offenses |
| Advisories (root) | `bundler-audit check --update` | **FAIL: 7 advisories on addressable 2.9.0** (H-01). The DB moved from 92c25ce to 79c0e05 (2026-11-01). |
| Advisories (demo) | `--gemfile-lock examples/sinatra_app/Gemfile.lock` | No vulnerabilities (addressable 2.9.2) |
| Advisories (AS 7.1) | `--gemfile-lock gemfiles/activesupport_71.gemfile.lock` | activesupport 7.1.6 has CVE-2026-33169/33170/33176 (the known D-21 exception). **Plus the same 7 addressable 2.9.0 advisories** (H-01). |
| YARD | `bin/docs` | Exit 0, 82.37% documented. The 4 ATTRIBUTES warnings and 6 unresolved `{#…}` links in `client.rb` are unchanged (E-1 from v0.6.0). The new `{UdapTieredAuthorizationRequest}` and `{UdapAuthorizationRequestReadiness}` links resolve. |
| Jekyll | `cd docs && bundle exec jekyll build -d /tmp/site-v7` | Exit 0, no warnings. `udap/tiered-oauth/` is built (nav_order 4 under UDAP). |
| Link check | `ruby -E UTF-8 /tmp/audit/scratch/linkcheck.rb /tmp/site-v7` (after `bin/docs`) | **0 broken internal links or anchors** |
| STU2 anchors | The 21 unique `udap-security/STU2/*.html#…` anchors in lib/docs/README/CHANGELOG/demo | All exist. The new `user.html#client-authorization-request-to-data-holder`, `#data-holder-authentication-request-to-idp` and `#data-holder-interaction-with-user-after-authentication` match the user.md headings. |
| Spec quotes | `fscratch/quotes.rb` over the new and changed docs, YARD and demo README, plus manual comparison | All Tiered quotes are exact. The single "MISS" is only the `[Section 4.1.2.1 of RFC 6749]` reference-link brackets. The other misses are pre-existing non-IG strings. |
| Gem build | `gem build safire.gemspec` | `safire-0.6.0`, **110 files**: the v0.6.0 list plus `docs/udap/tiered-oauth.md` and `lib/safire/protocols/udap_tiered_authorization_request.rb`. No `spec/`, `examples/` or `compliance/`. `docs/`, `.claude/` and `gemfiles/` still ship (E-14). |
| Version | `Safire::VERSION` | `0.6.0`, as expected before 7.R. CHANGELOG has `[Unreleased]`. All three locks pin `safire (0.6.0)`. |

## Wire behavior of `authorization_url(idp:)` (real PKI and signed metadata, only HTTP stubbed; `verify_tiered.out`)

- **Request shape (STU2 §6.1):** with `idp: 'https://idp.example.com/oidc'` the GET URL has exactly
  `client_id, code_challenge, code_challenge_method=S256, idp, redirect_uri, response_type=code, scope, state`.
  - `scope` is `openid fhirUser patient/Patient.rs udap`: `udap` is appended once and the order is kept.
  - `idp` is percent-encoded and decodes to the exact input.
  - PKCE, `state` and the signed endpoint are the same as in v0.6.0. An existing endpoint query (`?tenant=a`) is preserved. 0 POSTs.
- **Scope handling:**
  - `udap` already present (`scopes: %w[udap openid]`) is not duplicated.
  - A configured duplicate `%w[udap udap openid]` is collapsed by the existing normalization to `udap openid`.
  - A String `scopes:` is accepted.
  - `idp: nil` or no `idp` produces the exact v0.6.0 request: no `udap` scope and no Tiered readiness check.
- **Invalid `idp` raises `ValidationError` with `attribute == :idp` and 0 HTTP requests, before discovery:**
  - Integer, Symbol or `URI` object: `must be a String`.
  - `''`, spaces only, relative, no scheme, `https://` or `https:///path`: `must be an absolute URL`.
  - `http://`, `ftp://`, uppercase `HTTPS://`, or HTTP localhost without the flag: `must use HTTPS`.
  - `#frag` or an empty `#`: `must not include a fragment`.
  - The message never contains the value, and the logs never contain the IdP.
- **Check order:**
  - A missing `client_id` raises `ConfigurationError` before `idp` is checked.
  - An invalid `idp` is reported before missing scopes.
  - Both checks happen before any network request.
- **Localhost flag:** with `allow_insecure_localhost: true`, `http://localhost:9000/oidc` and `http://127.0.0.1:9000` are accepted. `http://[::1]` and other HTTP hosts are rejected. This matches the docs, which name only `localhost` and `127.0.0.1`.
- **Readiness (discovery §2.2, user §6.1; a fresh client per case because discovery is cached per instance):**
  - **No `udap_to`** (including when only signed metadata carries it): `DiscoveryError` "server does not advertise the udap_to profile in udap_profiles_supported".
  - **No `"udap"` in `scopes_supported`**, or the value is absent, empty, or a String: `DiscoveryError` "…udap scope in scopes_supported".
  - **Both missing:** the profile is reported first.
  - **Without `idp`:** every one of these servers still succeeds, with only the existing value-free warnings. Standard requests do not regress.
  - **Unadvertised wildcard with `idp`:** the existing count-only warning appears and the request proceeds.
- **Other behavior:**
  - `server_metadata(...).supports_tiered_oauth?` is `true` on a `udap_to` server.
  - SMART `authorization_url(idp:)` raises `ArgumentError: unknown keyword: :idp`. The docs scope the keyword to UDAP.
  - Token exchange after a Tiered request sends no `idp`. Its form keys are unchanged from v0.6.0. An `id_token` is returned as-is (not validated, as documented).
- **Release scope (D-15):**
  - Every file describes the feature as client side only. `tiered-oauth.md` has a scope table, and the following all say data holder ↔ IdP (§6.2–6.3) is out of scope: Limitations, CHANGELOG, ROADMAP, `client.rb`, `udap.rb`, `UdapTieredAuthorizationRequest`, ADR-015 and the gemspec ("including client-side Tiered OAuth").
  - Nothing claims IdP discovery, IdP registration, or ID token validation.

## Demo (puma on 127.0.0.1:4788; fake server on 4769; development trust mode; `probe_demo.out`)

- **Requests:**
  - **Preferred IdP set:** 303 to the authorization endpoint with `idp` and `scope=openid patient/Patient.rs udap`. The callback exchanged the code and the page masks tokens.
  - **Blank IdP:** a standard request, with no `idp` and no `udap`.
  - **Whitespace around the IdP:** trimmed. `udap`, which was already in the scope field, is not duplicated.
- **Errors on the start page (200, no redirect):**
  - An invalid IdP (HTTP, fragment, relative) shows `Validation failed for idp: …`.
  - A server without `udap_to` shows the `DiscoveryError` text.
- **`invalid_idp`:** the data holder returned `error=invalid_idp`. The callback checks `state` first (`app.rb:541`), then shows "The data holder rejected the preferred IdP (Tiered OAuth). No token was requested." plus retry guidance. No token request was made.
- **Escaping:** the reflected IdP value with `"><script>` is HTML-escaped (0 raw occurrences).
- **Logs:** the demo log has no IdP values, codes or tokens.

## Spot-check of earlier findings

| ID | Status at 98f168a |
|---|---|
| B-01…B-13 | Still fixed. Re-grepped: no `exchange_code_for_token` or `ssl_options` in docs/README (only in the generated internal `HTTPClient` API page). 0 broken links. B-11: the demo lock audits clean and is unchanged by install. **The root and AS 7.1 locks now fail on addressable (H-01).** |
| F-01 | Still fixed (no `5.2.3` citation) |
| F-02/F-03 | Still fixed. ADR-016:145-147 names all three AnT builders. |
| G-01 | Fixed (`docs/udap.md:6` and `:215` name the authorization code flow and now Tiered OAuth) |
| G-02 | Fixed: README:8 and :271, `docs/index.md:6/14/23`, `docs/configuration/index.md:45/58-60`, ADR-016. See E-3 for v0.7.0 summary wording. |
| G-03 | Fixed (`backend-services.html#request` is gone) |
| G-04 | Fixed (`should must`, `deprecated implicit` and `Tiered OAuth raises` are gone) |

## Confirmed defects (release blockers)

### H-01: Root and AS 7.1 lockfiles pin addressable 2.9.0 with 7 new advisories; CI's `bundler-audit check --update` fails
- **Files and lines:**
  - `Gemfile.lock:27` (`addressable (2.9.0)`);
  - `gemfiles/activesupport_71.gemfile.lock:27` and `:209`.
  - The demo lock already has 2.9.2.
- **Expected:** root `bundler-audit check --update` passes. `.github/workflows/ci.yml:46` runs exactly this, so it is a CI gate. The only allowed AS 7.1 exception is D-21 (activesupport).
- **Actual:** GHSA-4w5q-wg7v-w6gp, -539f-xcgw-2gjg, -8gmh-2hhj-2hv9, -9crm-g4mf-wc5j, -9f42-57jx-vpp3, -j82w-28jv-3pmj and -qq38-m9mg-xjj5, all "update to >= 2.9.1".
  - They cover template ReDoS, `display_uri` spoofing, and path-normalization issues.
  - They were published after the v0.6.0 audit (advisory DB 79c0e05, 2026-11-01).
- **Safire exposure:** low. `lib/` only uses `Addressable::URI.parse`, `host`, `scheme`, `path`, `fragment` and `query_values=`. No templates, `normalize` or `display_uri`. The gate still fails.
- **Repro:** `bundle exec bundler-audit check --update`, and `--gemfile-lock gemfiles/activesupport_71.gemfile.lock`.
- **Fix:** `bundle update addressable --conservative`, then `BUNDLE_GEMFILE=gemfiles/activesupport_71.gemfile bundle update addressable --conservative`. Both resolve to 2.9.2 within the gemspec's `~> 2.8`. This can be folded into 7.R's re-lock.
- **Optional, maintainer call:** raise the gemspec floor to `'~> 2.8', '>= 2.9.1'`.
- **Acceptance:**
  - The root audit reports "No vulnerabilities found".
  - The AS 7.1 audit lists only the D-21 activesupport CVEs.
  - Both suites stay green.

### H-02: `docs/udap/tiered-oauth.md` registration example fails at runtime
- **File:** `docs/udap/tiered-oauth.md:53-59` (Prerequisites, "Register with the `udap` scope").
- **Expected:** the example registers an authorization-code client with `udap` in `scope`.
- **Actual:**
  - Run as written (real PKI, WebMock), it raises `ValidationError: Validation failed for contacts: is required`.
  - Adding `contacts` then raises `Validation failed for logo_uri: is required for authorization_code`.
  - With both added (and a `client_uri` matching the certificate SAN), the software statement carries `scope: "openid fhirUser patient/Patient.rs udap"` and `response_types` as intended.
- **Spec:** registration.md (§3), software statement table.
  - `contacts`: "required … The array **SHALL** contain at least one valid email address using the mailto scheme".
  - `logo_uri`: "If grant_types includes "authorization_code", client applications **SHALL** include this field".
- **Repro:** the `doc register_client` and `register + contacts` cases in `/tmp/audit/v7scratch/verify_tiered.out`.
- **Fix:** add `contacts: ['mailto:ops@app.example.com'], logo_uri: 'https://app.example.com/logo.png'` to the metadata Hash. Optionally also add `refresh_token` to `grant_types` if the client wants refresh.
- **Acceptance:** the example, copied verbatim with a matching certificate, POSTs a registration whose software statement contains `udap` in `scope`.

### H-03: ROADMAP compatibility row misstates UDAP coverage
- **File:** `ROADMAP.md:120`: "…JWT client authentication, and B2B client credentials authorization code flows with refresh, and client-side Tiered OAuth implemented".
- **Expected:** two separate features, matching README:8 and `docs/udap.md:215`.
- **Actual:** a missing comma or conjunction turns this into one non-existent feature, "B2B client credentials authorization code flows". The row was edited in #394/release notes, and the same row was already the subject of v0.6.0 E-3.
- **Repro:** `sed -n 120p ROADMAP.md`.
- **Fix:** "…JWT client authentication, B2B client credentials, authorization code flows with refresh, and client-side Tiered OAuth implemented".
- **Acceptance:** the row lists B2B client credentials and authorization code as separate items.

No runtime defects were found in `authorization_url(idp:)`. It matches STU2 §6.1 (the `udap` scope is added once, `idp` is set to the given base URL) and the documented D-15 readiness choices. Invalid input fails before any network request without leaking the value. The demo and the documentation agree with it.

## Optional enhancements (not blockers)

- **E-1: `idp` validation is lenient** (all of it is Safire's implementation choice; the OIDC text was not fetched).
  - It accepts values that are not valid URLs, such as `https://idp.example.com/ x` or `"`/`<`/`>` characters (Addressable is lenient). The values are percent-encoded on the wire, so nothing can be injected.
  - It accepts userinfo (`https://user:pw@idp…`) and query components.
  - OIDC issuer identifiers have no query or fragment (OIDC Core §2 / Discovery §2).
  - Possible fix: reject whitespace and control characters, userinfo and query. Also mention the query case in the `tiered-oauth.md` validation table.
- **E-2: `tiered-oauth.md:135-137` fallback hint.** `supports_tiered_oauth?` checks only `udap_to`. A server can pass that check and still fail on the missing `udap` scope. Suggest also checking `scopes_supported.include?('udap')`, or rescuing `DiscoveryError`.
- **E-3: v0.7.0 summaries.** README:8, README:271 (demo blurb), `docs/index.md:6/14/23` and the `docs/index.md` demo blurb do not name Tiered OAuth.
  - These lines are still accurate, because Tiered OAuth is an option of the authorization code flow they already name. That is why this is not filed as G-02-class.
  - Adding "(including client-side Tiered OAuth)" and "optional preferred IdP" to the demo blurbs would match the gemspec and `docs/udap.md`.
- **E-4: ADR-015 Operation Matrix row "UDAP `authorization_url"`** does not list the invalid `idp` `ValidationError` or the `udap_to`/`udap` `DiscoveryError` as runtime hard failures. The footer sentence at `:176-178` does. Add them to the row for completeness.
- **E-5: the `invalid_idp` cause is stated too narrowly.**
  - The demo message (`udap_authorization.erb`: "does not trust that IdP or cannot obtain a client_id for it") and `auth-errors.md` "Cause" give only the first §6.2 trigger.
  - §6.2 also allows `invalid_idp` when the IdP returns no or an invalid ID token or an error response.
  - Suggest "for example, …".
- **E-6: `tiered-oauth.md:171` example `halt 400, params[:error]`** returns the unescaped error as an HTML body. It is mitigated because `state` is checked first, and the demo escapes it. Prefer `halt 400, 'authorization error'` or `Rack::Utils.escape_html`.
- **E-7: formatting.**
  - `docs/index.md:45-52`: blank lines split the UDAP features into three lists (continues v0.6.0 E-2).
  - ADR-015 matrix rows separated by blank lines (v0.6.0 E-2) are unchanged.
- **E-8: demo README (`examples/sinatra_app/README.md`, "Errors shown on the start page")** says HTTP IdPs are accepted "when the demo runs with a loopback callback". The demo enables the flag when either the server base URL or the redirect URI is HTTP loopback (`app.rb:105`).
- **Carried, unchanged:**
  - v0.6.0 E-1 (6 YARD link warnings) and E-4–E-9.
  - v0.5.0 E-F1/F2/F4–F9. E-F8 is that CI audits only the root lock, which is why AS 7.1 addressable would not be caught by CI.
  - E-14: the gem ships `docs/`, `.claude/` and `gemfiles/`, now 110 files.

## Release-prep items for 7.R (not defects at this commit)
- Bump `VERSION` to 0.7.0 and convert `[Unreleased]` to `[0.7.0] - <date>`.
- Re-lock the demo and AS 7.1 to `safire (0.7.0)`, picking up addressable 2.9.2 (H-01).
- Clear the ROADMAP marker at `:60` ("on `main`, unreleased").
- D-21 (activesupport 7.1.6 advisories) is still a maintainer decision.

## Verified as matching (no action)
- **v0.7.0 plan:**
  - 7.1: the `udap` scope and `idp` are added; `idp` must be absolute HTTPS; `udap_to` and `"udap"` readiness raises `DiscoveryError`.
  - 7.2: the registration SHALL is documented (README, `tiered-oauth.md`, `udap.rb` YARD, demo README and form hint); `invalid_idp` handling is documented in `tiered-oauth.md`, `auth-errors.md` and the demo.
  - 7.3: the demo has the IdP field and a dedicated `invalid_idp` message.
  - 7.4: CHANGELOG, ROADMAP, README and docs describe the client side only. The ROADMAP "identity chaining" wording was replaced (D-15).
- **Spec citations:**
  - §6.1 is cited for the scope and `idp` additions, the data-holder `scopes_supported` SHALL, the registration SHALL, and the iss/base-URL definition.
  - §6.2 is cited for `invalid_idp` and the client MAY retry. §6.3 is cited for `access_denied`.
  - Discovery §2.2 is cited for `udap_to`.
  - Every quote is exact. Hard-fail readiness is labelled as an implementation choice, and the OIDC text is labelled as not fetched.
- **Compatibility:** behavior without `idp` is unchanged (the v0.6.0 suites pass). The token exchange and refresh carry no Tiered parameters.
- **Gemspec:** the description is accurate, and the gem includes the new page and class.

## Not run / limitations
- **No real servers.** There was no real UDAP data holder, IdP or consent UI. All checks used WebMock or the local fake server. X.509 and signed-metadata validation were real in the harness (`verify_chain: true`). The demo ran in development trust mode.
- **Not run:**
  - The Inferno UDAP suite (it has no Tiered OAuth client coverage in the prior evidence either).
  - `bin/demo` itself, because port 4567 is reserved. Its steps were run manually.
  - The demo UDAP registration form with `udap` in scope (the client ID was seeded).
- **External text:** hl7.org, OIDC, RFC and udap.org text was not fetched; the IG source at the 2.0.0 tag was used.
- **Rendering:** the YARD HTML and the Jekyll site were not inspected visually.
- **H-01 fix:** not applied. The suites were not re-run against addressable 2.9.2 (the demo lock already uses 2.9.2, and its 204 specs pass).
