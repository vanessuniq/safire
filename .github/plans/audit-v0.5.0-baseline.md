# Safire v0.5.0 pre-release alignment audit — baseline (everything except the new UDAP token-request feature)

> **Point-in-time snapshot** of the baseline audit at `ca42bd8`. Paths under `/tmp/audit/` were scratch files in the audit sandbox and are not in the repository; the commands and their outputs are quoted inline. Current status of each finding is tracked in [audit-v0.5.0.md](audit-v0.5.0.md).

- Inspected commit: `origin/integration/v0.5.0` = `ca42bd8f894a29d2e36088eaa85be4f68ea639b5` ("Merge feature/udap-authentication-token into integration/v0.5.0"). Re-checked after the rate-limit interruption: the branch had not moved.
- Mode: read-only audit. No repository files were changed and nothing was pushed. Generated artifacts (docs/api, .yardoc, the demo's .env and data/, the built gem, the demo Gemfile.lock rewrite) were removed or reverted. The worktree is clean apart from the ignored `spec/examples.txt` that rspec writes.
- Scratch scripts and logs: `/tmp/audit/scratch/*.rb`, `/tmp/audit/*.log`, `/tmp/audit/demo-probe.log`, `/tmp/audit/site` (Jekyll output).
- Specs: SMART App Launch 2.2.0 `/tmp/specs/smart-ig/input/pages`; UDAP Security STU2 `/tmp/specs/udap-ig/input/pagecontent`.

## Check results

| Check | Command | Result |
|---|---|---|
| Full suite | `bundle exec rspec` | 1395 examples, 0 failures |
| Demo specs | `bundle exec rspec spec/examples` | 137 examples, 0 failures |
| Lint | `bundle exec rubocop` | 88 files, no offenses |
| Advisories (root) | `bundle exec bundler-audit check --update` | No vulnerabilities (advisory db 92c25ce, 2026-10-31) |
| Advisories (demo lock) | `bundler-audit check --gemfile-lock examples/sinatra_app/Gemfile.lock` | **Vulnerabilities found** (see B-11) |
| Advisories (AS 7.1 CI lock) | `bundler-audit check --gemfile-lock gemfiles/activesupport_71.gemfile.lock` | **Vulnerabilities found** (activesupport 7.1.6, 3 advisories) |
| YARD | `bin/docs` | Exit 0. 81.54% documented. 4 `Undocumentable ATTRIBUTES` warnings (client_config.rb:83, smart.rb:40, udap_metadata.rb:87, smart_metadata.rb:92). The nav patch step says the upstream fix is already present. |
| Jekyll | `cd docs && bundle install && bundle exec jekyll build -d /tmp/audit/site` | Exit 0, no warnings. The internal link check found 5 broken links (B-05). |
| Packaging | `gem build safire.gemspec` | Builds `safire-0.4.1.gem` with 104 files. Contents are covered in E-14. |
| Demo boot | `bundle exec ruby bin/setup_env.rb && bundle exec puma config.ru -p 4599` | Booted. Error paths were probed against `https://unreachable.invalid/fhir`. Server killed afterwards. |

## Confirmed defects (release blockers unless noted)

### B-01 — `docs/advanced.md` examples call APIs that do not exist or use wrong signatures
- Expected: the examples run against the current public API.
- Actual:
  - The retry example calls `client.exchange_code_for_token(params)`. This method does not exist, so it raises `NoMethodError`.
  - `TokenManager.refresh_token` calls `client.refresh_token(token_params)` with a positional Hash. Under Ruby 3 this raises `ArgumentError: wrong number of arguments (given 1, expected 0; required keyword: refresh_token)`.
  - The retry example rescues `TokenError` and matches `/timeout/`. Timeouts raise `NetworkError`, so that branch is dead code.
  - The same example retries the authorization-code exchange, but codes are single-use.
  - The caching note says `SmartMetadata` "holds an HTTPClient reference". It has no such instance variable.
- Repro: `/tmp/audit/scratch/verify_smart.rb` prints `[exchange_code_for_token] RAISED NoMethodError` and `[metadata ivars] []`. `/tmp/audit/scratch/verify_adv.rb` prints the `ArgumentError`.
- Fix:
  - Use `client.request_access_token(code:, code_verifier:)` and `client.refresh_token(**token_params)` (or pass `refresh_token:` directly).
  - Retry only on `NetworkError` or 5xx, and say that a code exchange should not be retried after the server may have consumed the code.
  - Drop the HTTPClient claim.
- Acceptance: every advanced.md block passes a WebMock-stubbed run.

### B-02 — Confidential asymmetric token-exchange page documents the wrong error for missing credentials
- File: `docs/smart-on-fhir/confidential-asymmetric/token-exchange.md`, "Missing credentials".
- Expected: the class and message that are actually raised.
- Actual: the page rescues `TokenError` and matches `'Missing required asymmetric credentials'`. The code raises `Safire::Errors::ConfigurationError: Configuration missing: kid` (or `private_key, kid`). The YARD for `request_access_token` and `troubleshooting/client-errors.md` already say `ConfigurationError`.
- Repro: verify_smart.rb prints `[asym missing kid] RAISED Safire::Errors::ConfigurationError: Configuration missing: kid`.
- Fix: rescue `ConfigurationError` and drop the message match.

### B-03 — SMART JWT assertion docs claim an `iat` claim that Safire does not send
- Files:
  - `docs/smart-on-fhir/confidential-asymmetric/index.md` (mermaid diagram: `iat: issued at`, `exp: iat + 5 minutes`)
  - `docs/troubleshooting/client-errors.md` ("Safire sets JWT `exp` to 5 minutes from `iat`")
- Actual: `Safire::JWTAssertion#payload` sends only `iss, sub, aud, exp, jti`. Header is `typ, kid, alg[, jku]`. This matches SMART 2.2.0 client-confidential-asymmetric.md "Authentication JWT Claims" (iss, sub, aud, exp, jti required; "exp ... SHALL be no more than five minutes in the future"). That table does not list `iat`. The table on token-exchange.md is correct.
- Repro: verify_smart.rb prints `[asym jwt claims] ["iss","sub","aud","exp","jti"]`.
- Fix: remove `iat` and write `exp: now + 300 s (≤ 5 min)`.

### B-04 — Discovery and DCR error-handling docs route transport failures to `DiscoveryError`
- Files and problems:
  - `docs/smart-on-fhir/discovery/index.md`: the `when /timeout/i` branch inside `rescue DiscoveryError` can never match.
  - `docs/smart-on-fhir/dynamic-client-registration/response.md`:
    - `e.status # ... nil if the server was unreachable`: an unreachable server raises `NetworkError` instead.
    - "`register_client` raises one of three error classes": it also raises `ConfigurationError` for a non-HTTPS endpoint.
- Repro: verify_smart.rb prints `[discovery timeout] RAISED Safire::Errors::NetworkError: HTTP request failed: execution expired` and `[register http endpoint] RAISED Safire::Errors::ConfigurationError ...`.
- Fix: move the timeout case to `rescue NetworkError`, list `ConfigurationError`, and correct the `status` comment (nil when the failure is not an HTTP status, e.g. a missing `registration_endpoint`).

### B-05 — Broken links on the published docs site
- Built site check (`/tmp/audit/scratch/linkcheck.rb /tmp/audit/site`):
  - `{{ site.baseurl }}/configuration/client-setup/` is used in `configuration/index.md:63` and `configuration/logging.md:85`. Jekyll emits `configuration/client-setup.html`, so the trailing-slash URL 404s on static Pages hosting.
  - `{{ site.baseurl }}/configuration/logging/` is used in `configuration/index.md:64` and `configuration/client-setup.md:275`. Same problem.
  - `security/#private-keys-confidential-asymmetric` is used in `smart-on-fhir/confidential-asymmetric/index.md`. That anchor no longer exists; the heading is now "Private Keys and Client Certificates".
- Fix: use `{% link configuration/client-setup.md %}` / `{% link configuration/logging.md %}` (or add permalinks), and change the anchor to `#private-keys-and-client-certificates`.
- Acceptance: the link check reports nothing.

### B-06 — The exact-match wildcard rule is attributed to STU2; it is Safire's stricter local rule
- What STU2 says (general.md §7.3 "Scope negotiation", item 3): "A client application **MAY** request a wildcard scope only if wildcards are specified in the server's `scopes_supported` metadata list."
- Safire's rule: the requested wildcard token must appear *exactly* in `scopes_supported`. This is stricter than STU2. `docs/udap/dynamic-client-registration/index.md` (updated by #335) already labels it correctly.
- Files that still present the exact-match rule as STU2's requirement:
  - `README.md`: "Registration and modification require a requested wildcard scope to be advertised exactly in `scopes_supported`, as UDAP Security STU2 requires".
  - `CHANGELOG.md [Unreleased]`: "enforce the UDAP Security STU2 rule that a wildcard scope may be requested only when it is advertised".
  - `docs/troubleshooting/client-errors.md`: "because STU2 permits requesting a wildcard only when it is advertised".
  - ROADMAP's wording is neutral.
- Fix (coordinator files): say "STU2 permits requesting a wildcard only if wildcards are listed in `scopes_supported` (general §7.3 item 3); Safire enforces the stricter exact-advertisement check."
- Acceptance: no doc says STU2 itself requires exact advertisement.

### B-07 — README says CONTRIBUTION.md covers the sign-off requirement; it does not
- `README.md` "Contributing" says CONTRIBUTION.md covers "branch naming, commit message style, and the sign-off requirement".
- `CONTRIBUTION.md` never mentions sign-off or `Signed-off-by`.
- Its "Commit Messages" section says "Keep the subject line as the entire commit message (no body)". That conflicts with the `Signed-off-by` trailers used on `main` (`git log origin/main` shows them).
- Fix: add a sign-off section (`git commit -s`, trailers allowed), or remove the claim from the README.

### B-08 — README and security docs point to SSL/user-agent configuration that the guide does not document or expose
- Claims:
  - `README.md`: "See the Configuration Guide for all options including `user_agent`, `log_level`, and SSL settings."
  - `docs/security.md` footer: "Configuration Guide for `ssl_options` and `log_http` settings".
- Actual:
  - The Configuration Guide does not mention `user_agent` (`Safire.configuration.user_agent` exists) or any SSL setting.
  - `ssl_options` is accepted only by the internal `Safire::HTTPClient.new`. `Protocols::Smart` and `Protocols::Udap` construct `HTTPClient` without it, so it cannot be set through the public API.
- Fix: document `user_agent` under logging/global config, and remove the SSL/`ssl_options` references (or expose the option deliberately in a later release).

### B-09 — Public-client "Testing Your Integration" steps fail under the v0.4.0 HTTPS policy
- File: `docs/smart-on-fhir/public-client/token-exchange.md`.
- The page tells readers to register `http://localhost:3000/auth/callback` and run it with the page's `ClientConfig`, which has no `allow_insecure_localhost: true`. That config raises `ConfigurationError: Configuration requires HTTPS for: redirect_uri ...`.
- Repro: verify_smart.rb `[http localhost redirect]`.
- Fix: add `allow_insecure_localhost: Rails.env.development?` to the example config and note it, or use an HTTPS tunnel.

### B-10 — ROADMAP attributes signing algorithms to the public client
- `ROADMAP.md` says "Public Client — PKCE-only authorization code flow (RS256/ES256)".
- Public clients sign nothing (the token request carries `client_id` only; verify_smart.rb `[public token body]`). RS256/ES256 are not SMART client algorithms at all; SMART asymmetric clients use RS384/ES384.
- Fix: drop "(RS256/ES256)".

### B-11 — Demo and CI-matrix lockfiles are stale and carry known advisories (release-prep defect; not consumer-runtime)
- `examples/sinatra_app/Gemfile.lock`:
  - Still records `safire (0.4.0)`. `bin/demo` runs `bundle install`, which rewrites it to 0.4.1 and leaves the tree dirty. Confirmed when the demo was booted; the change was reverted.
  - bundler-audit flags:
    - rack 3.2.6 (4 advisories; the root was bumped to 3.2.8 for these in #349)
    - addressable 2.8.8 (High: ReDoS in templates; fix ≥ 2.9.0)
    - faraday 2.14.0 (3, including SSRF via protocol-relative URL; fix ≥ 2.14.1)
    - activesupport 8.0.4 (3)
    - concurrent-ruby 1.3.6 (3)
    - json 2.18.0 (2)
    - jwt 2.10.2 (1)
- `gemfiles/activesupport_71.gemfile.lock` (CI matrix, shipped in the gem): activesupport 7.1.6 has 3 advisories.
- CI (`.github/workflows/ci.yml`) audits only the root lockfile.
- Repro: `bundle exec bundler-audit check --gemfile-lock examples/sinatra_app/Gemfile.lock` (log: `/tmp/audit/demo-audit.log`).
- Fix:
  - `cd examples/sinatra_app && bundle update --conservative rack addressable faraday activesupport concurrent-ruby json jwt` (plus the safire PATH version).
  - Same for the AS 7.1 lock, within `~> 7.1`, if a patched 7.1.x exists; otherwise document it.
  - Optionally add `--gemfile-lock` audits to CI.
  - Make the release step (5.R) re-lock the demo after the version bump.
- Acceptance: both lockfiles audit clean or have documented exceptions, and `bin/demo` leaves no diff.

### B-12 — `Safire::Client` YARD makes UDAP claims that are not traceable to STU2 and contradict the v0.5.0 plan (overlaps the token feature; hand to 5.10/5.12)
- `lib/safire/client.rb` header:
  - "The unregistered client flow (§8.1) allows client_credentials grant without prior DCR when identity can be fully determined from certificate attributes alone." No such section or flow exists in the UDAP STU2 IG pages; grep finds "unregistered" only in discovery.md §2.1. It may come from udap.org JWT client auth text, which could not be fetched.
  - `@note Future kwargs ... flow: :b2b / :b2c / :tiered_oauth` contradicts the plan's `Client#request_backend_token` on `protocol: :udap`.
- Fix: remove the claim, or cite and label it unverified. Replace the `@note` with the actual v0.5.0 API.

### B-13 — Example code in `docs/security.md` and some SMART pages cannot work as written (low effort)
- `security.md` "Symmetric Secret Rotation": `build_smart_client` rescues `TokenError` around client construction, but `create_client` never sends a request, so the fallback can never run. Fix: wrap the token call instead.
- `confidential-symmetric/authorization.md` and `troubleshooting/client-errors.md` (two places) call `metadata.token_endpoint_auth_methods_supported.include?(...)`. That field is OPTIONAL (SMART conformance.md), so the call raises `NoMethodError` when it is absent. It also contradicts `supports_symmetric_auth?`/`supports_asymmetric_auth?`, which treat absent as allowed. Fix: use `&.include?` or rely on the `supports_*?` helpers.

## Optional enhancements (not blockers)

- **E-01** `post-based-authorization.md`: the documented message "Invalid authorization method: :put. Supported methods are :get and :post" differs from the actual `Invalid method: :put; valid: get, post`.
- **E-02** `backend-services/token-request.md`: "typically in 5–15 minutes". SMART backend-services.md says `expires_in` "SHOULD NOT exceed `300`" and that tokens "SHALL be short-lived".
- **E-03** `discovery/metadata.md`: the "Optional" table mixes RECOMMENDED fields (scopes_supported, response_types_supported, management/introspection/revocation endpoints, user_access_brand_*) with OPTIONAL ones. `token_endpoint_auth_signing_alg_values_supported` is not a SMART conformance field. The example response lists `refresh_token` in `grant_types_supported`, which SMART does not enumerate.
- **E-04** `confidential-symmetric/index.md`:
  - It lists "Backend services with secure credential storage" as a symmetric use case, but SMART Backend Services requires asymmetric auth.
  - The "Offline Access: Limited vs Full support" row has no basis.
- **E-05** `troubleshooting/client-errors.md` "Blocked redirect":
  - "except `localhost`": since v0.4.0, localhost needs `allow_insecure_localhost: true`.
  - An `http://` base_url is rejected at construction, not on redirect.
- **E-06** The Sinatra ERB auto-POST form in `post-based-authorization.md` does not HTML-escape values (Sinatra ERB does not auto-escape). Use `Rack::Utils.escape_html`.
- **E-07** Several callback examples log the expected and received `state` values. Prefer value-free logging, consistent with ADR-015.
- **E-08** Coverage gaps:
  - `docs/index.md` SMART feature list omits SMART DCR (the README lists it).
  - The Configuration quick-reference table omits `issuer` and `allow_insecure_localhost` (`docs/configuration/index.md`).
  - `configuration/index.md` says Backend Services "requires explicit values", but v0.4.x still falls back with a warning.
- **E-09** `troubleshooting/index.md`: "Safire logs one line per error with all relevant context" is unverified and overstated.
- **E-10** `udap/dynamic-client-registration/lifecycle.md` error table omits the wildcard `ValidationError`/`DiscoveryError` cases that the DCR index page lists.
- **E-11** CONTRIBUTION.md:
  - "under 15 lines" versus RuboCop `Metrics/MethodLength: 20`.
  - The style example marks `ehr_launch_capability?` private, but it is public API (documented in capability-checks.md).
- **E-12** YARD: 27 undocumented methods, including all of `ClientConfigBuilder` except `certificate_chain`/`allow_insecure_localhost`, `Safire.logger`, `Safire::Configuration`, `PKCE.generate_code_verifier` and `HTTPClient#get/post`. There are also 4 "Undocumentable ATTRIBUTES" warnings from splatted `attr_reader`.
- **E-13** Demo UX: SMART discovery failure shows only "Server discovery failed — check the server URL", while UDAP shows the `NetworkError` detail. Consider a consistent, value-free category message.
- **E-14** Packaging: the gem ships 104 files. Besides `lib/` these are:
  - `docs/` (Jekyll sources incl. `docs/Gemfile.lock`, ADRs, ~60 files)
  - `.claude/skills/release-safire/SKILL.md`
  - `Gemfile`, `Gemfile.lock`, `gemfiles/*`
  - `.rubocop.yml`, `.rspec`, `.tool-versions`, `Rakefile`, `CONTRIBUTION.md`, `CODE_OF_CONDUCT.md`, `safire.gemspec`

  This is pre-existing: the gemspec `files` block is unchanged since v0.4.1, and v0.4.1 already tracked `.claude/`. Suggest an allow-list (`lib/**/*`, README, LICENSE, CHANGELOG) or extend the reject prefixes with `docs/ .claude/ gemfiles/ Gemfile`.

## Release-scope alignment checklist for 5.10–5.12 (not defects at this commit)

When the UDAP B2B token request lands, these baseline statements become false and must change together:

- `README.md`: intro ("discovery plus certificate-backed Dynamic Client Registration") and "UDAP JWT client authentication and Tiered OAuth are planned".
- `docs/index.md`: description and "JWT assertion authentication and Tiered OAuth remain planned".
- `docs/udap.md`:
  - The intro.
  - "Scope and Protocol Choice": "Safire does not yet implement UDAP JWT client authentication, token acquisition ... raise `NotImplementedError`".
  - The table row "Registration lifecycle only".
- `docs/configuration/index.md`: mermaid `Protocols::Udap — auth flows planned`, and the `private_key`/`jwt_algorithm` rows ("UDAP registration" only).
- `docs/configuration/client-setup.md`:
  - The `:udap | Partial | ... auth/token flows raise NotImplementedError` row.
  - "Future UDAP authentication flows will use signed JWT assertions".
  - "Configured credentials are intended to serve as defaults for UDAP Dynamic Client Registration".
- `ROADMAP.md`: "Planned v0.5.0" moves to Implemented, the compatibility row "JWT client authentication and authorization flows planned" changes, and "Latest Published Release" is updated at 5.R.
- `safire.gemspec`: the summary ("SMART App Launch and UDAP discovery and registration for Ruby") and the description need B2B/AnT wording.
- YARD:
  - `Safire::Client` header (see B-12).
  - `Safire::ClientConfig` `private_key`/`jwt_algorithm` text ("UDAP software statements" only).
  - The `Protocols::Udap` class comment ("B2B client credentials token acquisition ... raise NotImplementedError").
- `CHANGELOG.md [Unreleased]`: no "Added" section yet.
- `examples/sinatra_app/Gemfile.lock`: safire PATH version at release (B-11).

## Verified as matching (no action)

- **README.md**
  - SMART quick start: `authorization_url` returns `{auth_url:, state:, code_verifier:}`, state is 32 hex characters, the verifier is 128 characters, and the parameters are response_type, client_id, redirect_uri, scope, state, aud, code_challenge_method=S256, and code_challenge.
  - Token exchange and refresh behave as documented.
  - The Backend Services example works with the default client_type. The body has no `client_id`; it contains grant_type, scope, client_assertion_type and client_assertion.
  - `token_response_valid?(…, flow: :backend_services)` behaves as documented.
  - The deprecation warning text and the `system/*.rs` fallback match.
- **Confidential symmetric:** Basic auth applies to exchange and refresh, and `client_id` is not in the body.
- **Confidential asymmetric:** the header is `typ/kid/alg[/jku]` and the body has no `client_id`.
- **Error classes and messages:** the `DiscoveryError` messages and attributes for 404, a non-object body, and a missing `registration_endpoint` all match. The `RegistrationError` `received_fields` path, the `TokenError` message format, and the `NetworkError` format also match.
- **ClientConfig:** `to_hash` and `inspect` mask secrets, and the `allow_insecure_localhost` opt-in behaves as documented.
- **UDAP client:** `client_type=` raises `ConfigurationError`. UDAP `authorization_url` and `request_backend_token` raise `NotImplementedError`, as documented for this commit. SMART `cancel_registration` raises `NotImplementedError`; this is undocumented but harmless.
- **CHANGELOG `[Unreleased]` PKCE fix:**
  - nil and Integer verifiers raise `ArgumentError` naming only the class.
  - Non-ASCII and UTF-16 verifiers raise the invalid-characters `ArgumentError`.
- **CHANGELOG `[Unreleased]` wildcard enforcement:** matches the implementation and DCR docs, except for the attribution wording in B-06. `docs/udap/dynamic-client-registration/index.md` is correct, and STU2 §7.3 is cited properly.
- **`UdapRegistrationMetadata` docs examples:** `response_types`, `token_endpoint_auth_method`, cancel `grant_types: []`, the HTTP localhost rejection, and the opt-in with its value-free warning all behave as documented.
- **UDAP discovery doc claims** match STU2 discovery.md: 404 is a SHOULD-conclude-unsupported; a 204 for `community` is a MAY; signed_metadata is signed with RS256 (SHALL), and signed values take precedence (SHALL). The general.md §7.1 server RS256 baseline note is also correctly represented.
- **SMART spec claims are correct:**
  - S256 SHALL and plain SHALL NOT (conformance.md).
  - The `aud` parameter.
  - The DCR quote from app-launch.md.
  - The client SHALL support RS384 and ES384.
  - Backend Services scope semantics.
- **Demo app:** it boots. UDAP discovery against an unreachable host shows the `NetworkError` detail, and an invalid `community` shows `ConfigurationError`. SMART discovery, authorize and backend-token pages show a discovery-failed flash. POSTs without a CSRF token get 403.

## Not run / limitations

- Live external services were not contacted: the installation smoke test against launch.smarthealthit.org, the `--tag live` specs (they need credentials), and any real UDAP server. hl7.org, udap.org and RFC text were not fetched, so B-12's possible udap.org source is unverified.
- UDAP DCR and discovery docs examples were not run end-to-end with real certificates. The repo integration specs (`spec/integration/udap_*`) cover them and pass.
- Demo error-path probing was limited to GET pages plus CSRF rejection. The authorized POST to `/demo/:id/authorize` returned 403 because the CSRF token was scraped after a redirect; this was not investigated further. Browser-driven OAuth flows (EHR/standalone launch) were not exercised.
- `bin/demo` itself was not run, because port 4567 was already taken by an unrelated Inferno process in this environment. Its steps (`bundle install`, `setup_env.rb`, `puma`) were run manually on port 4599.
- The YARD HTML was generated but not inspected visually.
- The new UDAP Authentication Token / B2B extension / scope-negotiation code was out of scope, except where baseline docs reference it (B-12 and the checklist).
