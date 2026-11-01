# Decision log — roadmap execution (v0.5.0 – v0.7.0, Quality)

Coordinator-owned. Each entry: context, decision, basis, alternatives, status.
Basis labels: **[N]** normative spec text, **[R]** spec recommendation
(SHOULD/MAY), **[I]** Safire implementation choice, **[U]** cannot be verified
locally.

Specification sources (fetched as IG source at release tags because `hl7.org`
is blocked by this sandbox's network policy; rendered anchors are derived from
headings):

- UDAP Security STU2 v2.0.0 — HL7/fhir-udap-security-ig tag `2.0.0`
  (commit `d8ac5a6`), rendered at https://hl7.org/fhir/us/udap-security/STU2/
- SMART App Launch 2.2.0 — HL7/smart-app-launch tag `2.2.0`
  (commit `13449f9`), rendered at https://hl7.org/fhir/smart-app-launch/STU2.2/
- RFC 6749, RFC 7523, RFC 7636, udap.org profiles — cited by URL only; text not
  fetched in this environment **[U]**.

---

## D-01 Plan location: `.github/plans/`

- **Context:** `docs/` is the Jekyll site *and* is packaged into the gem
  (`safire.gemspec` ships every tracked file except `bin/ spec/ examples/ .git*`;
  59 `docs/` files are in the gem today). Execution plans change often and are
  not user documentation.
- **Decision [I]:** keep plans, review indexes, and audits in `.github/plans/`
  (not packaged, not published), on the coordinator branch
  `docs/roadmap-execution-plan`.
- **Alternatives:** `docs/plans/` with `nav_exclude` (published and packaged);
  root `plans/` plus a gemspec reject change (touches release metadata).

## D-02 Reuse draft PRs #335, #336, #337

- **Context:** while planning, draft PRs #335 (#332 wording), #336 (#333 release
  skill), #337 (#334 `bin/docs`) were opened from another session.
- **Decision:** reuse them in the v0.5.0 graph (#335, #336) and the Quality
  stack (#337) instead of duplicating; dependent work stacks on #335.

## D-03 Integration by merge commits, not rebases

- **Context:** parallel branches must all reach each version's release PR
  without duplicate implementation commits.
- **Decision [I]:** each version has a merge-only integration branch
  `integration/vX.Y.Z` that merges the tips of parallel branches with
  `git merge --no-ff`. Dependent work continues from that branch. No history
  rewrites; conflicts, if any, are resolved in the merge commit and described in
  the integration PR.
- **Tradeoff:** the integration PR diff repeats already-reviewed changes; its
  review is limited to confirming the merge set and any conflict resolution.

## D-04 CHANGELOG/ROADMAP/README owned by the coordinator

- **Decision [I]:** feature PRs carry code, tests, YARD, and feature docs pages;
  user-facing release notes (`CHANGELOG.md` `[Unreleased]`, `ROADMAP.md`,
  `README.md`, compatibility tables) are consolidated in one coordinator PR per
  version before the audit, then finalized by the release PR.
- **Why:** parallel edits to these files would conflict at integration.
- **Alternative:** per-PR CHANGELOG entries (repo precedent, e.g. #330); rejected
  only for parallel stacks.

## D-05 Later versions stack on earlier unmerged stacks

- **Decision:** v0.6.0 roots branch from the v0.5.0 release-prep branch tip
  (`release-0.5.0`), or from the last validated v0.5.0 PR if the release PR is
  blocked. Until `release-0.5.0` exists, a v0.6.0 root may start from the
  current v0.5.0 tip (interim base, e.g. `integration/v0.5.0` for 6.1); the
  coordinator later merges the newer v0.5.0 tip in and retargets the PR; v0.7.0 likewise from v0.6.0. Each PR targets its immediate
  predecessor so its diff is isolated. Merge order is documented in each release
  PR.

## D-06 UDAP client_credentials uses `Client#request_backend_token`

- **Context:** `Safire::Client` already delegates `request_backend_token`
  (documented as "client_credentials grant"); UDAP raised `NotImplementedError`.
  `client.rb` carried a `@note Future kwargs: flow: :b2b | :b2c | :tiered_oauth`.
- **Decision [I]:** implement `Udap#request_backend_token(scopes:, b2b:, ...)`
  so the existing facade method serves both protocols' client_credentials grant.
  The grant is selected by method, not by a `flow:` kwarg; the `@note` is
  replaced with the implemented contract.
- **Basis:** UDAP STU2 b2b.md §5 ("Client applications registered to use the
  client credentials grant **SHALL** obtain an access token ... RFC 6749 §4.4").
- **Alternatives:** a new protocol-neutral `request_client_credentials_token`
  (extra public API for one grant); a `flow:` constructor kwarg (grant choice
  per call is more natural and avoids mode state). Reviewer may prefer a
  dedicated name; changing it before v0.5.0 is cheap.
- **Review note (#348):** renaming after release is breaking. Status: keep
  `request_backend_token` for v0.5.0; YARD states the contract so a later
  protocol-neutral alias would be additive. **Open for maintainer decision
  before the v0.5.0 release PR merges.**

## D-07 Authentication Token (AnT) construction

- **Basis [N]:** b2b.md §5.2.1 / consumer.md §4.2.1: `iss` and `sub` = the
  `client_id` assigned at registration; `aud` = token endpoint URL; `exp`,
  `iat`, `jti` required; "the value of `exp` minus the value of `iat` **SHALL**
  NOT exceed 300 seconds"; signed, JWS compact serialization. general.md §7.1.3:
  header `alg` and `x5c` (leaf first) required. §7.1.4: the issuer "**SHALL
  NOT** reuse the same `jti` value ... prior to the expiration".
  general.md §7.1.5: clients should use a server-provided URI "exactly as it was
  originally provided" as `aud`.
- **Decision [I]:** lifetime exactly 300 s; `jti` = `SecureRandom.uuid` per
  token; header contains only `alg` and `x5c` (matches software statements,
  ADR-014); `aud` is the authoritative signed `token_endpoint` string unchanged;
  no URI-SAN match is required for the AnT (STU2 imposes the SAN rule on
  software statements, registration.md §3.2.1, not on AnTs); key/chain/algorithm
  handling is shared with software statements via `UdapSigningCredentials`.
- **Algorithm [N]/[I]:** chosen from `token_endpoint_auth_signing_alg_values_supported`
  using the same key-compatible preference as registration (RS256 is the STU2
  **SHALL** baseline).

## D-08 `hl7-b2b` extension validation

- **Basis [N]:** b2b.md §5.2.1.1: `version` fixed `"1"`; `organization_id`
  required, "**SHALL** be a Uniform Resource Identifier (URI)"; `purpose_of_use`
  required array of one or more strings; `consent_reference` "Omit if
  `consent_policy` is not present"; `extensions` "required for B2B client apps
  using the `client_credentials` flow; omit for ... `authorization_code`".
- **Decision [I]:** validate locally provable shape only; Safire injects
  `version`; unknown members rejected; `subject_id`/`subject_role` rejected
  without `subject_name` (stricter than the text, which ties them to a named
  subject); trust-community vocabularies (NPI, NUCC, PurposeOfUse) and URL
  resolvability are **[U]** and left to the caller.

## D-09 Token-request discovery readiness

- **Basis [N]:** discovery.md §2.2: `udap_profiles_supported` **SHALL** include
  `udap_authn` (and `udap_authz` when `client_credentials` is supported);
  "clients **SHALL** interpret an empty array value to mean that the
  corresponding capability is NOT supported"; `token_endpoint_auth_methods_supported`
  fixed `["private_key_jwt"]`; `udap_authorization_extensions_required` lists
  extensions "required ... in every token request". §2.3: if signed metadata
  fails validation "the client **SHALL NOT** proceed".
- **Decision [I], per ADR-015:** hard-fail (`DiscoveryError`) when trusted
  discovery fails, the authoritative token endpoint is unusable, `udap_authn`
  is not advertised, the grant is not in `grant_types_supported`,
  `private_key_jwt` is not advertised, or signing-algorithm metadata is not a
  non-empty string array; hard-fail (`ValidationError`) when a required
  extension is missing from the request; warn (value-free) when RS256 or
  `udap_authz` is not advertised or a sent extension key is not in
  `udap_authorization_extensions_supported`.

## D-10 Scope negotiation applies to token requests

- **Basis [N]:** general.md §7.3: constraints "apply for both registration
  requests and access token requests"; "A client application **MAY** request a
  wildcard scope only if wildcards are specified in the server's
  `scopes_supported` metadata list." b2b.md §5.2.2 client credentials: `scope`
  **required**.
- **Decision [I]:** reuse the registration wildcard policy (exact advertisement,
  `DiscoveryError` on unusable `scopes_supported`) for token requests through a
  shared `UdapScopeNegotiation` collaborator; a missing or empty scope for
  client_credentials raises `ConfigurationError` (no fallback, unlike SMART
  v0.4.x).

## D-11 Token response handling

- **Decision [I]:** UDAP token responses use the shared SMART parser (Hash with
  non-blank `access_token`, else `TokenError`). STU2 does not constrain token
  type (b2b.md §5.2.3 note). The 60-minute access-token lifetime is a server
  obligation; Safire does not reject longer `expires_in` **[I]** (possible
  future `token_response_valid?` diagnostic).

## D-12 v0.6.0: one authorization-code implementation for consumer and B2B

- **Basis [N]:** consumer.md §4.1–4.2 and b2b.md §5.1–5.2 define identical
  authorization-request and token-request wire shapes for authorization_code;
  B2B additionally permits refresh (§5.3, also consumer via RFC 6749).
- **Decision [I]:** a single UDAP `authorization_url` / `request_access_token` /
  `refresh_token` implementation; "Interactive B2B" is documented usage
  (registration with `authorization_code`, user scopes) rather than a separate
  API. AnTs for authorization_code omit `extensions` [N].

## D-13 v0.6.0: authorization request scope rule

- **Context:** §7.3 names registration and token requests; authorization
  requests are not named, but the scope requested there is the scope granted
  for the subsequent token.
- **Decision [I] (revised after #348 review):** §7.3 does not name
  authorization requests, so hard-failing there would be stricter than the
  text and could reject requests a server accepts. v0.6.0 uses **warning-only**
  (value-free) for unadvertised wildcards in `authorization_url`; the token
  request (code exchange/refresh carry no new scope, client_credentials does)
  keeps the §7.3 hard rule. Alternative (hard fail) recorded for review.

## D-14 v0.6.0: `state` comparison remains the application's job

- **Basis [N]:** general.md §7.2.1: "The client application **SHALL NOT**
  proceed if the `state` parameter is not included in the authorization
  response or its value does not match".
- **Decision [I]:** like SMART today, Safire returns `state` from
  `authorization_url`; the application compares it at the callback. Documented
  with an explicit warning. Alternative: a callback-parsing helper (new API
  surface for both protocols; deferred).

## D-15 v0.7.0 scope: client-app side of Tiered OAuth only

- **Basis [N]:** user.md §6.1: the client app adds `udap` to `scope` and the
  `idp` parameter; data holders advertising Tiered OAuth **SHALL** include
  `"udap"` in `scopes_supported` (and `udap_to` in profiles, discovery.md §2.2).
  §6.2–6.3 (data holder acting as OIDC client of the IdP, ID token validation)
  are data-holder obligations.
- **Decision [I]:** v0.7.0 implements `authorization_url(idp:)` with discovery
  readiness and `invalid_idp` documentation; data-holder/IdP interactions are
  out of scope for a client library. Roadmap wording ("identity chaining") is
  clarified in the v0.7.0 release notes.

## D-16 v0.6.0 removes the SMART Backend Services scope fallback

- **Basis:** CHANGELOG v0.4.1 Deprecated entry; SMART 2.2.0 backend-services.md
  token request `scope` **required** [N].
- **Decision:** `request_backend_token` without usable configured or per-call
  scopes raises `ConfigurationError` (breaking; v0.6.0 only).

## D-17 Section numbers in UDAP STU2 citations

- **Context:** the IG source has no explicit numbers on `general.md` headings.
  Cross-references in the IG ("Section 7.1.4" = JWT Claims, "Section 7.2.1" =
  state, "Section 7.4.1" = Certification template) fix the order: §7.1 JWT
  requirements, §7.2 Authorization code flow, **§7.3 Scope negotiation**, §7.4
  Certifications, §7.5 SMART App Launch.
- **Decision:** cite Scope negotiation as §7.3 plus its anchor
  (`general.html#scope-negotiation`). An earlier draft of this plan and issue
  #339 said §7.4; both were corrected.

## D-18 Fold #349 (rack advisories) into the v0.5.0 integration set

- **Context:** `bundle exec bundler-audit check --update` fails on `main`
  (rack 3.2.6: GHSA-p8x9-v4hv-2w4g, GHSA-wvg4-6p58-3gh3), so the CI "Security
  audit" step is red for every PR based on `main`. Draft PR #349 (other
  session) bumps rack to 3.2.8 in both lockfiles. rack is a development/test
  dependency (via sinatra), not a runtime dependency of the gem.
- **Decision:** merge `fix/bump-rack-advisories` into `integration/v0.5.0` so
  combined-stack checks include the audit. Root PRs based on `main` will show
  a red audit step that is not caused by their diff.

## D-19 Token success responses stay Hash-only

- **Context (from 5.4):** discovery and registration accept a raw JSON-object
  String body (v0.4.1); token responses require an already-parsed Hash.
- **Decision [I]:** keep Hash-only in v0.5.0 (no behavior change in the
  refactor); UDAP token responses use the same parser. Recorded as a candidate
  consistency enhancement for the audit, not a defect.
