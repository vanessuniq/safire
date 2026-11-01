# Roadmap execution — review index

Coordinator-owned index of the draft PR stacks implementing the remaining
[ROADMAP.md](../../ROADMAP.md) work. Nothing here is merged; every PR is a
DRAFT. Plans: [v0.5.0](v0.5.0.md) · [v0.6.0](v0.6.0.md) · [v0.7.0](v0.7.0.md)
· [Quality](quality.md) · [Decision log](decisions.md)

Milestones: [v0.5.0](https://github.com/vanessuniq/safire/milestone/1) ·
[v0.6.0](https://github.com/vanessuniq/safire/milestone/2) ·
[v0.7.0](https://github.com/vanessuniq/safire/milestone/3) ·
[Quality and Compliance](https://github.com/vanessuniq/safire/milestone/4)

## How to use this index

1. Read the version plan and the decisions it cites.
2. Review PRs top to bottom within a version. Each PR's base is its immediate
   predecessor, so the GitHub diff shows only that PR's concern.
3. Integration PRs contain merge commits only; review the merge set and any
   conflict resolution.
4. The release PR is last and lists the eventual merge/retarget order.

## Live task table

Last updated: 2026-11-01 (coordinator). Task numbers 5.5 and 5.8 were
reassigned to existing PRs #335 and #336 (other session) and are not reused.

Status legend: `planned` · `in progress` · `draft PR` · `blocked` ·
`validated in stack` (fix verified on the combined version branch, not merged).

### v0.5.0

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| 5.1 | Shared UDAP signing credentials | `refactor/udap-signing-credentials` | `main` | #338 | #351 | draft PR |
| 5.2 | Authentication Token builder | `feature/udap-authentication-token` | #351 | #338 | #354 | draft PR |
| 5.3 | `hl7-b2b` extension model | `feature/udap-b2b-authorization-extension` | `main` | #339 | #352 | draft PR |
| 5.4 | Shared token response parsing | `refactor/shared-token-response-parsing` | `main` | #339 | #350 | draft PR |
| — | Wildcard wording (#332) | `docs/udap-wildcard-spec-wording` | `main` | #332 | #335 | draft PR (other session) |
| 5.6 | Scope negotiation collaborator | `refactor/udap-scope-negotiation` | #335 | #339 | #353 | draft PR |
| — | rack security bump (D-18) | `fix/bump-rack-advisories` | `main` | — | #349 | draft PR (other session); merged into integration |
| — | Release skill markers (#333) | `docs/release-skill-roadmap-markers` | `main` | #333 | #336 | draft PR (other session) |
| 5.9 | Integration (merge-only): #352, #350, #336, #349, #354 | `integration/v0.5.0` | #353 | #340 | #355 | draft PR; green at `ca42bd8` (1395 ex.) |
| 5.7 | Token-request discovery readiness | `feature/udap-token-readiness` | #355 | #339 | #357 | draft PR |
| 5.10 | B2B client_credentials request + facade | `feature/udap-b2b-client-credentials` | #357 | #339 | #358 | draft PR; combined suite green at `51d6210` (1521 ex.) |
| 5.A1 | Audit fixes B-01, B-13 | `docs/fix-unrunnable-doc-examples` | #358 | #360 #372 | #374 | draft PR |
| 5.A2 | Audit fixes B-02, B-03, B-04, B-09 | `docs/fix-smart-error-and-claim-docs` | #374 | #361–#363 #368 | #375 | draft PR |
| 5.A3 | Audit fixes B-05, B-08 (docs) | `docs/fix-docs-links-and-config-refs` | #375 | #364 #367 | #376 | draft PR |
| 5.11 | Demo B2B token workflow (parallel branch) | `feature/demo-udap-b2b-token` | #358 | #339 | #377 | draft PR |
| 5.A4 | Audit fix B-11 (lockfiles; AS 7.1 exception D-21) | `fix/refresh-demo-and-ci-lockfiles` | #377 | #370 | #378 | draft PR |
| 5.12 | Release notes + audit fixes B-06, B-07, B-08 (README), B-10; joins #376 and #378 by merge | `docs/v0.5.0-release-notes` | #376 | #340 #365–#367 #369 | #379 | draft PR; 1544 ex. green at `b19a92f` |
| 5.A | Pre-release alignment audit ([audit-v0.5.0.md](audit-v0.5.0.md)) | — | — | #340 | — | complete: 17 findings, all validated in stack |
| 5.F1 | Feature-audit fixes F-01–F-03 | `docs/fix-v0.5.0-feature-audit` | #379 | #383–#385 | #386 | draft PR |
| 5.F2 | Re-audit fix F-04 | `docs/fix-v0.5.0-fallback-wording` | #386 | #387 | #388 | draft PR |
| 5.R | **Release preparation v0.5.0** | `release-0.5.0` | #388 | #340 | #389 | draft PR; CI green at `f5e0373` (run 41308808682) |

### v0.6.0

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| 6.1 | Explicit SMART backend scopes (breaking) | `feature/smart-backend-explicit-scopes` | interim `integration/v0.5.0` → `release-0.5.0` later (D-05) | #341 | #359 | draft PR |
| 6.2 | UDAP authorization request | `feature/udap-authorization-url` | interim #358 → `release-0.5.0` later | #342 | #380 | draft PR |
| 6.3 | UDAP authorization code token exchange | `feature/udap-authorization-code-token` | #380 | #342 | #381 | draft PR |
| 6.4 | UDAP refresh token | `feature/udap-refresh-token` | #381 | #342 | #382 | draft PR |
| 6.5 | Integration (merge-only): #382 + #359 | `integration/v0.6.0` | #382 | #343 | #390 | draft PR; 1702 ex. green at `de62bd7` |
| 6.6 | Demo UDAP authorization code (stricter demo state check) | `feature/demo-udap-authorization-code` | #390 | #342 | #391 | draft PR |
| 6.7 | Release notes (joins #391) | `docs/v0.6.0-release-notes` | #391 | #343 | #393 | draft PR; 1735 ex. green at `9a00689` |
| 6.A | Pre-release alignment audit | — | #393 | #343 | — | running on `9a00689` |
| 6.R | Release preparation | `release-0.6.0` | last fix | #343 | — | planned (after audit fixes) |

#359 and #380 were retargeted to `release-0.5.0` after merging it in (D-05); #359
resolved six wording conflicts in favor of its v0.6.0 text.

### v0.7.0

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| 7.1 | Tiered OAuth authorization request (`idp:`) | `feature/udap-tiered-oauth-request` | interim `integration/v0.6.0` → `release-0.6.0` later | #344 | #392 | draft PR |
| 7.3 | Demo IdP field + `invalid_idp` handling | `feature/demo-udap-tiered-oauth` | #392 (merges #393 for the demo base) | #344 | — | in progress |
| 7.4 | Release notes | `docs/v0.7.0-release-notes` | 7.3 | #345 | — | planned |
| 7.A / 7.R | Audit, fixes, release prep | — | — | #345 | — | planned |


### Quality and Compliance

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| Q1 | Drop legacy YARD nav patch | `fix/docs-remove-legacy-yard-patch` | `main` | #334 | #337 | draft PR (other session) |
| Q2 | Inferno Phase 1 (ran: Inferno suite pass + negative control) | `feature/inferno-smart-phase1` | `main` | #346 | #356 | draft PR |
| Q3 | Inferno Phase 2 (ran: 6 scenarios pass + 2 negative controls) | `feature/inferno-smart-phase2` | #356 | #347 | #373 | draft PR |

## Blockers and unverified claims

- `main` fails `bundler-audit` (rack advisories). Every PR based on `main`
  shows a red "Security audit" CI step not caused by its diff until #349
  merges; the v0.5.0 integration branch includes #349 (D-18).

- `hl7.org`, `build.fhir.org`, `rfc-editor.org`, `udap.org` are blocked by the
  sandbox network policy. Spec text comes from the IG sources at their release
  tags (see [decisions.md](decisions.md)); RFC/udap.org text is cited, not
  quoted.
- No reachable production UDAP authorization server. UDAP behavior is verified
  with WebMock-based tests plus a labeled external Inferno UDAP client-suite run
  (STU1-targeted kit; see [inferno-udap-v0.5.0.md](inferno-udap-v0.5.0.md)).
- Stacked PRs (base other than `main`) do not trigger the Ruby CI workflow;
  combined stacks are validated locally and via manual workflow runs where
  noted.
- Review threads were answered but not resolved: resolving threads was blocked
  by this session's permission policy.
