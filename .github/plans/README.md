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
| 5.A1 | Audit fixes B-01, B-13 | `docs/fix-unrunnable-doc-examples` | #358 | #360 #372 | — | in progress |
| 5.A2 | Audit fixes B-02, B-03, B-04, B-09 | `docs/fix-smart-error-and-claim-docs` | 5.A1 | #361–#363 #368 | — | in progress |
| 5.A3 | Audit fixes B-05, B-08 (docs) | `docs/fix-docs-links-and-config-refs` | 5.A2 | #364 #367 | — | in progress |
| 5.11 | Demo B2B token workflow | `feature/demo-udap-b2b-token` | #358 | #339 | — | in progress |
| 5.A4 | Audit fix B-11 (lockfiles) | `fix/refresh-demo-and-ci-lockfiles` | 5.11 | #370 | — | in progress |
| 5.12 | Release notes + audit fixes B-06, B-07, B-08 (README), B-10; merges 5.A3 and 5.A4 tips | `docs/v0.5.0-release-notes` | 5.A3 | #340 #365–#367 #369 | — | planned |
| 5.A | Pre-release alignment audit ([audit-v0.5.0.md](audit-v0.5.0.md)) | — | — | #340 | — | baseline done (13 blockers filed); feature audit pending |
| 5.R | Release preparation | `release-0.5.0` | last fix | #340 | — | planned |

### v0.6.0

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| 6.1 | Explicit SMART backend scopes (breaking) | `feature/smart-backend-explicit-scopes` | interim `integration/v0.5.0` → `release-0.5.0` later (D-05) | #341 | #359 | draft PR |

Remaining v0.6.0 tasks: see [v0.6.0.md](v0.6.0.md). v0.7.0: see [v0.7.0.md](v0.7.0.md).

### Quality and Compliance

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| Q1 | Drop legacy YARD nav patch | `fix/docs-remove-legacy-yard-patch` | `main` | #334 | #337 | draft PR (other session) |
| Q2 | Inferno Phase 1 (ran: Inferno suite pass + negative control) | `feature/inferno-smart-phase1` | `main` | #346 | #356 | draft PR |
| Q3 | Inferno Phase 2 | `feature/inferno-smart-phase2` | #356 | #347 | — | in progress |

## Blockers and unverified claims

- `main` fails `bundler-audit` (rack advisories). Every PR based on `main`
  shows a red "Security audit" CI step not caused by its diff until #349
  merges; the v0.5.0 integration branch includes #349 (D-18).

- `hl7.org`, `build.fhir.org`, `rfc-editor.org`, `udap.org` are blocked by the
  sandbox network policy. Spec text comes from the IG sources at their release
  tags (see [decisions.md](decisions.md)); RFC/udap.org text is cited, not
  quoted.
- No reachable production UDAP authorization server. UDAP behavior is verified
  with WebMock-based tests; an Inferno UDAP client-suite run (STU1-targeted kit)
  is in progress as labeled external evidence.
- Stacked PRs (base other than `main`) do not trigger the Ruby CI workflow;
  combined stacks are validated locally and via manual workflow runs where
  noted.
- Review threads were answered but not resolved: resolving threads was blocked
  by this session's permission policy.
