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

Status legend: `planned` · `in progress` · `draft PR` · `blocked` ·
`validated in stack` (fix verified on the combined version branch, not merged).

### v0.5.0

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| 5.1 | Shared UDAP signing credentials | `refactor/udap-signing-credentials` | `main` | #338 | #351 | draft PR |
| 5.2 | Authentication Token builder | `feature/udap-authentication-token` | #351 | #338 | — | in progress |
| 5.3 | `hl7-b2b` extension model | `feature/udap-b2b-authorization-extension` | `main` | #339 | #352 | draft PR |
| 5.4 | Shared token response parsing | `refactor/shared-token-response-parsing` | `main` | #339 | #350 | draft PR |
| — | Wildcard wording (#332) | `docs/udap-wildcard-spec-wording` | `main` | #332 | #335 | draft PR (other session) |
| 5.6 | Scope negotiation collaborator | `refactor/udap-scope-negotiation` | #335 | #339 | #353 | draft PR |
| — | rack security bump (D-18) | `fix/bump-rack-advisories` | `main` | — | #349 | draft PR (other session); merged into integration |
| — | Release skill markers (#333) | `docs/release-skill-roadmap-markers` | `main` | #333 | #336 | draft PR (other session) |
| 5.9 | Integration (merge-only) | `integration/v0.5.0` | 5.6 | #340 | — | planned |
| 5.7 | Token-request discovery readiness | `feature/udap-token-readiness` | 5.9 | #339 | — | planned |
| 5.10 | B2B client_credentials request + facade | `feature/udap-b2b-client-credentials` | 5.7 | #339 | — | planned |
| 5.11 | Demo B2B token workflow | `feature/demo-udap-b2b-token` | 5.10 | #339 | — | planned |
| 5.12 | Release notes consolidation | `docs/v0.5.0-release-notes` | 5.11 | #340 | — | planned |
| 5.A | Pre-release alignment audit | — | 5.12 | #340 | — | planned |
| 5.R | Release preparation | `release-0.5.0` | last fix | #340 | — | planned |

### v0.6.0 / v0.7.0

Planned; see [v0.6.0.md](v0.6.0.md) and [v0.7.0.md](v0.7.0.md).

### Quality and Compliance

| # | Task | Branch | Base | Issue | PR | Status |
|---|---|---|---|---|---|---|
| Q1 | Drop legacy YARD nav patch | `fix/docs-remove-legacy-yard-patch` | `main` | #334 | #337 | draft PR (other session) |
| Q2 | Inferno Phase 1 | `feature/inferno-smart-phase1` | `main` | #346 | — | in progress |
| Q3 | Inferno Phase 2 | — | Q2 | #347 | — | planned |

## Blockers and unverified claims

- `main` fails `bundler-audit` (rack advisories). Every PR based on `main`
  shows a red "Security audit" CI step not caused by its diff until #349
  merges; the v0.5.0 integration branch includes #349 (D-18).

- `hl7.org`, `build.fhir.org`, `rfc-editor.org`, `udap.org` are blocked by the
  sandbox network policy. Spec text comes from the IG sources at their release
  tags (see [decisions.md](decisions.md)); RFC/udap.org text is cited, not
  quoted.
- No reachable UDAP authorization server: UDAP behavior is verified with
  WebMock-based tests only.
