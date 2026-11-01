# v0.5.0 pre-release alignment audit

Status: **complete for the draft stack** — every confirmed finding has a fix
validated in the ancestry of the draft release PR #389 (`release-0.5.0` at
`f5e0373`). Issues stay open until their PRs merge to `main`. Open maintainer
decisions (not defects): D-06 (method name), D-21 (AS 7.1 advisories).

## Scope and method

- **Baseline audit** (whole project except the new UDAP token feature):
  `integration/v0.5.0` at `ca42bd8`. Full report:
  [audit-v0.5.0-baseline.md](audit-v0.5.0-baseline.md) (commands, outputs,
  verified-as-matching list, optional enhancements E-01–E-14, and what could
  not run).
- **Feature audit + fix verification** at `b19a92f` (#379): all B-01–B-13
  verified resolved; three new docs findings F-01–F-03. Report:
  [audit-v0.5.0-feature.md](audit-v0.5.0-feature.md).
- **Release-prep re-audit** after the version bump (`release-0.5.0`): found
  F-04 (fallback described as v0.4.x-only); fixed in #388 and the release
  branch rebuilt on it. Re-checked at `f5e0373`: rspec (root and AS 7.1),
  RuboCop, bundler-audit, demo lock stability, gem build/install, ROADMAP
  markers.
- **External validation**: Inferno SMART STU2.2 client suite (Backend
  Services) passed against Safire in Docker (see #356; that run was on `main`
  code). Inferno UDAP client suite (udap-security-test-kit v0.12.2, graded
  against UDAP **STU1**) against #358 at `51d6210`: every executed test passed
  (registration verification, token-request verification, token use) after one
  documented kit configuration change — the stock mock server signs metadata
  with a certificate whose SAN does not equal the metadata `iss`, violating the
  STU2 (and STU1) discovery rule, and Safire correctly rejected it. Wrong-key
  and missing-`hl7-b2b` negative controls failed in Inferno as expected. Full
  evidence and caveats: [inferno-udap-v0.5.0.md](inferno-udap-v0.5.0.md).
  Attestation tests (17) and Inferno grading of client discovery were not run.
- **GitHub CI**: `ruby.yml` manual run 41255776810 on `51d6210` — all three
  matrix jobs passed.

## Findings (confirmed defects = release blockers)

| ID | Issue | Summary | Fix (PR / owner) | Status |
|---|---|---|---|---|
| B-01 | #360 | `docs/advanced.md` examples call missing APIs / wrong signatures | #374 | validated in stack (feature audit, `b19a92f`) |
| B-02 | #361 | Asymmetric token-exchange page documents wrong error class | #375 | validated in stack (feature audit, `b19a92f`) |
| B-03 | #362 | Docs claim SMART assertion sends `iat` | #375 | validated in stack (feature audit, `b19a92f`) |
| B-04 | #363 | Discovery/DCR docs route transport failures to `DiscoveryError` | #375 | validated in stack (feature audit, `b19a92f`) |
| B-05 | #364 | Broken docs-site links | #376 | validated in stack (feature audit, `b19a92f`) |
| B-06 | #365 | Exact-match wildcard rule attributed to STU2 (README, CHANGELOG, client-errors.md) | #379 | validated in stack (feature audit, `b19a92f`) |
| B-07 | #366 | README claims CONTRIBUTION.md covers sign-off | #379 | validated in stack (feature audit, `b19a92f`) |
| B-08 | #367 | README/security.md point to undocumented `user_agent`/SSL settings | docs: #376; README: #379 | validated in stack (feature audit, `b19a92f`) |
| B-09 | #368 | Public-client testing steps fail under HTTPS policy | #375 | validated in stack (feature audit, `b19a92f`) |
| B-10 | #369 | ROADMAP attributes RS256/ES256 to public clients | #379 | validated in stack (feature audit, `b19a92f`) |
| B-11 | #370 | Demo and AS 7.1 lockfiles stale with advisories | #378 (AS 7.1 exception, D-21) | validated in stack (feature audit, `b19a92f`) |
| B-12 | #371 | `Safire::Client` YARD: untraceable "§8.1 unregistered client" claim; stale `flow:` note | #358 (5.10) removed both — verify in feature audit | validated in stack (feature audit, `b19a92f`) |
| B-13 | #372 | `security.md` rotation example unreachable; `.include?` on optional field | #374 | validated in stack (feature audit, `b19a92f`) |

| F-01 | #383 | §5.2.3 cited for client use of access tokens (is §5.2.4) | #386 | validated in stack |
| F-02 | #384 | ADR-016 says AnT builder unused | #386 | validated in stack |
| F-03 | #385 | Docs home/README/config omit B2B | #386 | validated in stack |
| F-04 | #387 | Fallback docs say "v0.4.x" although v0.5.0 keeps it | #388 | validated in stack (`f5e0373`) |

Optional enhancements E-01–E-14 (baseline) and E-F1–E-F9 (feature audit) are recorded in the baseline report and are
**not** release blockers; they were not filed as issues to keep the audit from
expanding into unrelated work.
