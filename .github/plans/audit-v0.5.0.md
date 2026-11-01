# v0.5.0 pre-release alignment audit

Status: **in progress** — baseline audit complete; new-feature audit and fix
validation pending. The release PR is blocked until every confirmed finding
below has a validated fix in the v0.5.0 stack ancestry.

## Scope and method

- **Baseline audit** (whole project except the new UDAP token feature):
  `integration/v0.5.0` at `ca42bd8`. Full report:
  [audit-v0.5.0-baseline.md](audit-v0.5.0-baseline.md) (commands, outputs,
  verified-as-matching list, optional enhancements E-01–E-14, and what could
  not run).
- **Feature audit** (UDAP Authentication Token, `hl7-b2b`, readiness,
  client_credentials, demo, docs): to run on the combined branch after 5.11,
  the doc fixes, and 5.12.
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
| B-01 | #360 | `docs/advanced.md` examples call missing APIs / wrong signatures | `docs/fix-unrunnable-doc-examples` | fix in progress |
| B-02 | #361 | Asymmetric token-exchange page documents wrong error class | `docs/fix-smart-error-and-claim-docs` | fix in progress |
| B-03 | #362 | Docs claim SMART assertion sends `iat` | `docs/fix-smart-error-and-claim-docs` | fix in progress |
| B-04 | #363 | Discovery/DCR docs route transport failures to `DiscoveryError` | `docs/fix-smart-error-and-claim-docs` | fix in progress |
| B-05 | #364 | Broken docs-site links | `docs/fix-docs-links-and-config-refs` | fix in progress |
| B-06 | #365 | Exact-match wildcard rule attributed to STU2 (README, CHANGELOG, client-errors.md) | 5.12 release notes (coordinator) | planned |
| B-07 | #366 | README claims CONTRIBUTION.md covers sign-off | 5.12 release notes (coordinator) | planned |
| B-08 | #367 | README/security.md point to undocumented `user_agent`/SSL settings | docs part: `docs/fix-docs-links-and-config-refs`; README part: 5.12 | fix in progress |
| B-09 | #368 | Public-client testing steps fail under HTTPS policy | `docs/fix-smart-error-and-claim-docs` | fix in progress |
| B-10 | #369 | ROADMAP attributes RS256/ES256 to public clients | 5.12 release notes (coordinator) | planned |
| B-11 | #370 | Demo and AS 7.1 lockfiles stale with advisories | `fix/refresh-demo-and-ci-lockfiles` | fix in progress |
| B-12 | #371 | `Safire::Client` YARD: untraceable "§8.1 unregistered client" claim; stale `flow:` note | #358 (5.10) removed both — verify in feature audit | fix in stack, to verify |
| B-13 | #372 | `security.md` rotation example unreachable; `.include?` on optional field | `docs/fix-unrunnable-doc-examples` | fix in progress |

Optional enhancements E-01–E-14 are recorded in the baseline report and are
**not** release blockers; they were not filed as issues to keep the audit from
expanding into unrelated work.
