# Quality and Compliance stack (unversioned)

Milestone: [Quality and Compliance](https://github.com/vanessuniq/safire/milestone/4)
· Issues: #334, #346 (Inferno Phase 1), #347 (Inferno Phase 2)

Not tied to a release: these change tooling/CI, not the packaged library, so
they root on `main` and can merge independently of any version stack.

| # | Concern | Branch | Base | Status notes |
|---|---|---|---|---|
| Q1 | Remove legacy YARD nav patch (#334) | `fix/docs-remove-legacy-yard-patch` | main | Draft PR #337 (other session); reused |
| Q2 | Inferno Phase 1: discovery local gate, Backend Services Inferno-driven, HTML report artifact | `feature/inferno-smart-phase1` | main | Feasibility investigated with local Docker; see README table |
| Q3 | Inferno Phase 2: authorization code flows via Capybara/headless Chrome | — | Q2 | Planned after Q2 |

External validation results are recorded only when Inferno actually ran;
mocked specs are never reported as Inferno results.
