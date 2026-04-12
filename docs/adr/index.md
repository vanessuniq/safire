---
layout: default
title: Architecture Decision Records
nav_order: 8
has_children: true
permalink: /adr/
---

# Architecture Decision Records

Architecture Decision Records (ADRs) document significant design decisions made in Safire — what was decided, why, and what trade-offs were accepted.

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001]({% link adr/ADR-001-activesupport-dependency.md %}) | `ActiveSupport` as a runtime dependency | Accepted |
| [ADR-002]({% link adr/ADR-002-facade-and-forwardable.md %}) | Facade pattern — `Client` delegates to protocol implementations via `Forwardable` | Accepted |
| [ADR-003]({% link adr/ADR-003-protocol-vs-client-type.md %}) | `protocol:` and `client_type:` as orthogonal dimensions | Accepted |
| [ADR-004]({% link adr/ADR-004-clientconfig-immutability-and-entity-masking.md %}) | `ClientConfig` immutability and `Entity` sensitive attribute masking | Accepted |
| [ADR-005]({% link adr/ADR-005-per-client-http-ownership.md %}) | Per-client `HTTPClient` ownership — no shared connection pool | Accepted |
| [ADR-006]({% link adr/ADR-006-lazy-discovery.md %}) | Lazy SMART discovery — no HTTP in constructors | Accepted |
| [ADR-007]({% link adr/ADR-007-https-only-redirects-and-localhost-exception.md %}) | HTTPS-only redirect enforcement and localhost exception | Accepted |
| [ADR-008]({% link adr/ADR-008-warn-return-false-for-compliance-validation.md %}) | Warn and return false for compliance validation — raise only for configuration errors | Accepted |
| [ADR-009]({% link adr/ADR-009-oauth-error-hierarchy.md %}) | `OAuthError` base class and `ReceivesFields` mixin for protocol error hierarchy | Accepted |
| [ADR-010]({% link adr/ADR-010-optional-client-id-dcr-temp-client.md %}) | `client_id` optional at initialization — deferred validation for the DCR temp-client pattern | Accepted |