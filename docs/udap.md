---
layout: default
title: UDAP
nav_order: 5
description: "Overview of planned UDAP Security protocol support in Safire, including UDAP discovery, dynamic client registration, JWT client authentication, and tiered OAuth for healthcare data exchange."
---

# UDAP

{: .no_toc }

<div class="code-example" markdown="1">
**Status:** Planned — see [ROADMAP.md](https://github.com/vanessuniq/safire/blob/main/ROADMAP.md) for timeline and progress.
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

UDAP (Unified Data Access Profiles) is a security framework for healthcare data exchange defined by the [UDAP Security Implementation Guide](https://hl7.org/fhir/us/udap-security/). It extends standard OAuth 2.0 with X.509 certificate-based identity, dynamic client registration, and trust community models — designed primarily for backend system-to-system integration and cross-organizational data access.

UDAP is a separate protocol from SMART. In Safire, it is selected via `protocol: :udap` rather than a `client_type:`. Watch the [GitHub repository](https://github.com/vanessuniq/safire) for release announcements.

---

## Planned Features

### Discovery

- **UDAP Discovery** (`/.well-known/udap`) — fetch server metadata and trust anchors

### Client Flows

- **Dynamic Client Registration (DCR)** — one-time registration using a signed software statement to obtain a `client_id`; required only when the client has not previously registered with the server and if the server supports DCR
- **JWT Client Authentication** — authenticate on every request using a signed JWT assertion (Authentication Token, AnT) with an X.509 certificate chain in the `x5c` header; the registered `client_id` is reused as `iss` and `sub` in each assertion
- **Tiered OAuth** — delegated authorization for multi-system access per the UDAP Security IG
- **Pushed Authorization Requests (RFC 9126)** — PAR support for pre-registering authorization requests

### Trust Framework

- **Certificate Validation** — verify server and client certificates against trust anchors
- **Trust Community Support** — integration with UDAP trust communities (e.g. Carequality, CommonWell)

---

## When to Use UDAP

| Scenario | Why UDAP |
|----------|----------|
| **Backend / B2B Integration** | Server-to-server flows without user interaction; certificate-based identity replaces pre-shared secrets |
| **Dynamic Client Registration** | Clients can register programmatically without manual server-side approval |
| **Cross-Organization Access** | Trust communities allow clients to be recognized across participant organizations without per-server registration |
| **High-Assurance Identity** | X.509 certificates provide stronger identity guarantees than client secrets |

---

## Comparison with SMART

| Feature | SMART | UDAP |
|---------|---------------|------|
| Primary use case | User-facing apps, EHR launch | B2B, backend services, cross-org access |
| Client registration | Pre-registered per server, optional DCR (recommended) | Dynamic (DCR) or pre-registered |
| Authentication | Client secrets or `private_key_jwt` | Signed JWT assertions (AnT) with X.509 `x5c` chain |
| Trust model | Per-server registration | Certificate-based trust communities |
| Safire selection | `client_type: :public / :confidential_symmetric / :confidential_asymmetric` | `protocol: :udap` (planned) |

### Resources

- [UDAP Security IG](https://hl7.org/fhir/us/udap-security/) — HL7 Implementation Guide
- [UDAP JWT Client Auth](https://www.udap.org/udap-jwt-client-auth.html) — JWT assertion specification
- [UDAP Dynamic Client Registration](https://www.udap.org/udap-dynamic-client-registration.html) — DCR specification
- [RFC 9126 — Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [UDAP Tiered OAuth](https://hl7.org/fhir/us/udap-security/b2b.html) — Delegated authorization