---
layout: default
title: UDAP
nav_order: 5
---

# UDAP

{: .no_toc }

<div class="code-example" markdown="1">
**Status:** Planned for future release
</div>

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

UDAP (Unified Data Access Profiles) provides a framework for trusted dynamic client registration and authentication using X.509 certificates. Safire will implement UDAP client flows to complement the existing SMART on FHIR support.

---

## Planned Features

### Discovery

- **UDAP Discovery** (`/.well-known/udap`) - Fetch server metadata and trust anchors

### Client Flows

- **Dynamic Client Registration** - Register clients using signed software statements
- **JWT Authentication** - Authenticate using X.509 certificates and JWT assertions
- **Tiered OAuth** - Support for delegated authorization (RFC 9126)

### Trust Framework

- **Certificate Validation** - Verify server and client certificates against trust anchors
- **Community Support** - Integration with UDAP trust communities

---

## When to Use UDAP

UDAP is designed for scenarios requiring:

| Scenario | Description |
|----------|-------------|
| **B2B Integration** | Server-to-server communication without user interaction |
| **Automated Registration** | Dynamic client registration without manual approval |
| **Trust Communities** | Participation in healthcare trust frameworks |
| **Cross-Organization** | Access across organizational boundaries |

---

## Comparison with SMART on FHIR

| Feature | SMART on FHIR | UDAP |
|---------|---------------|------|
| User-Facing Apps | Primary use case | Supported |
| Backend Services | Limited support | Primary use case |
| Client Registration | Manual (pre-registered) | Dynamic (automated) |
| Authentication | Client secrets or JWT | X.509 certificates |
| Trust Model | Per-server registration | Trust community anchors |

---

## Roadmap

1. **UDAP Discovery** - Implement `/.well-known/udap` endpoint fetching
2. **Certificate Management** - X.509 certificate loading and validation
3. **JWT Assertions** - Signed JWT generation for authentication
4. **Dynamic Registration** - Software statement creation and client registration
5. **Tiered OAuth** - Delegated authorization support

---

## Resources

- [UDAP Security IG](https://hl7.org/fhir/us/udap-security/) - HL7 Implementation Guide
- [Tiered OAuth RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) - Pushed Authorization Requests

---

## Stay Updated

UDAP support is actively being developed. Watch the [GitHub repository](https://github.com/vanessuniq/safire) for updates and release announcements.
