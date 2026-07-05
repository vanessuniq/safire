---
layout: default
title: Home
nav_order: 1
permalink: /
description: "Safire is a Ruby gem implementing SMART App Launch 2.2.0 and UDAP Security STU2 for healthcare client applications."
---

# Safire Documentation

[![Gem Version](https://badge.fury.io/rb/safire.svg)](https://badge.fury.io/rb/safire)
[![CI](https://github.com/vanessuniq/safire/workflows/CI/badge.svg)](https://github.com/vanessuniq/safire/actions)

A lean Ruby gem implementing **[SMART App Launch](https://hl7.org/fhir/smart-app-launch/)** flows and **[UDAP Security STU2 / v2.0.0](https://hl7.org/fhir/us/udap-security/STU2/index.html)** discovery and Dynamic Client Registration for clients.

## Quick Navigation

| Section | Description |
|---------|-------------|
| [Getting Started]({{ site.baseurl }}/installation/) | Install Safire and quick start guide |
| [Configuration]({{ site.baseurl }}/configuration/) | All configuration options and parameters |
| [SMART]({{ site.baseurl }}/smart-on-fhir/) | App Launch (Public, Confidential Symmetric, Confidential Asymmetric) and Backend Services |
| [UDAP]({{ site.baseurl }}/udap/) | UDAP Security discovery plus certificate-backed Dynamic Client Registration |
| [Security Guide]({{ site.baseurl }}/security/) | HTTPS, credential protection, token storage, key rotation |
| [Advanced Examples]({{ site.baseurl }}/advanced/) | Caching, multi-server, token management, complete Rails integration |
| [Troubleshooting]({{ site.baseurl }}/troubleshooting/) | Common issues and solutions |
| [Safire API Docs]({{ site.baseurl }}/api/){:target="_blank"} | Complete YARD documentation |

## Features

### SMART App Launch

- Discovery (`/.well-known/smart-configuration`)
- Public Client (PKCE)
- Confidential Symmetric Client (client_secret + Basic Auth)
- Confidential Asymmetric Client (private_key_jwt with RS384/ES384)
- POST-Based Authorization
- Backend Services (client_credentials grant, JWT assertion, no user interaction or PKCE)

### UDAP Security (STU2)

- Discovery (`/.well-known/udap`) with optional community scoping
- Dynamic Client Registration metadata validation and normalization
- X.509-backed software-statement signing for registration, modification, and cancellation

JWT assertion authentication and Tiered OAuth remain planned. See
[ROADMAP.md](https://github.com/vanessuniq/safire/blob/main/ROADMAP.md) for
details.

## Demo Application

A Sinatra-based demo app is included to help you explore Safire's features:

```bash
bin/demo
```

Visit http://localhost:4567 to test SMART discovery, authorization flows, token management, and backend services token requests.

See [`examples/sinatra_app/README.md`](https://github.com/vanessuniq/safire/tree/main/examples/sinatra_app) for details.

## Community

- [GitHub Repository](https://github.com/vanessuniq/safire)
- [Issue Tracker](https://github.com/vanessuniq/safire/issues)
- [Architecture Decision Records]({{ site.baseurl }}/adr/) — design decisions and rationale

---

*Last updated: {{ site.time | date: '%B %d, %Y' }}*

*Parts of this project were developed with AI assistance (Claude Code) and reviewed by maintainers.*
