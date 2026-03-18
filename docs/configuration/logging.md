---
layout: default
title: Logging
parent: Configuration
nav_order: 2
---

# Logging

{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Global Logger Setup

Configure Safire's logger once at application startup via `Safire.configure`:

```ruby
# config/initializers/safire.rb
Safire.configure do |config|
  config.logger    = Rails.logger
  config.log_level = Rails.env.development? ? Logger::DEBUG : Logger::INFO
  config.log_http  = true  # default
end
```

By default, Safire logs to `$stdout` at `Logger::INFO`.

---

## Log Levels

| Level | Behaviour |
|-------|-----------|
| `Logger::DEBUG` | Verbose — all Safire internal operations |
| `Logger::INFO` | Standard — normal operation events (default) |
| `Logger::WARN` | Compliance warnings and non-critical issues only |
| `Logger::ERROR` | Errors only |

---

## HTTP Request Logging

When `log_http` is `true` (the default), Safire logs each outbound HTTP request and response. Sensitive data is automatically filtered:

- The `Authorization` header is replaced with `[FILTERED]`
- Request and response **bodies are never logged** — tokens and credentials are never captured

```ruby
Safire.configure do |config|
  config.log_http = false  # disable if not needed in production
end
```

---

## Environment Variables

### `SAFIRE_LOGGER`

By default Safire logs to `$stdout`. Set `SAFIRE_LOGGER` to a file path to redirect output:

```bash
SAFIRE_LOGGER=/var/log/safire.log
```

This only affects the **default logger**. If you set `config.logger` in `Safire.configure`, `SAFIRE_LOGGER` is ignored entirely.

| `SAFIRE_LOGGER` set? | `config.logger` set? | Log destination |
|----------------------|----------------------|-----------------|
| No | No | `$stdout` |
| Yes | No | File at that path |
| Either | Yes | Your custom logger |

---

## Next Steps

- [Client Setup]({{ site.baseurl }}/configuration/client-setup/) — client parameters, protocol, and credential protection
- [Troubleshooting]({{ site.baseurl }}/troubleshooting/) — common issues and solutions