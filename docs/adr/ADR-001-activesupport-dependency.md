---
layout: default
title: "ADR-001: ActiveSupport as a runtime dependency"
parent: Architecture Decision Records
nav_order: 1
---

# ADR-001: ActiveSupport as a runtime dependency

**Status:** Accepted

---

## Context

Safire needs several utility methods throughout its codebase: presence checks (`present?`, `blank?`), string/array utilities, and safe object handling. There are three options:

**Option A — Implement utilities inline:** write custom `present?`, `blank?`, and other helpers inside the `Safire` module.

**Option B — Require individual ActiveSupport components:** use `require 'active_support/core_ext/object/blank'` and similar targeted requires to pull in only what is needed.

**Option C — `require 'active_support/all'`:** load the entire ActiveSupport library at once.

Option A introduces maintenance burden and drift from well-tested, community-maintained implementations. Option B requires tracking which AS components are used and updating requires when new utilities are adopted — a form of accidental complexity with no real benefit.

The key fact about ActiveSupport is that it uses Ruby's `autoload` mechanism internally. Even though `require 'active_support/all'` loads the autoload registry for all AS modules, the actual code for each module is only loaded when that module is first referenced. The memory overhead of `require 'active_support/all'` is therefore close to the overhead of targeted requires — the difference is measured in milliseconds at startup, not in runtime memory.

Safire is also commonly used alongside Rails applications, where ActiveSupport is already loaded. In that context, `require 'active_support/all'` is effectively a no-op.

---

## Decision

Use `require 'active_support/all'` and treat ActiveSupport as a first-class runtime dependency (`spec.add_dependency 'activesupport', '~> 8.0.0'`).

ActiveSupport utilities (`present?`, `blank?`, `fetch`, safe navigation, etc.) may be used freely throughout the codebase without needing to track individual requires.

---

## Consequences

**Benefits:**
- No custom utility reimplementations to maintain
- Any ActiveSupport method is available anywhere in the codebase without an explicit require
- No startup overhead in Rails applications (AS already loaded)
- Minimal overhead in non-Rails applications due to AS autoloading

**Trade-offs:**
- `activesupport` is pinned to `~> 8.0.0` — non-Rails Ruby applications must accept this dependency; a future major AS version bump requires a Safire dependency update
- Developers unfamiliar with AS may not recognise AS methods as external — mitigated by the fact that AS conventions (`present?`, `blank?`) are widely known in the Ruby ecosystem
