---
layout: default
title: "ADR-009: OAuthError base class and ReceivesFields mixin for protocol error hierarchy"
parent: Architecture Decision Records
nav_order: 9
---

# ADR-009: OAuthError base class and ReceivesFields mixin for protocol error hierarchy

**Status:** Accepted

---

## Context

Three protocol operations can return OAuth2-style error responses: token exchange (`TokenError`), authorization failure (`AuthError`), and dynamic client registration (`RegistrationError`). All three carry the same RFC-defined fields — HTTP `status`, an OAuth2 `error` code, and an `error_description` string — and all three produce structured error messages from those fields.

`TokenError` and `RegistrationError` have a second failure path: the server returns a 2xx response but omits the field the caller requires (`access_token` or `client_id`). In that case the error must report which fields were present in the response, without logging their values, to assist debugging without leaking data.

Without a shared foundation, each error class would duplicate the constructor, the attribute readers, and the message-building logic.

**Option A — Duplicate per class:** each error class independently defines `attr_reader :status, :error_code, :error_description`, its own constructor, and its own `build_message` method.

**Option B — Extract a shared base:** introduce `OAuthError < Error` with a template-method design; each subclass overrides `operation_label` to supply the lead phrase of the error message. Extract a `ReceivesFields` mixin for the structural failure path (`received_fields` attribute + constructor forwarding), included only by the two classes that need it.

---

## Decision

Option B — `OAuthError` as a shared base class with `ReceivesFields` as a private mixin.

```ruby
class OAuthError < Error
  attr_reader :status, :error_code, :error_description

  def initialize(status: nil, error_code: nil, error_description: nil)
    @status = status; @error_code = error_code; @error_description = error_description
    super(build_message)
  end

  private

  def operation_label
    raise NotImplementedError, "#{self.class} must define #operation_label"
  end

  def build_message
    parts = [operation_label]
    parts << "HTTP #{@status}" if @status
    parts << @error_code       if @error_code
    parts << @error_description if @error_description
    parts.join(' — ')
  end
end

module ReceivesFields
  def self.included(base) = base.attr_reader :received_fields
  def initialize(received_fields: nil, **) = (@received_fields = received_fields; super(**))
end

class TokenError        < OAuthError; include ReceivesFields; ... end
class AuthError         < OAuthError; ...                          end
class RegistrationError < OAuthError; include ReceivesFields; ... end
```

Each subclass defines only `operation_label` and, when needed, overrides `build_message` for the structural path.

---

## Consequences

**Benefits:**
- DRY: each concrete error class is a handful of lines; the shared attributes and message format are defined once
- Consistent error messages across all three operations; callers and log parsers see the same structure
- `ReceivesFields` is `@api private` — callers interact only with `TokenError` and `RegistrationError`; the mixin is an implementation detail
- Adding a new OAuth-style error (e.g. for a future introspection endpoint) requires only a new subclass with `operation_label`

**Trade-offs:**
- The `operation_label` template method raises `NotImplementedError` at runtime if a subclass forgets to define it; a compile-time check is not possible in Ruby
- `ReceivesFields` modifies the constructor via `super(**)` forwarding, which requires care when the inheritance chain has multiple `initialize` overrides

---

## Amendment: Shared protocol response handling

UDAP Dynamic Client Registration uses the same RFC 7591 success and OAuth-style
error response shapes as SMART registration. Keeping response translation as
private methods on `Protocols::Smart` would either couple UDAP to SMART or
duplicate parsing at the protocol trust boundary.

`Protocols::OAuthResponseHandling` now owns two private transformations shared
by protocol implementations:

- converting a Faraday error response into a typed `OAuthError` subclass
- validating and normalizing an RFC 7591 registration success response

The module accepts already-received response bodies. It does not send HTTP
requests, select endpoints, log response values, or apply protocol-specific
policy.

Registration success responses are normalized to string-keyed hashes and must
contain a non-blank string `client_id`, as required by RFC 7591. Missing
`client_id` responses continue to report only the received field names. A
present but blank or non-string `client_id` raises `RegistrationError` with a
structural error description. This intentionally hardens SMART registration:
valid RFC 7591 responses are unchanged, while malformed identifiers that were
previously accepted through `present?` now fail closed.

Malformed or non-object OAuth error bodies produce an error containing the HTTP
status only. Parsed JSON objects preserve their protocol error codes, including
UDAP-specific values such as `invalid_software_statement`.

### Amendment consequences

**Benefits:**

- SMART and UDAP share one auditable response boundary without sharing request
  construction or endpoint policy
- response key normalization makes direct and middleware-parsed hashes behave
  consistently
- malformed successful registrations fail before an invalid identifier reaches
  application state

**Trade-offs:**

- the private module contains generic OAuth error translation and
  registration-specific success validation; splitting two small transformations
  into separate objects would add indirection without creating an independent
  responsibility
- SMART servers returning a non-string `client_id` are now rejected even if an
  earlier Safire version accepted the malformed value
