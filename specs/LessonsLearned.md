# Lessons Learned

**Project:** Safire SMART on FHIR Ruby Gem
**Purpose:** Track errors encountered and their solutions during development and testing

---

## 2026-01-22 - Initial Spec Compliance Review

### Finding: All Tests Pass ✅
**Status:** SUCCESS
**Context:** Baseline test run after SMART App Launch v2.2.0 specification review
**Result:** All 85 examples passed with 0 failures
**Action:** No fixes required - implementation is compliant with specification

### Analysis Complete
**Spec Version:** SMART App Launch STU 2.2.0
**Compliance:** FULL COMPLIANCE
**Documentation:** Created `SPEC_COMPLIANCE_ANALYSIS.md` with detailed findings

**Key Findings:**
- ✅ SMART discovery properly implemented
- ✅ PKCE implementation correct (S256, proper entropy)
- ✅ Public client auth workflow compliant
- ✅ Confidential symmetric client auth workflow compliant
- ✅ Refresh token flows for both auth types compliant
- ✅ All required parameters present
- ✅ Proper HTTP Basic authentication encoding
- ✅ Secure randomness for state and code_verifier

---

## Common Patterns & Best Practices

### Pattern: PKCE Implementation
**Lesson:** Always use `SecureRandom.urlsafe_base64` for code verifier generation
**Reason:** Ensures sufficient entropy (128 characters) and URL-safe encoding
**Code:**
```ruby
def self.generate_code_verifier
  SecureRandom.urlsafe_base64(96, padding: false) # 128 characters
end
```

### Pattern: State Parameter Generation
**Lesson:** Use `SecureRandom.hex(16)` for OAuth2 state parameter
**Reason:** Generates 32 hex characters = 128 bits of entropy (exceeds spec minimum of 122 bits)
**Code:**
```ruby
state: SecureRandom.hex(16)
```

### Pattern: HTTP Basic Authentication
**Lesson:** Use `Base64.strict_encode64` for OAuth2 Basic auth
**Reason:** Ensures proper encoding without line breaks
**Code:**
```ruby
"Basic #{Base64.strict_encode64("#{client_id}:#{client_secret}")}"
```

### Pattern: Conditional Parameters
**Lesson:** Use `.compact` to remove nil values from parameter hashes
**Reason:** Cleanly handles optional parameters like `launch`
**Code:**
```ruby
{
  response_type: 'code',
  client_id:,
  launch:,  # may be nil
  # ...
}.compact
```

### Pattern: Client ID in Request Body
**Lesson:** Only include `client_id` in token request for public clients
**Reason:** Confidential clients authenticate via HTTP Basic auth header
**Code:**
```ruby
params[:client_id] = client_id if auth_type == :public
```

---

## Testing Best Practices

### Pattern: WebMock for External HTTP Calls
**Lesson:** Always stub external HTTP requests in tests
**Reason:** Tests should be fast, deterministic, and not depend on external services
**Tool:** WebMock gem

### Pattern: Shared Examples for Common Behaviors
**Lesson:** Use RSpec shared examples for repeated test scenarios
**Benefit:** DRY tests, consistent validation
**Example:**
```ruby
shared_examples 'returns token response' do
  it 'returns access_token, token_type, expires_in' do
    expect(token_response['access_token']).to be_present
  end
end
```

### Pattern: Custom Matchers for Complex Assertions
**Lesson:** Create custom RSpec matchers for domain-specific validations
**Example:**
```ruby
RSpec::Matchers.define :have_basic_auth do |value|
  match { |request| request.headers['Authorization'] == value }
end
```

---

## Future Error Prevention

### Checklist: Adding New Auth Types
- [ ] Update `AUTH_TYPES` constant
- [ ] Implement parameter building method
- [ ] Implement header building method
- [ ] Add unit tests for new auth type
- [ ] Add integration tests
- [ ] Update documentation (README, YARD docs)
- [ ] Verify spec compliance

### Checklist: Modifying OAuth2 Flows
- [ ] Check SMART App Launch specification for requirements
- [ ] Validate parameter names and formats
- [ ] Test with both public and confidential clients
- [ ] Verify state/PKCE security requirements met
- [ ] Update tests to cover changes
- [ ] Run full test suite

---

## 2026-02-25 - SmartMetadata#valid? PKCE Content Validation

### Decision: valid? is a user-callable helper, not auto-invoked during discovery

**Context:** SMART App Launch 2.2.0 conformance analysis (PR-1) identified that `SmartMetadata#valid?`
checked field presence but not PKCE method content (`S256` inclusion, `plain` exclusion).

**Key architectural decision:** Safire's role is to discover the server configuration.
Server compliance checking is the **caller's responsibility**. `valid?` is a helper method
for users who want to verify conformance — it is **not** called automatically during discovery.

**Changes made:**
- `valid?` now checks `code_challenge_methods_supported` includes `'S256'` (SMART 2.2.0 SHALL)
- `valid?` now checks `code_challenge_methods_supported` does NOT include `'plain'` (SMART 2.2.0 SHALL NOT)
- Warnings are logged via `Safire.logger.warn` for each violation (non-blocking)
- Returns `false` when any check fails; never raises an exception

**Pattern: warn-and-return in validation helpers**
```ruby
# Correct pattern: log warning + return false (do not raise)
unless methods&.include?('S256')
  Safire.logger.warn("SMART metadata non-compliance: 'S256' is missing...")
  valid = false
end
```

**Testing pattern for logger warnings:**
Use the spy pattern (not `expect(...).to receive`):
```ruby
before { allow(Safire.logger).to receive(:warn) }

it 'logs warning when S256 is missing' do
  result = metadata.valid?
  expect(result).to be(false)
  expect(Safire.logger).to have_received(:warn).with(/'S256' is missing/)
end
```

**Prevention:** When adding new validation to helper methods that check external data,
always prefer warnings + false return over exceptions. Reserve exceptions for
configuration errors and unrecoverable states.

---

## 2026-01-22 - Test Duplication and Architecture

### Issue: Duplicate tests across client_spec.rb and smart_spec.rb

**Problem:** Found 11 duplicate tests between `spec/safire/client_spec.rb` and `spec/safire/protocols/smart_spec.rb`

**Root Cause:** `Safire::Client` is a thin wrapper/facade around `Safire::Protocols::Smart`. The Client class delegates all method calls to the Smart protocol implementation without adding additional logic.

**Analysis:**
- `client_spec.rb` tested the Client facade layer
- `smart_spec.rb` tested the Smart protocol implementation layer
- Since Client just delegates to Smart, the tests were functionally identical
- Integration tests in `public_client_flow_spec.rb` already verify the Client facade works correctly

**Solution:** Removed `spec/safire/client_spec.rb` entirely (11 tests)
- Implementation layer tests remain in `smart_spec.rb`
- Integration layer tests remain in `public_client_flow_spec.rb`
- This reduces test count from 90 to 79 without losing coverage

**Pattern:** When a class is a pure delegator/facade with no additional logic, test only:
1. The implementation layer (the class being delegated to)
2. The integration layer (end-to-end flows using the facade)

Skip testing the facade's delegation methods individually.

---

## 2026-01-22 - WebMock Configuration for Live Tests

### Issue: Live tests blocked by WebMock

**Problem:** Live integration tests tagged with `:live` were blocked by WebMock's `disable_net_connect!`

**Root Cause:** WebMock blocks all HTTP connections by default. The `before(:each)` hook runs after `before(:all)`, so the network was still disabled during the `before(:all)` connectivity check.

**Solution:** Explicitly enable network connections in the test file's `before(:all)` and `after(:all)` hooks:
```ruby
before(:all) do
  WebMock.allow_net_connect!
  # connectivity check and test setup
end

after(:all) do
  WebMock.disable_net_connect!
end
```

**Prevention:** For live tests, manage WebMock configuration at the test suite level, not via global hooks.

---

## 2026-01-22 - Integration Testing Strategy

### Decision: Two-Tier Testing Approach

**Context:** Implementing end-to-end tests for SMART on FHIR workflows

**Options Considered:**
1. Stubbed tests (WebMock) - Fast, isolated, no network dependencies
2. Live reference server tests - Real integration, validates against actual SMART server
3. Hybrid approach - Both stubbed and live tests

**Decision:** Implement **hybrid approach** with two test files:
- `spec/integration/public_client_flow_spec.rb` - Stubbed tests (fast, deterministic)
- `spec/integration/public_client_live_spec.rb` - Live reference server tests (real integration)

**Rationale:**
- Stubbed tests: Fast feedback, run in CI, test error paths easily
- Live tests: Validate against real SMART server, catch integration issues
- Live tests use SMART Health IT reference server: `https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir`
- Live tests tagged with `:live` metadata, skipped by default in CI

**Pattern:**
```ruby
# Stubbed test (default, fast)
RSpec.describe 'Public Client Flow', type: :integration do
  # Uses WebMock stubs
end

# Live test (optional, real server)
RSpec.describe 'Public Client Flow (Live)', type: :integration, :live do
  # Uses real SMART reference server
  # Tagged with :live, skipped by default
  # Run with: bundle exec rspec --tag live
end
```

---

## Notes

This file should be updated whenever:
1. A bug is discovered and fixed
2. A test fails and is corrected
3. A pattern emerges that should be documented
4. An architectural decision is made

Always include:
- Date
- Problem description
- Root cause
- Solution
- Prevention strategy
