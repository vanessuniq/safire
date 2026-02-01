# Contributing to Safire

Thank you for your interest in contributing to Safire! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/safire.git
   cd safire
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/vanessuniq/safire.git
   ```

## Development Setup

### Requirements

- Ruby 4.0.1 or later
- Bundler

### Setup

```bash
# Install dependencies
bin/setup

# Run the test suite to verify setup
bundle exec rspec

# Start an interactive console
bin/console
```

### Running the Demo Application

```bash
bin/demo
```

Visit http://localhost:4567 to explore Safire's features interactively.

## Making Changes

### Branch Naming

Create a descriptive branch name:

- `feature/add-udap-discovery` - New features
- `fix/token-refresh-error` - Bug fixes
- `docs/update-readme` - Documentation updates
- `refactor/simplify-client-config` - Code refactoring

### Commit Messages

Write clear, concise commit messages:

- Use the imperative mood ("Add feature" not "Added feature")
- First line should be 50 characters or less
- Provide additional detail in the body if needed
- Reference issues when applicable (`Fixes #123`)

Example:
```
Add UDAP discovery endpoint support

- Implement /.well-known/udap endpoint fetching
- Add UdapMetadata class for parsing responses
- Include validation for required fields

Fixes #42
```

### Small, Focused Commits

- Each commit should represent a single logical change
- Keep commits small and reviewable
- Separate refactoring from new features

## Coding Standards

### Style Guide

This project uses [RuboCop](https://rubocop.org/) for code style enforcement:

```bash
# Check for style violations
bundle exec rubocop

# Auto-fix correctable violations
bundle exec rubocop -a
```

### Key Conventions

- **Naming**: Use descriptive names; prefer clarity over brevity
- **Methods**: Keep methods short and focused (under 15 lines when possible)
- **Classes**: Follow single responsibility principle
- **Documentation**: Add YARD documentation for public methods

### Example

```ruby
# Good: Clear, documented, follows conventions
module Safire
  module Protocols
    # Handles SMART on FHIR metadata discovery
    class SmartMetadata
      # Checks if the server supports EHR-initiated launches
      #
      # @return [Boolean] true if EHR launch is supported with required endpoints
      def supports_ehr_launch?
        ehr_launch_capability? && authorization_endpoint.present?
      end

      private

      def ehr_launch_capability?
        capability?('launch-ehr')
      end
    end
  end
end
```

## Testing

### Running Tests

```bash
# Run all tests
bundle exec rspec

# Run specific test file
bundle exec rspec spec/safire/client_spec.rb

# Run with documentation format
bundle exec rspec --format documentation

# Run integration tests
bundle exec rspec --tag live
```

### Writing Tests

- Place tests in `spec/` mirroring the `lib/` structure
- Use descriptive `describe` and `it` blocks
- Test edge cases and error conditions
- Use WebMock for HTTP stubbing (no real network calls in unit tests)

Example:
```ruby
RSpec.describe Safire::Client do
  describe '#smart_metadata' do
    context 'when server returns valid configuration' do
      it 'returns a SmartMetadata object' do
        stub_smart_configuration(valid_config)

        metadata = client.smart_metadata

        expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
        expect(metadata.token_endpoint).to eq('https://example.com/token')
      end
    end

    context 'when server returns 404' do
      it 'raises DiscoveryError' do
        stub_smart_configuration_not_found

        expect { client.smart_metadata }.to raise_error(Safire::Errors::DiscoveryError)
      end
    end
  end
end
```

### Test Coverage

- Aim for high test coverage on new code
- All public methods should have tests
- Include both happy path and error cases

## Submitting Changes

### Before Submitting

1. Ensure all tests pass:
   ```bash
   bundle exec rspec
   ```

2. Ensure code style is correct:
   ```bash
   bundle exec rubocop
   ```

3. Update documentation if needed:
   ```bash
   bundle exec yard doc
   ```

4. Verify Jekyll docs build (if you modified docs/):
   ```bash
   cd docs && bundle install && bundle exec jekyll build
   ```

5. Rebase on latest main:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Pull Request Process

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature
   ```

2. Open a Pull Request against `main`

3. Fill out the PR template with:
   - Summary of changes
   - Related issues
   - Test plan
   - Screenshots (if UI changes)

4. Wait for CI checks to pass

5. Address review feedback promptly

### PR Guidelines

- Keep PRs focused on a single concern
- Include tests for new functionality
- Update documentation as needed
- Respond to review comments constructively

## Reporting Issues

### Bug Reports

Include:
- Safire version (`Safire::VERSION`)
- Ruby version
- Steps to reproduce
- Expected vs actual behavior
- Error messages and stack traces
- Minimal reproduction code if possible

### Feature Requests

Include:
- Use case description
- Proposed solution (if any)
- Alternatives considered
- Relevant SMART/UDAP spec references

### Security Issues

For security vulnerabilities, please email the maintainers directly rather than opening a public issue.

## Questions?

- Open a [GitHub Discussion](https://github.com/vanessuniq/safire/discussions) for questions
- Check existing issues and documentation first
- Be respectful and patient

---

Thank you for contributing to Safire!
