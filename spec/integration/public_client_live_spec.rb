# frozen_string_literal: true

require 'spec_helper'

#
# Live Integration Tests using SMART Health IT Reference Server
#
# These tests validate the Safire gem against a real SMART on FHIR server.
# They are tagged with :live and skipped by default to avoid network dependencies in CI.
#
# To run these tests:
#   bundle exec rspec --tag live
#
# Reference Server: https://launch.smarthealthit.org
# Documentation: http://docs.smarthealthit.org/
#
RSpec.describe 'Public Client Flow (Live Server)', live: true, type: :integration do
  let(:base_url) { 'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir' }
  let(:client_id) { 'safire_test_client' }
  let(:redirect_uri) { 'https://example.com/callback' }
  let(:scopes) { %w[openid profile launch/patient patient/*.read] }

  before(:all) do
    # Allow real HTTP connections for live tests
    WebMock.allow_net_connect!

    # Check if we can reach the server before running tests
    uri = URI('https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir/.well-known/smart-configuration')
    Net::HTTP.get_response(uri)
  rescue StandardError => e
    skip "SMART reference server not reachable: #{e.message}"
  end

  after(:all) do
    # Re-disable network connections after live tests
    WebMock.disable_net_connect!
  end

  describe 'SMART Discovery' do
    it 'fetches and parses SMART metadata from live server' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Fetch metadata from real server
      metadata = client.smart_metadata

      # Verify metadata structure
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.valid?).to be true

      # Verify required endpoints
      expect(metadata.authorization_endpoint).to be_present
      expect(metadata.token_endpoint).to be_present
      expect(metadata.authorization_endpoint).to start_with('https://')
      expect(metadata.token_endpoint).to start_with('https://')

      # Verify PKCE support
      expect(metadata.code_challenge_methods_supported).to include('S256')

      # Verify capabilities
      expect(metadata.capabilities).to be_an(Array)
      expect(metadata.capabilities).not_to be_empty

      # Check for common SMART capabilities
      expect(metadata.supports_standalone_launch?).to be true
      expect(metadata.supports_public_clients?).to be true

      # Display discovered metadata for verification
      puts "\n=== SMART Metadata from Live Server ==="
      puts "Authorization Endpoint: #{metadata.authorization_endpoint}"
      puts "Token Endpoint: #{metadata.token_endpoint}"
      puts "Capabilities: #{metadata.capabilities.join(', ')}"
      puts "Scopes Supported: #{metadata.scopes_supported&.join(', ') || 'N/A'}"
      puts "======================================\n"
    end

    it 'handles server metadata with optional fields' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)
      metadata = client.smart_metadata

      # Optional fields may or may not be present
      # Just verify they're accessible without error
      expect { metadata.issuer }.not_to raise_error
      expect { metadata.jwks_uri }.not_to raise_error
      expect { metadata.registration_endpoint }.not_to raise_error
      expect { metadata.scopes_supported }.not_to raise_error
      expect { metadata.response_types_supported }.not_to raise_error
      expect { metadata.introspection_endpoint }.not_to raise_error
      expect { metadata.revocation_endpoint }.not_to raise_error
    end
  end

  describe 'Authorization URL Generation' do
    it 'generates valid authorization URL with PKCE for live server' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Generate authorization URL
      auth_data = client.authorize_url

      # Verify structure
      expect(auth_data).to have_key(:auth_url)
      expect(auth_data).to have_key(:state)
      expect(auth_data).to have_key(:code_verifier)

      # Parse URL
      auth_uri = URI.parse(auth_data[:auth_url])
      auth_params = URI.decode_www_form(auth_uri.query).to_h

      # Verify it points to the real server
      expect(auth_uri.host).to eq('launch.smarthealthit.org')
      expect(auth_uri.scheme).to eq('https')

      # Verify OAuth2 + PKCE parameters
      expect(auth_params['response_type']).to eq('code')
      expect(auth_params['client_id']).to eq(client_id)
      expect(auth_params['redirect_uri']).to eq(redirect_uri)
      expect(auth_params['scope']).to eq(scopes.join(' '))
      expect(auth_params['state']).to be_present
      expect(auth_params['code_challenge']).to be_present
      expect(auth_params['code_challenge_method']).to eq('S256')
      expect(auth_params['aud']).to eq(base_url)

      # Verify PKCE implementation
      expect(auth_data[:state].length).to eq(32) # 16 bytes hex = 32 chars
      expect(auth_data[:code_verifier].length).to eq(128)
      expect(auth_params['code_challenge'].length).to eq(43) # SHA256 base64url

      # Display generated URL for manual testing
      puts "\n=== Generated Authorization URL ==="
      puts "You can manually test this URL in a browser:"
      puts auth_data[:auth_url]
      puts "\nState (save this): #{auth_data[:state]}"
      puts "Code Verifier (save this): #{auth_data[:code_verifier]}"
      puts "====================================\n"
    end

    it 'includes launch parameter when provided' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Generate authorization URL with launch parameter
      launch_token = 'WzAsImU3NDhkNDNmLTY4N2YtNGQ3Yi05MGM3LTBmYjAyYjJhNjdkOCIsInNpbS1laHIiLDEsIiIsIiIsIiIsIiIsMCwxXQ'
      auth_data = client.authorize_url(launch: launch_token)

      # Parse URL
      auth_uri = URI.parse(auth_data[:auth_url])
      auth_params = URI.decode_www_form(auth_uri.query).to_h

      # Verify launch parameter included
      expect(auth_params['launch']).to eq(launch_token)
    end
  end

  describe 'PKCE Implementation Validation' do
    it 'generates RFC 7636 compliant code verifiers and challenges' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Generate multiple auth URLs to verify uniqueness
      auth_data_1 = client.authorize_url
      auth_data_2 = client.authorize_url

      # Verify verifiers are unique
      expect(auth_data_1[:code_verifier]).not_to eq(auth_data_2[:code_verifier])

      # Verify states are unique
      expect(auth_data_1[:state]).not_to eq(auth_data_2[:state])

      # Verify code_challenge is properly derived from code_verifier
      auth_uri_1 = URI.parse(auth_data_1[:auth_url])
      auth_params_1 = URI.decode_www_form(auth_uri_1.query).to_h

      expected_challenge = Safire::PKCE.generate_code_challenge(auth_data_1[:code_verifier])
      expect(auth_params_1['code_challenge']).to eq(expected_challenge)

      # Verify URL-safe base64 encoding (no +, /, =)
      expect(auth_data_1[:code_verifier]).not_to match(/[+\/=]/)
      expect(auth_params_1['code_challenge']).not_to match(/[+\/=]/)
    end
  end
end
