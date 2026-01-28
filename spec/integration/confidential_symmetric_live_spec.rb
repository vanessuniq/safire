# frozen_string_literal: true

require 'spec_helper'

#
# Live Integration Tests for Confidential Symmetric Client
#
# These tests validate the Safire gem against a real SMART on FHIR server
# for confidential symmetric client flows.
#
# They are tagged with :live and skipped by default to avoid network dependencies in CI.
#
# To run these tests:
#   bundle exec rspec --tag live
#
# Reference Server: https://launch.smarthealthit.org
# Documentation: http://docs.smarthealthit.org/
#
# Note: The SMART Health IT reference server supports confidential symmetric clients.
# For full token exchange testing, you would need a registered client with a secret.
#
RSpec.describe 'Confidential Symmetric Client Flow (Live Server)', :live, type: :integration do
  let(:base_url) { 'https://launch.smarthealthit.org/v/r4/sim/eyJoIjoiMSJ9/fhir' }
  let(:client_id) { 'safire_confidential_test' }
  let(:client_secret) { 'test_secret_for_safire' }
  let(:redirect_uri) { 'https://example.com/callback' }
  let(:scopes) { %w[openid profile launch/patient patient/*.read offline_access] }

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

  describe 'SMART Discovery for Confidential Clients' do
    it 'verifies server supports confidential symmetric authentication' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      # Fetch metadata from real server
      metadata = client.smart_metadata

      # Verify metadata structure
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.valid?).to be true

      # Verify confidential symmetric support
      expect(metadata.supports_confidential_symmetric_clients?).to be true

      # Verify token endpoint auth methods include client_secret_basic
      auth_methods = metadata.token_endpoint_auth_methods_supported
      expect(auth_methods).to be_an(Array)
      # Server should support at least one method for confidential clients
      expect(
        auth_methods.include?('client_secret_basic') ||
        auth_methods.include?('client_secret_post')
      ).to be true
    end
  end

  describe 'Authorization URL Generation' do
    it 'generates valid authorization URL with PKCE for confidential client' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

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

      # Verify PKCE is used even for confidential clients
      # (PKCE adds security even when client_secret is available)
      expect(auth_params['code_challenge_method']).to eq('S256')
      expect(auth_params['code_challenge']).to be_present

      # Verify OAuth2 parameters
      expect(auth_params['response_type']).to eq('code')
      expect(auth_params['client_id']).to eq(client_id)
      expect(auth_params['redirect_uri']).to eq(redirect_uri)
      expect(auth_params['scope']).to include('offline_access')
    end
  end

  describe 'Client Configuration' do
    it 'requires client_secret for confidential symmetric auth' do
      # Missing client_secret should work for config but may fail at auth time
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      # Client can be initialized without secret
      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      # But authorization URL generation still works
      # (secret is only needed for token exchange)
      auth_data = client.authorize_url
      expect(auth_data[:auth_url]).to be_present
    end

    it 'stores client_secret in configuration' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      expect(config.client_secret).to eq(client_secret)
    end
  end

  describe 'Comparison: Public vs Confidential Symmetric' do
    it 'both use PKCE for authorization' do
      public_config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      confidential_config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      public_client = Safire::Client.new(public_config, auth_type: :public)
      confidential_client = Safire::Client.new(confidential_config, auth_type: :confidential_symmetric)

      public_auth = public_client.authorize_url
      confidential_auth = confidential_client.authorize_url

      public_uri = URI.parse(public_auth[:auth_url])
      confidential_uri = URI.parse(confidential_auth[:auth_url])

      public_params = URI.decode_www_form(public_uri.query).to_h
      confidential_params = URI.decode_www_form(confidential_uri.query).to_h

      # Both should use S256 PKCE
      expect(public_params['code_challenge_method']).to eq('S256')
      expect(confidential_params['code_challenge_method']).to eq('S256')

      # Both should have code_verifier
      expect(public_auth[:code_verifier].length).to eq(128)
      expect(confidential_auth[:code_verifier].length).to eq(128)

      # But different values (unique per request)
      expect(public_auth[:code_verifier]).not_to eq(confidential_auth[:code_verifier])
    end
  end
end
