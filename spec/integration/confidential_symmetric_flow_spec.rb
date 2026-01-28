# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Confidential Symmetric Client End-to-End Flow', type: :integration do
  #
  # This test demonstrates a complete SMART on FHIR authorization flow
  # for a confidential symmetric client (using client_secret with HTTP Basic auth).
  #
  # Flow:
  # 1. Discovery: Fetch /.well-known/smart-configuration
  # 2. Authorization: Build authorization URL with PKCE
  # 3. Token Exchange: Exchange authorization code for access token (with Basic auth)
  # 4. Token Refresh: Refresh the access token using refresh token (with Basic auth)
  #

  let(:base_url) { 'https://fhir.example.com' }
  let(:client_id) { 'test_confidential_client' }
  let(:client_secret) { 'super_secret_key_12345' }
  let(:redirect_uri) { 'https://myapp.example.com/callback' }
  let(:scopes) { ['openid', 'profile', 'patient/*.read', 'offline_access'] }

  # Base64 encoded client_id:client_secret for Basic auth
  let(:basic_auth_header) do
    Base64.strict_encode64("#{client_id}:#{client_secret}")
  end

  let(:smart_metadata) do
    {
      'issuer' => base_url,
      'authorization_endpoint' => "#{base_url}/authorize",
      'token_endpoint' => "#{base_url}/token",
      'grant_types_supported' => %w[authorization_code refresh_token],
      'code_challenge_methods_supported' => ['S256'],
      'token_endpoint_auth_methods_supported' => %w[client_secret_basic client_secret_post],
      'capabilities' => %w[
        launch-standalone
        client-public
        client-confidential-symmetric
        sso-openid-connect
        context-standalone-patient
        permission-offline
      ],
      'scopes_supported' => scopes
    }
  end

  let(:authorization_code) { 'confidential_auth_code_456' }

  let(:token_response) do
    {
      'access_token' => 'confidential_access_token_abc',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => scopes.join(' '),
      'refresh_token' => 'confidential_refresh_token_xyz',
      'patient' => '789'
    }
  end

  let(:refreshed_token_response) do
    {
      'access_token' => 'new_confidential_access_token_def',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => scopes.join(' '),
      'refresh_token' => 'new_confidential_refresh_token_uvw'
    }
  end

  before do
    # Stub SMART discovery endpoint
    stub_request(:get, "#{base_url}/.well-known/smart-configuration")
      .to_return(
        status: 200,
        body: smart_metadata.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  describe 'Complete Authorization Flow' do
    it 'executes discovery → authorization → token exchange → refresh with Basic auth' do
      # Initialize client configuration with client_secret
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      # Initialize confidential symmetric client
      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      # =====================================================
      # STEP 1: SMART Discovery
      # =====================================================
      metadata = client.smart_metadata

      # Verify discovery response
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.authorization_endpoint).to eq("#{base_url}/authorize")
      expect(metadata.token_endpoint).to eq("#{base_url}/token")
      expect(metadata.supports_confidential_symmetric_clients?).to be true
      expect(metadata.token_endpoint_auth_methods_supported).to include('client_secret_basic')

      # =====================================================
      # STEP 2: Authorization URL Generation
      # =====================================================
      auth_data = client.authorize_url

      # Verify authorization data structure
      expect(auth_data).to have_key(:auth_url)
      expect(auth_data).to have_key(:state)
      expect(auth_data).to have_key(:code_verifier)

      # Parse authorization URL
      auth_uri = URI.parse(auth_data[:auth_url])
      auth_params = URI.decode_www_form(auth_uri.query).to_h

      # Verify PKCE is still used (even for confidential clients)
      expect(auth_params['code_challenge_method']).to eq('S256')
      expect(auth_params['code_challenge']).to be_present
      expect(auth_data[:code_verifier].length).to eq(128)

      # =====================================================
      # STEP 3: Token Exchange with Basic Auth
      # =====================================================

      # Stub token endpoint - expect Basic auth header, NO client_id in body
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'authorization_code',
            'code' => authorization_code,
            'redirect_uri' => redirect_uri,
            'code_verifier' => auth_data[:code_verifier]
          ),
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization' => "Basic #{basic_auth_header}"
          }
        )
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      # Exchange authorization code for tokens
      tokens = client.request_access_token(
        code: authorization_code,
        code_verifier: auth_data[:code_verifier]
      )

      # Verify token response
      expect(tokens).to be_a(Hash)
      expect(tokens['access_token']).to eq('confidential_access_token_abc')
      expect(tokens['refresh_token']).to eq('confidential_refresh_token_xyz')
      expect(tokens['patient']).to eq('789')

      # Verify client_id is NOT in request body (it's in Basic auth header)
      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| !req.body.include?('client_id') })

      # =====================================================
      # STEP 4: Token Refresh with Basic Auth
      # =====================================================

      # Stub token endpoint for refresh
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'refresh_token',
            'refresh_token' => tokens['refresh_token']
          ),
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization' => "Basic #{basic_auth_header}"
          }
        )
        .to_return(
          status: 200,
          body: refreshed_token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      # Refresh access token
      new_tokens = client.refresh_token(refresh_token: tokens['refresh_token'])

      # Verify refreshed token response
      expect(new_tokens['access_token']).to eq('new_confidential_access_token_def')
      expect(new_tokens['refresh_token']).to eq('new_confidential_refresh_token_uvw')

      # Verify Basic auth was used for refresh (not client_id in body)
      expect(WebMock).to have_requested(:post, "#{base_url}/token")
        .with(headers: { 'Authorization' => "Basic #{basic_auth_header}" })
        .twice # Once for token exchange, once for refresh
    end
  end

  describe 'Basic Auth Header Verification' do
    it 'correctly encodes client_id:client_secret in Base64' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      # Stub token endpoint
      stub_request(:post, "#{base_url}/token")
        .with(headers: { 'Authorization' => /^Basic / })
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      # Verify the exact Basic auth header value
      expect(WebMock).to have_requested(:post, "#{base_url}/token")
        .with(headers: { 'Authorization' => "Basic #{basic_auth_header}" })

      # Decode and verify
      decoded = Base64.decode64(basic_auth_header)
      expect(decoded).to eq("#{client_id}:#{client_secret}")
    end

    it 'handles special characters in client_secret' do
      special_secret = 'secret!@#$%^&*()_+='
      encoded = Base64.strict_encode64("#{client_id}:#{special_secret}")

      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret: special_secret,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      expect(WebMock).to have_requested(:post, "#{base_url}/token")
        .with(headers: { 'Authorization' => "Basic #{encoded}" })
    end
  end

  describe 'Difference from Public Client' do
    let(:public_config) do
      Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )
    end

    let(:confidential_config) do
      Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )
    end

    it 'public client includes client_id in body, no Authorization header' do
      client = Safire::Client.new(public_config, auth_type: :public)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      # Public: client_id in body, no Authorization header
      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| req.body.include?('client_id') && !req.headers.key?('Authorization') })
    end

    it 'confidential symmetric client uses Basic auth, no client_id in body' do
      client = Safire::Client.new(confidential_config, auth_type: :confidential_symmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      # Confidential: Basic auth header, no client_id in body
      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| !req.body.include?('client_id') && req.headers['Authorization']&.start_with?('Basic ') })
    end
  end

  describe 'Error Handling' do
    it 'raises AuthError when client credentials are invalid' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret: 'wrong_secret',
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 401,
          body: {
            'error' => 'invalid_client',
            'error_description' => 'Client authentication failed'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect do
        client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')
      end.to raise_error(Safire::Errors::AuthError, /Failed to obtain access token/)
    end

    it 'raises AuthError when refresh token is invalid' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :confidential_symmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 400,
          body: {
            'error' => 'invalid_grant',
            'error_description' => 'Refresh token expired'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect do
        client.refresh_token(refresh_token: 'expired_token')
      end.to raise_error(Safire::Errors::AuthError, /Failed to refresh access token/)
    end
  end
end
