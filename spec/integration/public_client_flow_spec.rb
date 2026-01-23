# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Public Client End-to-End Flow', type: :integration do
  #
  # This test demonstrates a complete SMART on FHIR authorization flow
  # for a public client (using PKCE, no client secret).
  #
  # Flow:
  # 1. Discovery: Fetch /.well-known/smart-configuration
  # 2. Authorization: Build authorization URL with PKCE
  # 3. Token Exchange: Exchange authorization code for access token
  # 4. Token Refresh: Refresh the access token using refresh token
  #

  let(:base_url) { 'https://fhir.example.com' }
  let(:client_id) { 'test_public_client' }
  let(:redirect_uri) { 'https://myapp.example.com/callback' }
  let(:scopes) { ['openid', 'profile', 'patient/*.read'] }

  let(:smart_metadata) do
    {
      'issuer' => base_url,
      'authorization_endpoint' => "#{base_url}/authorize",
      'token_endpoint' => "#{base_url}/token",
      'grant_types_supported' => ['authorization_code', 'refresh_token'],
      'code_challenge_methods_supported' => ['S256'],
      'capabilities' => [
        'launch-standalone',
        'client-public',
        'sso-openid-connect',
        'context-standalone-patient'
      ],
      'scopes_supported' => scopes
    }
  end

  let(:authorization_code) { 'test_auth_code_123' }

  let(:token_response) do
    {
      'access_token' => 'test_access_token_abc',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => scopes.join(' '),
      'refresh_token' => 'test_refresh_token_xyz',
      'patient' => '123'
    }
  end

  let(:refreshed_token_response) do
    {
      'access_token' => 'new_access_token_def',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => scopes.join(' '),
      'refresh_token' => 'new_refresh_token_uvw'
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
    it 'executes discovery → authorization → token exchange → refresh' do
      # Initialize client configuration
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      # Initialize public client
      client = Safire::Client.new(config, auth_type: :public)

      # =====================================================
      # STEP 1: SMART Discovery
      # =====================================================
      metadata = client.smart_metadata

      # Verify discovery response
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.authorization_endpoint).to eq("#{base_url}/authorize")
      expect(metadata.token_endpoint).to eq("#{base_url}/token")
      expect(metadata.code_challenge_methods_supported).to include('S256')
      expect(metadata.supports_public_clients?).to be true
      expect(metadata.supports_standalone_launch?).to be true

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

      # Verify authorization URL structure
      expect(auth_uri.scheme).to eq('https')
      expect(auth_uri.host).to eq('fhir.example.com')
      expect(auth_uri.path).to eq('/authorize')

      # Verify required OAuth2 parameters
      expect(auth_params['response_type']).to eq('code')
      expect(auth_params['client_id']).to eq(client_id)
      expect(auth_params['redirect_uri']).to eq(redirect_uri)
      expect(auth_params['scope']).to eq(scopes.join(' '))
      expect(auth_params['aud']).to eq(base_url)

      # Verify state parameter (security)
      expect(auth_params['state']).to eq(auth_data[:state])
      expect(auth_data[:state]).to match(/\A[a-f0-9]{32}\z/) # 32 hex chars = 128 bits

      # Verify PKCE parameters
      expect(auth_params['code_challenge_method']).to eq('S256')
      expect(auth_params['code_challenge']).to be_present
      expect(auth_params['code_challenge'].length).to eq(43) # SHA256 base64url = 43 chars
      expect(auth_data[:code_verifier].length).to eq(128) # 128 characters

      # Verify code_challenge is derived from code_verifier
      expected_challenge = Safire::PKCE.generate_code_challenge(auth_data[:code_verifier])
      expect(auth_params['code_challenge']).to eq(expected_challenge)

      # =====================================================
      # STEP 3: Token Exchange (Authorization Code → Access Token)
      # =====================================================

      # Stub token endpoint for authorization code exchange
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'authorization_code',
            'code' => authorization_code,
            'redirect_uri' => redirect_uri,
            'code_verifier' => auth_data[:code_verifier],
            'client_id' => client_id # Public clients include client_id in body
          ),
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded'
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
      expect(tokens['access_token']).to eq('test_access_token_abc')
      expect(tokens['token_type']).to eq('Bearer')
      expect(tokens['expires_in']).to eq(3600)
      expect(tokens['refresh_token']).to eq('test_refresh_token_xyz')
      expect(tokens['scope']).to eq(scopes.join(' '))
      expect(tokens['patient']).to eq('123') # SMART context parameter

      # =====================================================
      # STEP 4: Token Refresh
      # =====================================================

      # Stub token endpoint for refresh token exchange
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'refresh_token',
            'refresh_token' => tokens['refresh_token'],
            'client_id' => client_id # Public clients include client_id in body
          ),
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded'
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
      expect(new_tokens).to be_a(Hash)
      expect(new_tokens['access_token']).to eq('new_access_token_def')
      expect(new_tokens['token_type']).to eq('Bearer')
      expect(new_tokens['refresh_token']).to eq('new_refresh_token_uvw')

      # Verify HTTP request was made without Authorization header (public client)
      expect(WebMock).to have_requested(:post, "#{base_url}/token")
        .with { |req| !req.headers.key?('Authorization') }
        .twice # Once for token exchange, once for refresh
    end

    it 'handles reduced scopes during token refresh' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Original refresh token from initial authorization
      original_refresh_token = 'test_refresh_token_xyz'

      # Request reduced scopes
      reduced_scopes = ['patient/Patient.read']

      # Stub token endpoint with reduced scopes
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'refresh_token',
            'refresh_token' => original_refresh_token,
            'scope' => reduced_scopes.join(' '),
            'client_id' => client_id
          )
        )
        .to_return(
          status: 200,
          body: {
            'access_token' => 'reduced_scope_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => reduced_scopes.join(' '),
            'refresh_token' => 'new_refresh_token'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      # Refresh with reduced scopes
      new_tokens = client.refresh_token(
        refresh_token: original_refresh_token,
        scopes: reduced_scopes
      )

      # Verify reduced scope in response
      expect(new_tokens['scope']).to eq(reduced_scopes.join(' '))
      expect(new_tokens['access_token']).to eq('reduced_scope_token')
    end
  end

  describe 'Error Handling' do
    it 'raises DiscoveryError when discovery endpoint returns 404' do
      stub_request(:get, "#{base_url}/.well-known/smart-configuration")
        .to_return(status: 404)

      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      expect { client.smart_metadata }.to raise_error(Safire::Errors::DiscoveryError)
    end

    it 'raises AuthError when token exchange fails' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Stub token endpoint to return OAuth error
      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 400,
          body: {
            'error' => 'invalid_grant',
            'error_description' => 'Authorization code has expired'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect do
        client.request_access_token(code: 'invalid_code', code_verifier: 'test_verifier')
      end.to raise_error(Safire::Errors::AuthError, /Failed to obtain access token/)
    end

    it 'raises AuthError when refresh token is invalid' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )

      client = Safire::Client.new(config, auth_type: :public)

      # Stub token endpoint to return OAuth error
      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 400,
          body: {
            'error' => 'invalid_grant',
            'error_description' => 'Refresh token is invalid or expired'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect do
        client.refresh_token(refresh_token: 'invalid_refresh_token')
      end.to raise_error(Safire::Errors::AuthError, /Failed to refresh access token/)
    end
  end
end
