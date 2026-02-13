# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Confidential Asymmetric Client End-to-End Flow', type: :integration do
  #
  # This test demonstrates a complete SMART on FHIR authorization flow
  # for a confidential asymmetric client (using private_key_jwt authentication).
  #
  # Flow:
  # 1. Discovery: Fetch /.well-known/smart-configuration
  # 2. Authorization: Build authorization URL with PKCE
  # 3. Token Exchange: Exchange authorization code for access token (with JWT assertion)
  # 4. Token Refresh: Refresh the access token using refresh token (with JWT assertion)
  #

  let(:base_url) { 'https://fhir.example.com' }
  let(:client_id) { 'test_confidential_asymmetric_client' }
  let(:redirect_uri) { 'https://myapp.example.com/callback' }
  let(:scopes) { %w[openid profile patient/*.read offline_access] }
  let(:kid) { 'test-key-id-123' }
  let(:jwks_uri) { 'https://myapp.example.com/.well-known/jwks.json' }

  # Generate RSA key for asymmetric auth
  let(:rsa_private_key) { OpenSSL::PKey::RSA.generate(2048) }

  let(:smart_metadata) do
    {
      'issuer' => base_url,
      'authorization_endpoint' => "#{base_url}/authorize",
      'token_endpoint' => "#{base_url}/token",
      'grant_types_supported' => %w[authorization_code refresh_token],
      'code_challenge_methods_supported' => ['S256'],
      'token_endpoint_auth_methods_supported' => %w[client_secret_basic private_key_jwt],
      'token_endpoint_auth_signing_alg_values_supported' => %w[RS384 ES384],
      'capabilities' => %w[
        launch-standalone
        client-public
        client-confidential-symmetric
        client-confidential-asymmetric
        sso-openid-connect
        context-standalone-patient
        permission-offline
      ],
      'scopes_supported' => scopes
    }
  end

  let(:authorization_code) { 'asymmetric_auth_code_789' }

  let(:token_response) do
    {
      'access_token' => 'asymmetric_access_token_abc',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => scopes.join(' '),
      'refresh_token' => 'asymmetric_refresh_token_xyz',
      'patient' => '456'
    }
  end

  let(:refreshed_token_response) do
    {
      'access_token' => 'new_asymmetric_access_token_def',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => scopes.join(' '),
      'refresh_token' => 'new_asymmetric_refresh_token_uvw'
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
    it 'executes discovery -> authorization -> token exchange -> refresh with JWT assertion' do
      # Initialize client configuration with asymmetric credentials
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        private_key: rsa_private_key,
        kid:,
        jwt_algorithm: 'RS384',
        jwks_uri:
      )

      # Initialize confidential asymmetric client
      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

      # =====================================================
      # STEP 1: SMART Discovery
      # =====================================================
      metadata = client.smart_metadata

      # Verify discovery response
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.authorization_endpoint).to eq("#{base_url}/authorize")
      expect(metadata.token_endpoint).to eq("#{base_url}/token")
      expect(metadata.supports_asymmetric_auth?).to be true
      expect(metadata.token_endpoint_auth_methods_supported).to include('private_key_jwt')
      expect(metadata.asymmetric_signing_algorithms_supported).to include('RS384')

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

      # Verify PKCE is still used (asymmetric clients also use PKCE)
      expect(auth_params['code_challenge_method']).to eq('S256')
      expect(auth_params['code_challenge']).to be_present
      expect(auth_data[:code_verifier].length).to eq(128)

      # =====================================================
      # STEP 3: Token Exchange with JWT Assertion
      # =====================================================

      # Stub token endpoint - expect JWT assertion, NO client_id or client_secret in body
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'authorization_code',
            'code' => authorization_code,
            'redirect_uri' => redirect_uri,
            'code_verifier' => auth_data[:code_verifier],
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          ),
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded'
          }
        ) do |req|
          # Verify client_assertion is present and valid
          body = URI.decode_www_form(req.body).to_h
          body['client_assertion'].present?
        end
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
      expect(tokens['access_token']).to eq('asymmetric_access_token_abc')
      expect(tokens['refresh_token']).to eq('asymmetric_refresh_token_xyz')
      expect(tokens['patient']).to eq('456')

      # Verify client_id is NOT in request body (it's in the JWT assertion)
      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| !req.body.include?('client_id=') })

      # Verify no Authorization header (asymmetric uses JWT in body, not Basic auth)
      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| !req.headers.key?('Authorization') })

      # =====================================================
      # STEP 4: Token Refresh with JWT Assertion
      # =====================================================

      # Stub token endpoint for refresh
      stub_request(:post, "#{base_url}/token")
        .with(
          body: hash_including(
            'grant_type' => 'refresh_token',
            'refresh_token' => tokens['refresh_token'],
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          ),
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded'
          }
        ) do |req|
          body = URI.decode_www_form(req.body).to_h
          body['client_assertion'].present?
        end
        .to_return(
          status: 200,
          body: refreshed_token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      # Refresh access token
      new_tokens = client.refresh_token(refresh_token: tokens['refresh_token'])

      # Verify refreshed token response
      expect(new_tokens['access_token']).to eq('new_asymmetric_access_token_def')
      expect(new_tokens['refresh_token']).to eq('new_asymmetric_refresh_token_uvw')
    end
  end

  describe 'JWT Assertion Verification' do
    it 'generates valid JWT assertion with correct claims' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        private_key: rsa_private_key,
        kid:,
        jwt_algorithm: 'RS384',
        jwks_uri:
      )

      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

      # Capture the JWT from the token request
      captured_jwt = nil

      stub_request(:post, "#{base_url}/token")
        .with do |req|
          body = URI.decode_www_form(req.body).to_h
          captured_jwt = body['client_assertion']
          true
        end
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      # Decode and verify JWT structure
      expect(captured_jwt).to be_present
      decoded = JWT.decode(captured_jwt, rsa_private_key.public_key, true, algorithm: 'RS384')
      payload = decoded[0]
      header = decoded[1]

      # Verify header
      expect(header['alg']).to eq('RS384')
      expect(header['typ']).to eq('JWT')
      expect(header['kid']).to eq(kid)

      # Verify claims
      expect(payload['iss']).to eq(client_id)
      expect(payload['sub']).to eq(client_id)
      expect(payload['aud']).to eq("#{base_url}/token")
      expect(payload['jti']).to be_present
      expect(payload['exp']).to be_a(Integer)
      expect(payload['exp']).to be > Time.now.to_i
    end

    it 'supports EC keys with ES384 algorithm' do
      ec_private_key = OpenSSL::PKey::EC.generate('secp384r1')

      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        private_key: ec_private_key,
        kid:,
        jwt_algorithm: 'ES384'
      )

      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

      captured_jwt = nil

      stub_request(:post, "#{base_url}/token")
        .with do |req|
          body = URI.decode_www_form(req.body).to_h
          captured_jwt = body['client_assertion']
          true
        end
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      # Verify ES384 algorithm
      decoded = JWT.decode(captured_jwt, ec_private_key, true, algorithm: 'ES384')
      expect(decoded[1]['alg']).to eq('ES384')
    end
  end

  describe 'Difference from Other Client Types' do
    let(:public_config) do
      Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:
      )
    end

    let(:symmetric_config) do
      Safire::ClientConfig.new(
        base_url:,
        client_id:,
        client_secret: 'test_secret',
        redirect_uri:,
        scopes:
      )
    end

    let(:asymmetric_config) do
      Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        private_key: rsa_private_key,
        kid:,
        jwt_algorithm: 'RS384'
      )
    end

    it 'public client includes client_id in body, no auth header' do
      client = Safire::Client.new(public_config, auth_type: :public)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| req.body.include?('client_id') && !req.headers.key?('Authorization') })
    end

    it 'symmetric client uses Basic auth header, no client_id in body' do
      client = Safire::Client.new(symmetric_config, auth_type: :confidential_symmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with { |req| !req.body.include?('client_id=') && req.headers['Authorization']&.start_with?('Basic ') })
    end

    it 'asymmetric client uses JWT assertion in body, no auth header' do
      client = Safire::Client.new(asymmetric_config, auth_type: :confidential_asymmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 200,
          body: token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')

      expect(WebMock).to(have_requested(:post, "#{base_url}/token")
        .with do |req|
          body = URI.decode_www_form(req.body).to_h
          !body.key?('client_id') &&
            body['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            body['client_assertion'].present? &&
            !req.headers.key?('Authorization')
        end)
    end
  end

  describe 'Error Handling' do
    it 'raises AuthError when private_key is missing' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        kid: # kid only, no private_key
      )

      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

      expect do
        client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')
      end.to raise_error(Safire::Errors::AuthError, /Missing required asymmetric credentials/)
    end

    it 'raises AuthError when kid is missing' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        private_key: rsa_private_key
        # No kid
      )

      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

      expect do
        client.request_access_token(code: 'test_code', code_verifier: 'test_verifier')
      end.to raise_error(Safire::Errors::AuthError, /Missing required asymmetric credentials/)
    end

    it 'raises AuthError when server returns invalid_client error' do
      config = Safire::ClientConfig.new(
        base_url:,
        client_id:,
        redirect_uri:,
        scopes:,
        private_key: rsa_private_key,
        kid:
      )

      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

      stub_request(:post, "#{base_url}/token")
        .to_return(
          status: 401,
          body: {
            'error' => 'invalid_client',
            'error_description' => 'Client authentication failed: JWT signature invalid'
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
        redirect_uri:,
        scopes:,
        private_key: rsa_private_key,
        kid:
      )

      client = Safire::Client.new(config, auth_type: :confidential_asymmetric)

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
