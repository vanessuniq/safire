require 'spec_helper'

RSpec.describe 'SMART Backend Services End-to-End Flow', type: :integration do
  #
  # Tests the SMART Backend Services (system-to-system) flow per
  # https://hl7.org/fhir/smart-app-launch/backend-services.html
  #
  # Flow:
  # 1. (Optional) Discovery: Fetch /.well-known/smart-configuration
  # 2. Token Request: POST client_credentials grant + JWT assertion
  #
  # No redirect_uri, no PKCE, no authorization code.
  # scope is REQUIRED per the specification.
  #

  # ---------- Test Data ----------

  let(:base_url)        { 'https://fhir.example.com' }
  let(:token_endpoint)  { "#{base_url}/token" }
  let(:client_id)       { 'backend_system_client' }
  let(:scopes)          { %w[system/Patient.rs system/Observation.rs] }
  let(:kid)             { 'backend-rsa-key-001' }
  let(:rsa_private_key) { OpenSSL::PKey::RSA.generate(2048) }

  let(:smart_metadata) do
    {
      'issuer' => base_url,
      'token_endpoint' => token_endpoint,
      'grant_types_supported' => %w[authorization_code client_credentials],
      'token_endpoint_auth_methods_supported' => %w[private_key_jwt],
      'token_endpoint_auth_signing_alg_values_supported' => %w[RS384 ES384],
      'capabilities' => %w[client-confidential-asymmetric client-backend-services permission-v2],
      'scopes_supported' => %w[system/*.rs system/Patient.rs system/Observation.rs]
    }
  end

  let(:backend_token_response) do
    { 'access_token' => 'backend_access_token_xyz', 'token_type' => 'Bearer',
      'expires_in' => 300, 'scope' => scopes.join(' ') }
  end

  let(:backend_config_attrs) do
    {
      base_url:,
      client_id:,
      token_endpoint:,
      scopes:,
      private_key: rsa_private_key,
      kid:
    }
  end

  let(:backend_config) { Safire::ClientConfig.new(backend_config_attrs) }
  let(:client) { Safire::Client.new(backend_config) }

  # ---------- Helpers ----------

  def stub_discovery
    stub_request(:get, "#{base_url}/.well-known/smart-configuration")
      .to_return(status: 200, body: smart_metadata.to_json,
                 headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token_post(body_matcher: hash_including('grant_type' => 'client_credentials'),
                      response_body: backend_token_response)
    stub_request(:post, token_endpoint)
      .with(body: body_matcher)
      .to_return(status: 200, body: response_body.to_json,
                 headers: { 'Content-Type' => 'application/json' })
  end

  before { stub_discovery }

  # ---------- Discovery ----------

  describe 'Discovery' do
    it 'fetches SMART metadata advertising backend services support' do
      config = Safire::ClientConfig.new(backend_config_attrs.except(:token_endpoint))
      metadata = Safire::Client.new(config).server_metadata

      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.token_endpoint).to eq(token_endpoint)
      expect(metadata.grant_types_supported).to include('client_credentials')
      expect(metadata.token_endpoint_auth_methods_supported).to include('private_key_jwt')
    end
  end

  # ---------- Backend Token Request ----------

  describe 'Backend Token Request' do
    before { stub_token_post }

    it 'exchanges JWT assertion for an access token (token_endpoint hardcoded)' do
      tokens = client.request_backend_token

      expect(tokens['access_token']).to eq('backend_access_token_xyz')
      expect(tokens['token_type']).to eq('Bearer')
      expect(tokens['expires_in']).to eq(300)
      expect(tokens['scope']).to eq(scopes.join(' '))
    end

    it 'exchanges JWT assertion for an access token (token_endpoint via discovery)' do
      discovery_config = Safire::ClientConfig.new(backend_config_attrs.except(:token_endpoint))
      tokens = Safire::Client.new(discovery_config).request_backend_token

      expect(tokens['access_token']).to eq('backend_access_token_xyz')
    end

    it 'sends correct request body — no redirect_uri, no code, no PKCE, no Authorization header' do
      client.request_backend_token

      expect(WebMock).to(have_requested(:post, token_endpoint).with do |req|
        body = URI.decode_www_form(req.body).to_h
        body['grant_type'] == 'client_credentials' &&
          body['scope'] == scopes.join(' ') &&
          body['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
          body['client_assertion'].present? &&
          !body.key?('redirect_uri') &&
          !body.key?('code') &&
          !body.key?('code_verifier') &&
          !req.headers.key?('Authorization')
      end)
    end

    it 'generates a valid JWT assertion with correct claims' do
      client.request_backend_token

      expect(WebMock).to(have_requested(:post, token_endpoint).with do |req|
        body    = URI.decode_www_form(req.body).to_h
        decoded = JWT.decode(body['client_assertion'], rsa_private_key.public_key, true, algorithm: 'RS384')
        payload, header = decoded

        header['alg'] == 'RS384' &&
          header['kid'] == kid &&
          payload['iss'] == client_id &&
          payload['sub'] == client_id &&
          payload['aud'] == token_endpoint &&
          payload['jti'].present? &&
          payload['exp'].is_a?(Integer) &&
          payload['exp'] > Time.now.to_i
      end)
    end

    it 'supports EC keys with ES384 algorithm' do
      ec_key    = OpenSSL::PKey::EC.generate('secp384r1')
      ec_config = Safire::ClientConfig.new(backend_config_attrs.merge(private_key: ec_key, jwt_algorithm: 'ES384'))
      Safire::Client.new(ec_config).request_backend_token

      expect(WebMock).to(have_requested(:post, token_endpoint).with do |req|
        body    = URI.decode_www_form(req.body).to_h
        decoded = JWT.decode(body['client_assertion'], ec_key, true, algorithm: 'ES384')
        decoded[1]['alg'] == 'ES384' && decoded[1]['kid'] == kid
      end)
    end

    it 'overrides configured scopes when scopes: is provided' do
      stub_token_post(
        body_matcher: hash_including('scope' => 'system/Patient.rs'),
        response_body: backend_token_response.merge('scope' => 'system/Patient.rs')
      )
      tokens = client.request_backend_token(scopes: %w[system/Patient.rs])

      expect(WebMock).to have_requested(:post, token_endpoint)
        .with(body: hash_including('scope' => 'system/Patient.rs'))
      expect(tokens['scope']).to eq('system/Patient.rs')
    end
  end

  # ---------- Error Handling ----------

  describe 'Error Handling' do
    it 'raises ConfigurationError when scopes are missing' do
      cfg = Safire::ClientConfig.new(backend_config_attrs.except(:scopes))
      expect { Safire::Client.new(cfg).request_backend_token }
        .to raise_error(Safire::Errors::ConfigurationError, /scopes/)
    end

    it 'raises ConfigurationError when private_key is missing' do
      cfg = Safire::ClientConfig.new(backend_config_attrs.except(:private_key))
      expect { Safire::Client.new(cfg).request_backend_token }
        .to raise_error(Safire::Errors::ConfigurationError, /private_key/)
    end

    it 'raises ConfigurationError when kid is missing' do
      cfg = Safire::ClientConfig.new(backend_config_attrs.except(:kid))
      expect { Safire::Client.new(cfg).request_backend_token }
        .to raise_error(Safire::Errors::ConfigurationError, /kid/)
    end

    it 'raises TokenError when the server returns an error response' do
      stub_request(:post, token_endpoint)
        .to_return(
          status: 401,
          body: { 'error' => 'invalid_client', 'error_description' => 'JWT signature invalid' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      expect { client.request_backend_token }
        .to raise_error(Safire::Errors::TokenError, /Token request failed/)
    end

    it 'raises NetworkError on connection failure' do
      stub_request(:post, token_endpoint).to_raise(Faraday::ConnectionFailed)
      expect { client.request_backend_token }
        .to raise_error(Safire::Errors::NetworkError)
    end
  end
end
