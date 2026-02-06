require 'spec_helper'

RSpec.describe Safire::Client do
  # ---------- Test Data ----------

  let(:base_url) { 'https://fhir.example.com' }
  let(:token_endpoint) { "#{base_url}/token" }
  let(:rsa_private_key) { OpenSSL::PKey::RSA.generate(2048) }

  let(:base_config_attrs) do
    {
      client_id: 'test_client_id',
      redirect_uri: 'https://app.example.com/callback',
      scopes: ['openid', 'profile', 'patient/*.read'],
      base_url: base_url,
      authorization_endpoint: "#{base_url}/authorize",
      token_endpoint: token_endpoint
    }
  end

  let(:config) do
    Safire::ClientConfig.new(base_config_attrs.merge(client_secret: 'test_client_secret'))
  end

  let(:asymmetric_config) do
    Safire::ClientConfig.new(
      base_config_attrs.merge(
        private_key: rsa_private_key,
        kid: 'test-key-id',
        jwt_algorithm: 'RS384',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json'
      )
    )
  end

  let(:token_response) do
    { 'access_token' => 'token123', 'token_type' => 'Bearer', 'expires_in' => 3600 }
  end

  # ---------- Helpers ----------

  def stub_token_request(body_matcher: nil, headers: {})
    stub = stub_request(:post, token_endpoint)
    stub = stub.with(body: body_matcher) if body_matcher
    stub = stub.with(headers: headers) if headers.any?
    stub.to_return(
      status: 200,
      body: token_response.to_json,
      headers: { 'Content-Type' => 'application/json' }
    )
  end

  # ---------- Initialization ----------

  describe '#auth_type=' do
    it 'changes the auth type from public to confidential_symmetric' do
      client = described_class.new(config, auth_type: :public)
      expect(client.auth_type).to eq(:public)

      client.auth_type = :confidential_symmetric
      expect(client.auth_type).to eq(:confidential_symmetric)
    end

    it 'symbolizes string auth types' do
      client = described_class.new(config)
      client.auth_type = 'confidential_symmetric'
      expect(client.auth_type).to eq(:confidential_symmetric)
    end

    it 'raises ArgumentError for unsupported auth types' do
      client = described_class.new(config)
      expect { client.auth_type = :unsupported }.to raise_error(ArgumentError, /unsupported/)
    end

    it 'resets the internal smart_client so new auth type is used' do
      stub_token_request(headers: { 'Authorization' => /^Basic / })

      client = described_class.new(config, auth_type: :public)
      client.auth_type = :confidential_symmetric

      tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')
      expect(tokens['access_token']).to eq('token123')

      expect(WebMock).to have_requested(:post, token_endpoint)
        .with(headers: { 'Authorization' => /^Basic / })
    end
  end

  # ---------- Token Exchange ----------

  describe '#request_access_token' do
    context 'with public auth' do
      before { stub_token_request(body_matcher: hash_including('client_id' => 'test_client_id')) }

      it 'includes client_id in request body' do
        client = described_class.new(config, auth_type: :public)
        tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(body: hash_including('client_id'))
      end
    end

    context 'with confidential_symmetric auth' do
      before { stub_token_request(headers: { 'Authorization' => /^Basic / }) }

      it 'uses Basic auth header' do
        client = described_class.new(config, auth_type: :confidential_symmetric)
        tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(headers: { 'Authorization' => /^Basic / })
      end
    end

    context 'with confidential_asymmetric auth' do
      before do
        stub_token_request(
          body_matcher: hash_including(
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          )
        )
      end

      it 'uses JWT assertion' do
        client = described_class.new(asymmetric_config, auth_type: :confidential_asymmetric)
        tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(body: hash_including('client_assertion_type', 'client_assertion'))
      end

      it 'sends valid JWT with correct claims' do
        client = described_class.new(asymmetric_config, auth_type: :confidential_asymmetric)
        client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(WebMock).to(have_requested(:post, token_endpoint).with do |req|
          body = URI.decode_www_form(req.body).to_h
          jwt = body['client_assertion']
          decoded = JWT.decode(jwt, rsa_private_key.public_key, true, algorithm: 'RS384')
          decoded[0]['iss'] == 'test_client_id' &&
            decoded[0]['sub'] == 'test_client_id' &&
            decoded[1]['kid'] == 'test-key-id'
        end)
      end
    end
  end

  # ---------- Token Refresh ----------

  describe '#refresh_token' do
    let(:refresh_response) { token_response.merge('refresh_token' => 'new_refresh') }

    context 'with public auth' do
      before do
        stub_request(:post, token_endpoint)
          .with(body: hash_including('grant_type' => 'refresh_token', 'client_id' => 'test_client_id'))
          .to_return(status: 200, body: refresh_response.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'includes client_id in request body' do
        client = described_class.new(config, auth_type: :public)
        tokens = client.refresh_token(refresh_token: 'old_refresh')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(body: hash_including('client_id'))
      end
    end

    context 'with confidential_asymmetric auth' do
      before do
        stub_request(:post, token_endpoint)
          .with(body: hash_including(
            'grant_type' => 'refresh_token',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          ))
          .to_return(status: 200, body: refresh_response.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'uses JWT assertion' do
        client = described_class.new(asymmetric_config, auth_type: :confidential_asymmetric)
        tokens = client.refresh_token(refresh_token: 'old_refresh')

        expect(tokens['access_token']).to eq('token123')
        expect(tokens['refresh_token']).to eq('new_refresh')
      end
    end
  end
end
