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

  describe '#initialize' do
    it 'defaults to protocol: :smart' do
      expect(described_class.new(config).protocol).to eq(:smart)
    end

    it 'defaults to client_type: :public' do
      expect(described_class.new(config).client_type).to eq(:public)
    end

    it 'raises ConfigurationError for unknown protocol' do
      expect { described_class.new(config, protocol: :bogus) }
        .to raise_error(Safire::Errors::ConfigurationError, /protocol.*bogus/i)
    end

    it 'raises ConfigurationError for invalid client_type for SMART' do
      expect { described_class.new(config, client_type: :bogus) }
        .to raise_error(Safire::Errors::ConfigurationError, /client_type.*bogus/i)
    end

    it 'symbolizes a string client_type keyword' do
      client = described_class.new(config, client_type: 'confidential_symmetric')
      expect(client.client_type).to eq(:confidential_symmetric)
    end
  end

  describe '#client_type=' do
    it 'changes the client type from public to confidential_symmetric' do
      client = described_class.new(config, client_type: :public)
      expect(client.client_type).to eq(:public)

      client.client_type = :confidential_symmetric
      expect(client.client_type).to eq(:confidential_symmetric)
    end

    it 'symbolizes string client types' do
      client = described_class.new(config)
      client.client_type = 'confidential_symmetric'
      expect(client.client_type).to eq(:confidential_symmetric)
    end

    it 'raises ConfigurationError for unsupported client types' do
      client = described_class.new(config)
      expect { client.client_type = :unsupported }
        .to raise_error(Safire::Errors::ConfigurationError, /client_type.*unsupported/i)
    end

    it 'updates client_type on the existing protocol client without rebuilding it' do
      stub_token_request(headers: { 'Authorization' => /^Basic / })

      client = described_class.new(config, client_type: :public)
      client.client_type = :confidential_symmetric

      tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')
      expect(tokens['access_token']).to eq('token123')

      expect(WebMock).to have_requested(:post, token_endpoint)
        .with(headers: { 'Authorization' => /^Basic / })
    end

    context 'when protocol does not support client_type (e.g. :udap)' do
      it 'logs a warning and returns without changing client_type' do
        client = described_class.new(config, protocol: :udap)

        allow(Safire.logger).to receive(:warn)
        client.client_type = :confidential_symmetric

        expect(Safire.logger).to have_received(:warn).with(/not configurable.*:udap/i)
        expect(client.client_type).to eq(:public)
      end
    end

    it 'does not re-discover endpoints when client_type changes' do
      discovery_config = Safire::ClientConfig.new(
        base_config_attrs.except(:authorization_endpoint, :token_endpoint)
                         .merge(client_secret: 'secret')
      )
      well_known_url = "#{base_url}/.well-known/smart-configuration"
      stub_request(:get, well_known_url).to_return(
        status: 200,
        body: { 'authorization_endpoint' => "#{base_url}/authorize",
                'token_endpoint' => token_endpoint,
                'capabilities' => [] }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
      stub_token_request(headers: { 'Authorization' => /^Basic / })

      client = described_class.new(discovery_config)
      client.server_metadata
      client.client_type = :confidential_symmetric
      client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

      expect(WebMock).to have_requested(:get, well_known_url).once
    end
  end

  # ---------- Authorization URL ----------

  describe '#authorization_url' do
    it 'returns auth_url, state, and code_verifier' do
      result = described_class.new(config).authorization_url
      expect(result).to include(:auth_url, :state, :code_verifier)
    end

    it 'accepts launch and custom_scopes' do
      result = described_class.new(config).authorization_url(launch: 'token', custom_scopes: %w[openid])
      expect(result[:auth_url]).to include('launch=token')
    end
  end

  # ---------- Server Metadata ----------

  describe '#server_metadata' do
    it 'returns SMART server metadata' do
      well_known_url = "#{base_url}/.well-known/smart-configuration"
      stub_request(:get, well_known_url).to_return(
        status: 200,
        body: { 'authorization_endpoint' => "#{base_url}/authorize",
                'token_endpoint' => token_endpoint,
                'capabilities' => [] }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
      discovery_config = Safire::ClientConfig.new(base_config_attrs.except(:authorization_endpoint, :token_endpoint))
      result = described_class.new(discovery_config).server_metadata
      expect(result).to be_a(Safire::Protocols::SmartMetadata)
    end
  end

  # ---------- Token Exchange ----------

  describe '#request_access_token' do
    context 'with public client_type' do
      before { stub_token_request(body_matcher: hash_including('client_id' => 'test_client_id')) }

      it 'includes client_id in request body' do
        client = described_class.new(config, client_type: :public)
        tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(body: hash_including('client_id'))
      end
    end

    context 'with confidential_symmetric client_type' do
      before { stub_token_request(headers: { 'Authorization' => /^Basic / }) }

      it 'uses Basic auth header' do
        client = described_class.new(config, client_type: :confidential_symmetric)
        tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(headers: { 'Authorization' => /^Basic / })
      end
    end

    context 'with confidential_asymmetric client_type' do
      before do
        stub_token_request(
          body_matcher: hash_including(
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          )
        )
      end

      it 'uses JWT assertion' do
        client = described_class.new(asymmetric_config, client_type: :confidential_asymmetric)
        tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(body: hash_including('client_assertion_type', 'client_assertion'))
      end

      it 'sends valid JWT with correct claims' do
        client = described_class.new(asymmetric_config, client_type: :confidential_asymmetric)
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

    context 'with public client_type' do
      before do
        stub_request(:post, token_endpoint)
          .with(body: hash_including('grant_type' => 'refresh_token', 'client_id' => 'test_client_id'))
          .to_return(status: 200, body: refresh_response.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'includes client_id in request body' do
        client = described_class.new(config, client_type: :public)
        tokens = client.refresh_token(refresh_token: 'old_refresh')

        expect(tokens['access_token']).to eq('token123')
        expect(WebMock).to have_requested(:post, token_endpoint)
          .with(body: hash_including('client_id'))
      end
    end

    context 'with confidential_asymmetric client_type' do
      before do
        stub_request(:post, token_endpoint)
          .with(body: hash_including(
            'grant_type' => 'refresh_token',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          ))
          .to_return(status: 200, body: refresh_response.to_json, headers: { 'Content-Type' => 'application/json' })
      end

      it 'uses JWT assertion' do
        client = described_class.new(asymmetric_config, client_type: :confidential_asymmetric)
        tokens = client.refresh_token(refresh_token: 'old_refresh')

        expect(tokens['access_token']).to eq('token123')
        expect(tokens['refresh_token']).to eq('new_refresh')
      end
    end
  end

  # ---------- Token Response Validation ----------

  describe '#token_response_valid?' do
    before { allow(Safire.logger).to receive(:warn) }

    let(:valid_response) do
      { 'access_token' => 'abc', 'token_type' => 'Bearer', 'scope' => 'openid' }
    end

    it 'returns true for a compliant response' do
      expect(described_class.new(config).token_response_valid?(valid_response)).to be(true)
    end

    it 'returns false and warns for a non-compliant response' do
      result = described_class.new(config).token_response_valid?({})
      expect(result).to be(false)
      expect(Safire.logger).to have_received(:warn).at_least(:once)
    end
  end

  # ---------- Backend Token ----------

  describe '#request_backend_token' do
    let(:backend_config_attrs) do
      {
        client_id: 'backend_client_id',
        base_url: base_url,
        token_endpoint: token_endpoint,
        private_key: rsa_private_key,
        kid: 'backend-key-id',
        scopes: %w[system/Patient.rs system/Observation.rs]
      }
    end

    let(:backend_config) { Safire::ClientConfig.new(backend_config_attrs) }

    let(:backend_token_response) do
      { 'access_token' => 'backend_token_abc', 'token_type' => 'Bearer',
        'expires_in' => 300, 'scope' => 'system/Patient.rs system/Observation.rs' }
    end

    before do
      stub_request(:post, token_endpoint)
        .with(body: hash_including('grant_type' => 'client_credentials'))
        .to_return(
          status: 200,
          body: backend_token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
    end

    it 'delegates to the protocol and returns the token response' do
      result = described_class.new(backend_config).request_backend_token
      expect(result['access_token']).to eq('backend_token_abc')
      expect(result['token_type']).to eq('Bearer')
    end

    it 'sends client_credentials grant with scope and JWT assertion' do
      described_class.new(backend_config).request_backend_token

      expect(WebMock).to have_requested(:post, token_endpoint)
        .with(body: hash_including(
          'grant_type' => 'client_credentials',
          'scope' => 'system/Patient.rs system/Observation.rs',
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        ))
    end

    it 'accepts a scopes override' do
      stub_request(:post, token_endpoint)
        .with(body: hash_including('scope' => 'system/Patient.rs'))
        .to_return(
          status: 200,
          body: backend_token_response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      described_class.new(backend_config).request_backend_token(scopes: %w[system/Patient.rs])

      expect(WebMock).to have_requested(:post, token_endpoint)
        .with(body: hash_including('scope' => 'system/Patient.rs'))
    end

    it 'defaults to system/*.rs scope when no scopes are configured' do
      cfg = Safire::ClientConfig.new(backend_config_attrs.except(:scopes))
      described_class.new(cfg).request_backend_token

      expect(WebMock).to have_requested(:post, token_endpoint)
        .with(body: hash_including('scope' => 'system/*.rs'))
    end
  end

  # ---------- Dynamic Client Registration ----------

  describe '#register_client' do
    it 'raises NotImplementedError' do
      expect { described_class.new(config).register_client }
        .to raise_error(NotImplementedError)
    end
  end
end
