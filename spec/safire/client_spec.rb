require 'spec_helper'

RSpec.describe Safire::Client do
  # ---------------- Fixtures ----------------
  let(:smart_metadata) do
    {
      'authorization_endpoint' => 'https://fhir.example.com/authorize',
      'token_endpoint' => 'https://fhir.example.com/token',
      'code_challenge_methods_supported' => ['S256'],
      'capabilities' => %w[launch-standalone client-public client-confidential-symmetric]
    }
  end

  let(:base_config_hash) do
    {
      client_id: 'test_client_id',
      redirect_uri: 'https://app.example.com/callback',
      scopes: ['openid', 'profile', 'patient/*.read'],
      base_url: 'https://fhir.example.com',
      issuer: 'https://fhir.example.com'
    }
  end

  let(:config_obj)  { Safire::ClientConfig.new(base_config_hash) }
  let(:config_hash) { base_config_hash }

  let(:authorization_code) { 'auth_code_abc123' }
  let(:code_verifier)      { 'test_code_verifier_xyz789' }
  let(:refresh_token_val)  { 'refresh_token_456def' }

  let(:token_response_body) do
    {
      'access_token' => 'access_token_xyz789',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => 'openid profile patient/*.read'
    }
  end

  let(:refreshed_response_body) do
    {
      'access_token' => 'new_access_token_123ghi',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => 'openid profile patient/*.read',
      'refresh_token' => 'new_refresh_token_789jkl'
    }
  end

  # ---------------- Helpers ----------------
  def stub_discovery(for_base_url:)
    stub_request(:get, "#{for_base_url}/.well-known/smart-configuration")
      .to_return(status: 200, body: smart_metadata.to_json,
                 headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token_post(url:, body:, status:, response:)
    stub_request(:post, url)
      .with(body: body, headers: { 'Content-Type' => 'application/x-www-form-urlencoded' })
      .to_return(status: status, body: response.to_json,
                 headers: { 'Content-Type' => 'application/json' })
  end

  def basic_auth_header(id, secret)
    "Basic #{Base64.strict_encode64("#{id}:#{secret}")}"
  end

  def parse_query_params(url)
    Addressable::URI.parse(url).query_values
  end

  # ---------------- Initialization & type validation ----------------
  describe '#initialize' do
    it 'accepts a ClientConfig and preserves auth_type (default public)' do
      client = described_class.new(config_obj)
      expect(client.config).to be_a(Safire::ClientConfig)
      expect(client.auth_type).to eq(:public)
    end

    it 'accepts a Hash and wraps it in ClientConfig' do
      client = described_class.new(config_hash)
      expect(client.config).to be_a(Safire::ClientConfig)
      expect(client.config.client_id).to eq('test_client_id')
    end

    it 'raises for unsupported auth_type' do
      expect { described_class.new(config_obj, auth_type: :bogus) }
        .to raise_error(ArgumentError, /not supported/)
    end
  end

  # ---------------- Discovery ----------------
  describe '#smart_metadata' do
    it 'performs SMART discovery once and memoizes' do
      client = described_class.new(config_obj)
      stub_discovery(for_base_url: client.config.base_url)

      md1 = client.smart_metadata
      md2 = client.smart_metadata

      expect(md1.authorization_endpoint).to eq(smart_metadata['authorization_endpoint'])
      expect(md2.token_endpoint).to eq(smart_metadata['token_endpoint'])
    end
  end

  # ---------------- Authorization URL ----------------
  describe '#authorize_url' do
    let(:client) { described_class.new(config_obj) }

    before { stub_discovery(for_base_url: client.config.base_url) }

    it 'builds a valid auth URL with PKCE and state' do
      res = client.authorize_url
      expect(res).to include(:auth_url, :state, :code_verifier)

      qp = parse_query_params(res[:auth_url])
      expect(qp['response_type']).to eq('code')
      expect(qp['client_id']).to eq(config_obj.client_id)
      expect(qp['redirect_uri']).to eq(config_obj.redirect_uri)
      expect(qp['aud']).to eq(config_obj.issuer)
      expect(qp['scope']).to eq(config_obj.scopes.join(' '))
      expect(qp['code_challenge_method']).to eq('S256')
      expect(qp['code_challenge']).to be_present
      expect(res[:state]).to match(/\A[a-f0-9]{32}\z/)
      expect(res[:code_verifier]).to match(/\A[A-Za-z0-9_-]+\z/)
    end

    it 'passes through launch and custom_scopes' do
      launch = 'launch_token_123'
      scopes = %w[openid fhirUser]

      res = client.authorize_url(launch:, custom_scopes: scopes)
      qp = parse_query_params(res[:auth_url])

      expect(qp['launch']).to eq(launch)
      expect(qp['scope']).to eq(scopes.join(' '))
    end
  end

  # ---------------- Token exchange: public ----------------
  describe '#request_access_token (public)' do
    let(:client) { described_class.new(config_obj, auth_type: :public) }

    before do
      stub_discovery(for_base_url: client.config.base_url)
      stub_token_post(
        url: smart_metadata['token_endpoint'],
        body: {
          'grant_type' => 'authorization_code',
          'code' => authorization_code,
          'redirect_uri' => config_obj.redirect_uri,
          'code_verifier' => code_verifier,
          'client_id' => config_obj.client_id
        },
        status: 200,
        response: token_response_body
      )
    end

    it 'posts form-encoded body with client_id and returns string-keyed hash' do
      resp = client.request_access_token(code: authorization_code, code_verifier: code_verifier)
      expect(resp).to eq(token_response_body)
    end
  end

  # ---------------- Token exchange: confidential_symmetric ----------------
  describe '#request_access_token (confidential_symmetric)' do
    let(:confidential_cfg) { config_hash.merge(client_secret: 'top_secret') }
    let(:client) { described_class.new(confidential_cfg, auth_type: :confidential_symmetric) }

    before do
      stub_discovery(for_base_url: client.config.base_url)
      stub_request(:post, smart_metadata['token_endpoint'])
        .with(
          body: {
            'grant_type' => 'authorization_code',
            'code' => authorization_code,
            'redirect_uri' => client.config.redirect_uri,
            'code_verifier' => code_verifier
            # no client_id in body for confidential symmetric
          },
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization' => basic_auth_header(client.config.client_id, client.config.client_secret)
          }
        ).to_return(status: 200, body: token_response_body.to_json,
                    headers: { 'Content-Type' => 'application/json' })
    end

    it 'uses Basic auth and omits client_id from body' do
      resp = client.request_access_token(code: authorization_code, code_verifier: code_verifier)
      expect(resp).to eq(token_response_body)
    end
  end

  # ---------------- Refresh token ----------------
  describe '#refresh_token' do
    context 'when public client' do
      let(:client) { described_class.new(config_obj, auth_type: :public) }

      before do
        stub_discovery(for_base_url: client.config.base_url)
        stub_token_post(
          url: smart_metadata['token_endpoint'],
          body: {
            'grant_type' => 'refresh_token',
            'refresh_token' => refresh_token_val,
            'client_id' => client.config.client_id
          },
          status: 200,
          response: refreshed_response_body
        )
      end

      it 'exchanges refresh token (public body includes client_id)' do
        resp = client.refresh_token(refresh_token: refresh_token_val)
        expect(resp).to eq(refreshed_response_body)
      end

      it 'passes reduced scopes when provided' do
        reduced = %w[openid profile]
        stub_token_post(
          url: smart_metadata['token_endpoint'],
          body: {
            'grant_type' => 'refresh_token',
            'refresh_token' => refresh_token_val,
            'client_id' => client.config.client_id,
            'scope' => reduced.join(' ')
          },
          status: 200,
          response: refreshed_response_body
        )

        resp = client.refresh_token(refresh_token: refresh_token_val, scopes: reduced)
        expect(resp['access_token']).to eq('new_access_token_123ghi')
      end
    end

    context 'when confidential_symmetric' do
      let(:confidential_cfg) { config_hash.merge(client_secret: 'top_secret') }
      let(:client) { described_class.new(confidential_cfg, auth_type: :confidential_symmetric) }

      before do
        stub_discovery(for_base_url: client.config.base_url)
        stub_request(:post, smart_metadata['token_endpoint'])
          .with(
            body: {
              'grant_type' => 'refresh_token',
              'refresh_token' => refresh_token_val
              # no client_id
            },
            headers: {
              'Content-Type' => 'application/x-www-form-urlencoded',
              'Authorization' => basic_auth_header(client.config.client_id, client.config.client_secret)
            }
          ).to_return(status: 200, body: refreshed_response_body.to_json,
                      headers: { 'Content-Type' => 'application/json' })
      end

      it 'uses Basic auth and omits client_id' do
        resp = client.refresh_token(refresh_token: refresh_token_val)
        expect(resp).to eq(refreshed_response_body)
      end
    end
  end
end
