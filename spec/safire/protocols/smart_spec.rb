require 'spec_helper'

RSpec.describe Safire::Protocols::Smart do
  # ---------- Test Data ----------

  let(:config) do
    {
      client_id: 'test_client_id',
      redirect_uri: 'https://app.example.com/callback',
      scopes: ['openid', 'profile', 'patient/*.read'],
      issuer: 'https://fhir.example.com',
      authorization_endpoint: 'https://fhir.example.com/authorize',
      token_endpoint: 'https://fhir.example.com/token'
    }
  end
  let(:confidential_config) { config.merge(client_secret: 'test_client_secret') }

  let(:smart_metadata_body) do
    {
      'authorization_endpoint' => 'https://fhir.example.com/authorize',
      'token_endpoint' => 'https://fhir.example.com/token',
      'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
      'grant_types_supported' => %w[authorization_code refresh_token],
      'scopes_supported' => ['openid', 'profile', 'launch', 'patient/*.read'],
      'response_types_supported' => ['code'],
      'capabilities' => %w[launch-ehr client-public client-confidential-symmetric],
      'code_challenge_methods_supported' => ['S256']
    }
  end

  let(:token_response_body) do
    { 'access_token' => 'access_token_xyz789', 'token_type' => 'Bearer', 'expires_in' => 3600,
      'scope' => 'openid profile patient/*.read' }
  end

  let(:refreshed_token_response_body) do
    {
      'access_token' => 'new_access_token_123ghi',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => 'openid profile patient/*.read',
      'refresh_token' => 'new_refresh_token_789jkl'
    }
  end

  # ---------- Helpers / Matchers ----------

  def parse_query_params(url)
    Addressable::URI.parse(url).query_values
  end

  def stub_token_post(body_params:, status:, body:, headers: {})
    stub_request(:post, config[:token_endpoint]).with(
      body: body_params,
      headers: { 'Content-Type' => 'application/x-www-form-urlencoded' }.merge(headers)
    ).to_return(
      status: status,
      body: body.to_json,
      headers: { 'Content-Type' => 'application/json' }
    )
  end

  def stub_well_known(issuer: config[:issuer], status: 200, body: smart_metadata_body)
    well_known_url = "#{issuer.to_s.chomp('/')}#{described_class::WELL_KNOWN_PATH}"
    stub_request(:get, well_known_url).to_return(
      status: status, body: body.to_json, headers: { 'Content-Type' => 'application/json' }
    )
  end

  def basic_auth_header(client_id, client_secret)
    "Basic #{Base64.strict_encode64("#{client_id}:#{client_secret}")}"
  end

  RSpec::Matchers.define :have_basic_auth do |value|
    match do |request|
      request.headers['Authorization'] == value
    end
    failure_message { "expected Authorization header to equal #{value.inspect}" }
  end

  RSpec::Matchers.define :body_excludes_keys do |*keys|
    match do |request|
      keys.all? { |k| request.body[k.to_s].nil? }
    end
  end

  # ---------- Shared Contexts / Bodies ----------

  shared_context 'with auth code bodies' do
    let(:authorization_code) { 'auth_code_abc123' }
    let(:code_verifier) { 'test_code_verifier_xyz789' }

    let(:public_auth_code_body) do
      {
        'grant_type' => 'authorization_code',
        'code' => authorization_code,
        'redirect_uri' => config[:redirect_uri],
        'code_verifier' => code_verifier,
        'client_id' => config[:client_id]
      }
    end

    let(:confidential_auth_code_body) do
      {
        'grant_type' => 'authorization_code',
        'code' => authorization_code,
        'redirect_uri' => config[:redirect_uri],
        'code_verifier' => code_verifier
        # no client_id
      }
    end
  end

  shared_context 'with refresh bodies' do
    let(:refresh_token_value) { 'refresh_token_456def' }

    let(:public_refresh_body) do
      {
        'grant_type' => 'refresh_token',
        'refresh_token' => refresh_token_value,
        'client_id' => config[:client_id]
      }
    end

    let(:confidential_refresh_body) do
      {
        'grant_type' => 'refresh_token',
        'refresh_token' => refresh_token_value
        # no client_id
      }
    end
  end

  # ---------- Initialization ----------

  describe '#initialize' do
    it 'creates a public client with valid config' do
      client = described_class.new(config, auth_type: :public)
      expect(client.auth_type).to eq(:public)
      described_class::ATTRIBUTES.each { |attr| expect(client.send(attr)).to eq(config[attr]) }
    end

    it 'creates a confidential symmetric client' do
      client = described_class.new(confidential_config, auth_type: :confidential_symmetric)
      expect(client.auth_type).to eq(:confidential_symmetric)
      expect(client.client_secret).to eq(confidential_config[:client_secret])
    end

    it 'defaults auth_type to public' do
      expect(described_class.new(config).auth_type).to eq(:public)
    end

    it 'symbolizes string auth_type' do
      expect(described_class.new(config, auth_type: 'public').auth_type).to eq(:public)
    end

    it 'allows scopes and client_secret to be optional' do
      client = described_class.new(config.except(:scopes, :client_secret))
      expect(client.scopes).to be_nil
      expect(client.client_secret).to be_nil
    end

    it 'raises ConfigurationError when a required attribute is missing' do
      %i[client_id redirect_uri issuer].each do |attr|
        expect { described_class.new(config.except(attr)) }
          .to raise_error(Safire::Errors::ConfigurationError, /#{attr}/)
      end
    end

    it 'fetches endpoints from well-known when not provided' do
      stub_well_known
      client = described_class.new(config.except(:authorization_endpoint, :token_endpoint))
      expect(client.authorization_endpoint).to eq(smart_metadata_body['authorization_endpoint'])
      expect(client.token_endpoint).to eq(smart_metadata_body['token_endpoint'])
    end
  end

  # ---------- Well-known Discovery ----------

  describe '#well_known_config' do
    let(:well_known_url) { "#{config[:issuer]}#{described_class::WELL_KNOWN_PATH}" }

    it 'fetches and exposes metadata' do
      stub_well_known
      metadata = described_class.new(config).well_known_config
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.authorization_endpoint).to eq(smart_metadata_body['authorization_endpoint'])
      expect(metadata.token_endpoint).to eq(smart_metadata_body['token_endpoint'])
      expect(metadata.capabilities).to eq(smart_metadata_body['capabilities'])
    end

    it 'raises on 404' do
      stub_request(:get, well_known_url).to_return(status: 404)
      expect { described_class.new(config).well_known_config }
        .to raise_error(Safire::Errors::DiscoveryError, /Failed to discover SMART configuration/)
    end

    it 'raises on invalid JSON' do
      stub_request(:get, well_known_url).to_return(status: 200, body: 'not-json')
      expect { described_class.new(config).well_known_config }
        .to raise_error(Safire::Errors::DiscoveryError)
    end

    it 'raises when response is not a hash' do
      stub_request(:get, well_known_url).to_return(status: 200, body: '[]',
                                                   headers: { 'Content-Type' => 'application/json' })
      expect { described_class.new(config).well_known_config }
        .to raise_error(Safire::Errors::DiscoveryError, /expected JSON object/)
    end

    it 'handles issuer with or without trailing slash' do
      stub_well_known(issuer: 'https://fhir.example.com/')
      expect do
        described_class.new(config.merge(issuer: 'https://fhir.example.com/')).well_known_config
      end.not_to raise_error

      stub_well_known(issuer: 'https://fhir.example.com')
      expect { described_class.new(config).well_known_config }.not_to raise_error
    end
  end

  # ---------- Authorization URL ----------

  describe '#authorization_url' do
    let(:client) { described_class.new(config) }
    let(:auth_data) { client.authorization_url }
    let(:query_params) { parse_query_params(auth_data[:auth_url]) }

    shared_examples 'valid authorization response' do
      it 'returns url, state, and code_verifier' do
        expect(auth_data.keys).to contain_exactly(:auth_url, :state, :code_verifier)
        expect(auth_data[:state]).to match(/\A[a-f0-9]{32}\z/)
        expect(auth_data[:code_verifier]).to match(/\A[A-Za-z0-9_-]+\z/)
        expect(auth_data[:code_verifier].length).to eq(128)
      end
    end

    shared_examples 'includes core oauth and pkce' do
      it 'includes response_type/client_id/redirect_uri/aud' do
        expect(query_params.values_at('response_type', 'client_id', 'redirect_uri', 'aud'))
          .to eq(['code', config[:client_id], config[:redirect_uri], config[:issuer]])
      end

      it 'includes S256 challenge' do
        expect(query_params['code_challenge_method']).to eq('S256')
        expect(query_params['code_challenge']).to match(/\A[A-Za-z0-9_-]{43}\z/)
        expect(query_params['code_challenge']).to eq(Safire::PKCE.generate_code_challenge(auth_data[:code_verifier]))
      end
    end

    it_behaves_like 'valid authorization response'
    it_behaves_like 'includes core oauth and pkce'

    it 'includes configured scopes' do
      expect(query_params['scope']).to eq(config[:scopes].join(' '))
    end

    it 'raises when no scopes configured' do
      expect { described_class.new(config.except(:scopes)).authorization_url }
        .to raise_error(Safire::Errors::ConfigurationError, /requires scopes/)
    end

    it 'uses custom scopes when provided' do
      cs = %w[custom.scope1 custom.scope2]
      custom = described_class.new(config).authorization_url(custom_scopes: cs)
      expect(parse_query_params(custom[:auth_url])['scope']).to eq(cs.join(' '))
    end

    it 'supports launch parameter' do
      launched = described_class.new(config).authorization_url(launch: 'launch_token_123')
      expect(parse_query_params(launched[:auth_url])['launch']).to eq('launch_token_123')
      no_launch = described_class.new(config).authorization_url
      expect(parse_query_params(no_launch[:auth_url]).key?('launch')).to be(false)
    end

    it 'produces unique state/verifier/challenge per call' do
      states = 3.times.map { described_class.new(config).authorization_url[:state] }
      expect(states.uniq.size).to eq(3)
    end

    it 'encodes scopes and redirect_uri properly' do
      cs = ['patient/*.read', 'user/Observation.read']
      data = described_class.new(config).authorization_url(custom_scopes: cs)
      expect(data[:auth_url]).to include('patient%2F%2A.read')

      cfg2 = config.merge(redirect_uri: 'https://app.example.com/callback?param=value')
      data2 = described_class.new(cfg2).authorization_url
      expect(data2[:auth_url]).to include(CGI.escape(cfg2[:redirect_uri]))
    end
  end

  # ---------- Token Exchange ----------

  describe '#request_access_token' do
    include_context 'with auth code bodies'

    shared_examples 'returns token response' do
      it 'returns access_token, token_type, expires_in' do
        expect(token_response).to be_a(Hash)
        expect(token_response['access_token']).to eq('access_token_xyz789')
        expect(token_response['token_type']).to eq('Bearer')
        expect(token_response['expires_in']).to eq(3600)
      end
    end

    context 'when public lcient' do
      subject(:token_response) do
        described_class.new(config, auth_type: :public)
                       .request_access_token(code: authorization_code, code_verifier: code_verifier)
      end

      before do
        stub_token_post(body_params: public_auth_code_body, status: 200, body: token_response_body)
      end

      it_behaves_like 'returns token response'

      it 'includes client_id in request body' do
        token_response

        expect(WebMock).to have_requested(:post, config[:token_endpoint])
          .with(body: hash_including('client_id' => config[:client_id]))
      end

      it 'does not include Authorization header' do
        token_response

        expect(WebMock).to(have_requested(:post, config[:token_endpoint])
          .with { |req| !req.headers.key?('Authorization') })
      end
    end

    context 'when confidential_symmetric' do
      subject(:token_response) do
        described_class.new(confidential_config, auth_type: :confidential_symmetric)
                       .request_access_token(code: authorization_code, code_verifier: code_verifier)
      end

      let(:auth_header) { basic_auth_header(confidential_config[:client_id], confidential_config[:client_secret]) }

      before do
        stub_token_post(
          body_params: confidential_auth_code_body,
          status: 200,
          body: token_response_body,
          headers: { 'Authorization' => auth_header }
        )
      end

      it_behaves_like 'returns token response'

      it 'uses Basic auth and omits client_id' do
        token_response
        expect(WebMock).to(have_requested(:post, config[:token_endpoint]).with do |req|
          have_basic_auth(auth_header).matches?(req) && body_excludes_keys(:client_id).matches?(req)
        end)
      end
    end

    context 'when invalid response (missing access_token)' do
      it 'raises AuthError' do
        stub_token_post(
          body_params: {
            'grant_type' => 'authorization_code',
            'code' => 'auth_code_abc123',
            'redirect_uri' => config[:redirect_uri],
            'code_verifier' => 'test_code_verifier_xyz789',
            'client_id' => config[:client_id]
          },
          status: 200,
          body: { 'token_type' => 'Bearer', 'expires_in' => 3600 }
        )
        expect do
          described_class.new(config, auth_type: :public)
                         .request_access_token(code: 'auth_code_abc123', code_verifier: 'test_code_verifier_xyz789')
        end.to raise_error(Safire::Errors::AuthError, /Missing access token/)
      end
    end

    context 'when server OAuth error' do
      it 'raises AuthError' do
        stub_token_post(
          body_params: {
            'grant_type' => 'authorization_code',
            'code' => 'bad',
            'redirect_uri' => config[:redirect_uri],
            'code_verifier' => 'v',
            'client_id' => config[:client_id]
          },
          status: 400,
          body: { 'error' => 'invalid_grant' }
        )
        expect do
          described_class.new(config, auth_type: :public)
                         .request_access_token(code: 'bad', code_verifier: 'v')
        end.to raise_error(Safire::Errors::AuthError, /Failed to obtain access token/)
      end
    end

    context 'when network error' do
      it 'raises AuthError' do
        stub_request(:post, config[:token_endpoint]).to_raise(Faraday::ConnectionFailed)
        expect do
          described_class.new(config, auth_type: :public)
                         .request_access_token(code: 'x', code_verifier: 'y')
        end.to raise_error(Safire::Errors::AuthError)
      end
    end
  end

  # ---------- Refresh ----------

  describe '#refresh_token' do
    include_context 'with refresh bodies'

    context 'when public client' do
      before do
        stub_token_post(
          body_params: public_refresh_body,
          status: 200,
          body: refreshed_token_response_body
        )
      end

      it 'returns refreshed tokens' do
        res = described_class.new(config, auth_type: :public)
                             .refresh_token(refresh_token: refresh_token_value)
        expect(res).to eq(refreshed_token_response_body)
      end
    end

    context 'when public with custom scopes' do
      let(:custom_scopes) { %w[openid profile] }

      before do
        stub_token_post(
          body_params: public_refresh_body.merge('scope' => custom_scopes.join(' ')),
          status: 200,
          body: refreshed_token_response_body
        )
      end

      it 'includes scopes in request' do
        res = described_class.new(config, auth_type: :public)
                             .refresh_token(refresh_token: refresh_token_value, scopes: custom_scopes)
        expect(res['access_token']).to eq('new_access_token_123ghi')
      end
    end

    context 'when confidential_symmetric' do
      let(:auth_header) { basic_auth_header(confidential_config[:client_id], confidential_config[:client_secret]) }

      before do
        stub_token_post(
          body_params: confidential_refresh_body,
          status: 200,
          body: refreshed_token_response_body,
          headers: { 'Authorization' => auth_header }
        )
      end

      it 'uses Basic auth and omits client_id' do
        res = described_class.new(confidential_config, auth_type: :confidential_symmetric)
                             .refresh_token(refresh_token: refresh_token_value)
        expect(res).to eq(refreshed_token_response_body)

        expect(WebMock).to(have_requested(:post, config[:token_endpoint]).with do |req|
          have_basic_auth(auth_header).matches?(req) && body_excludes_keys(:client_id).matches?(req)
        end)
      end
    end

    it 'raises AuthError on invalid refresh token' do
      stub_token_post(
        body_params: { 'grant_type' => 'refresh_token', 'refresh_token' => 'bad', 'client_id' => config[:client_id] },
        status: 400,
        body: { 'error' => 'invalid_grant' }
      )
      expect do
        described_class.new(config, auth_type: :public).refresh_token(refresh_token: 'bad')
      end.to raise_error(Safire::Errors::AuthError, /Failed to refresh access token/)
    end

    it 'raises AuthError when access_token missing' do
      stub_token_post(
        body_params: { 'grant_type' => 'refresh_token', 'refresh_token' => 'x', 'client_id' => config[:client_id] },
        status: 200,
        body: { 'token_type' => 'Bearer' }
      )
      expect do
        described_class.new(config, auth_type: :public).refresh_token(refresh_token: 'x')
      end.to raise_error(Safire::Errors::AuthError, /Missing access token/)
    end

    it 'raises AuthError on network error' do
      stub_request(:post, config[:token_endpoint]).to_raise(Faraday::TimeoutError)
      expect do
        described_class.new(config, auth_type: :public).refresh_token(refresh_token: 'x')
      end.to raise_error(Safire::Errors::AuthError)
    end
  end
end
