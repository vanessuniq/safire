require 'spec_helper'

RSpec.describe Safire::Protocols::Smart do
  # ---------- Test Data ----------

  let(:config_attrs) do
    {
      client_id: 'test_client_id',
      redirect_uri: 'https://app.example.com/callback',
      scopes: ['openid', 'profile', 'patient/*.read'],
      base_url: 'https://fhir.example.com',
      issuer: 'https://fhir.example.com',
      authorization_endpoint: 'https://fhir.example.com/authorize',
      token_endpoint: 'https://fhir.example.com/token'
    }
  end

  let(:config) { Safire::ClientConfig.new(config_attrs) }
  let(:confidential_config) { Safire::ClientConfig.new(config_attrs.merge(client_secret: 'test_client_secret')) }
  let(:rsa_private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:asymmetric_config) do
    Safire::ClientConfig.new(
      config_attrs.merge(
        private_key: rsa_private_key,
        kid: 'test-key-id',
        jwt_algorithm: 'RS384',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json'
      )
    )
  end

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

  def stub_token_post(body_matcher:, status:, body:, headers: {})
    stub_request(:post, config_attrs[:token_endpoint]).with(
      body: body_matcher,
      headers: { 'Content-Type' => 'application/x-www-form-urlencoded' }.merge(headers)
    ).to_return(
      status: status,
      body: body.to_json,
      headers: { 'Content-Type' => 'application/json' }
    )
  end

  def stub_well_known(base_url: config_attrs[:base_url], status: 200, body: smart_metadata_body)
    well_known_url = "#{base_url.to_s.chomp('/')}#{described_class::WELL_KNOWN_PATH}"
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
        'redirect_uri' => config_attrs[:redirect_uri],
        'code_verifier' => code_verifier,
        'client_id' => config_attrs[:client_id]
      }
    end

    let(:confidential_auth_code_body) do
      {
        'grant_type' => 'authorization_code',
        'code' => authorization_code,
        'redirect_uri' => config_attrs[:redirect_uri],
        'code_verifier' => code_verifier
        # no client_id
      }
    end

    let(:asymmetric_auth_code_body_matcher) do
      hash_including(
        'grant_type' => 'authorization_code',
        'code' => authorization_code,
        'redirect_uri' => config_attrs[:redirect_uri],
        'code_verifier' => code_verifier,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => kind_of(String)
      )
    end
  end

  shared_context 'with refresh bodies' do
    let(:refresh_token_value) { 'refresh_token_456def' }

    let(:public_refresh_body) do
      {
        'grant_type' => 'refresh_token',
        'refresh_token' => refresh_token_value,
        'client_id' => config_attrs[:client_id]
      }
    end

    let(:confidential_refresh_body) do
      {
        'grant_type' => 'refresh_token',
        'refresh_token' => refresh_token_value
        # no client_id
      }
    end

    let(:asymmetric_refresh_body_matcher) do
      hash_including(
        'grant_type' => 'refresh_token',
        'refresh_token' => refresh_token_value,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => kind_of(String)
      )
    end
  end

  # ---------- Initialization ----------

  describe '#initialize' do
    it 'includes Safire::Protocols::Behaviours' do
      expect(described_class.ancestors).to include(Safire::Protocols::Behaviours)
    end

    it 'creates a public client from a ClientConfig' do
      client = described_class.new(config, client_type: :public)
      expect(client.client_type).to eq(:public)
      described_class::ATTRIBUTES.each { |attr| expect(client.send(attr)).to eq(config.send(attr)) }
    end

    it 'creates a confidential symmetric client' do
      client = described_class.new(confidential_config, client_type: :confidential_symmetric)
      expect(client.client_type).to eq(:confidential_symmetric)
      expect(client.client_secret).to eq(confidential_config.client_secret)
    end

    it 'creates a confidential asymmetric client' do
      client = described_class.new(asymmetric_config, client_type: :confidential_asymmetric)
      expect(client.client_type).to eq(:confidential_asymmetric)
      expect(client.private_key).to eq(asymmetric_config.private_key)
      expect(client.kid).to eq(asymmetric_config.kid)
      expect(client.jwt_algorithm).to eq(asymmetric_config.jwt_algorithm)
      expect(client.jwks_uri).to eq(asymmetric_config.jwks_uri)
    end

    it 'defaults client_type to :public' do
      expect(described_class.new(config).client_type).to eq(:public)
    end

    it 'symbolizes string client_type' do
      expect(described_class.new(config, client_type: 'public').client_type).to eq(:public)
    end

    it 'allows scopes and client_secret to be optional' do
      client = described_class.new(Safire::ClientConfig.new(config_attrs.except(:scopes, :client_secret)))
      expect(client.scopes).to be_nil
      expect(client.client_secret).to be_nil
    end

    it 'allows client_id to be omitted on initialization' do
      client = described_class.new(Safire::ClientConfig.new(config_attrs.except(:client_id)))
      expect(client.client_id).to be_nil
    end

    it 'gives each instance its own distinct HTTPClient' do
      client1 = described_class.new(config)
      client2 = described_class.new(config)

      expect(client1.instance_variable_get(:@http_client))
        .not_to be(client2.instance_variable_get(:@http_client))
    end
  end

  # ---------- client_type writer ----------

  describe '#client_type=' do
    it 'allows client_type to be updated after initialization' do
      client = described_class.new(config, client_type: :public)
      client.client_type = :confidential_symmetric

      expect(client.client_type).to eq(:confidential_symmetric)
    end
  end

  # ---------- Server Metadata (SMART Discovery) ----------

  describe '#server_metadata' do
    let(:well_known_url) { "#{config_attrs[:base_url]}#{described_class::WELL_KNOWN_PATH}" }

    it 'fetches and exposes metadata' do
      stub_well_known
      metadata = described_class.new(config).server_metadata
      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.authorization_endpoint).to eq(smart_metadata_body['authorization_endpoint'])
      expect(metadata.token_endpoint).to eq(smart_metadata_body['token_endpoint'])
      expect(metadata.capabilities).to eq(smart_metadata_body['capabilities'])
    end

    it 'raises on 404' do
      stub_request(:get, well_known_url).to_return(status: 404)
      expect { described_class.new(config).server_metadata }
        .to raise_error(Safire::Errors::DiscoveryError, /Failed to discover SMART configuration/)
    end

    it 'raises on invalid JSON' do
      stub_request(:get, well_known_url).to_return(status: 200, body: 'not-json')
      expect { described_class.new(config).server_metadata }
        .to raise_error(Safire::Errors::DiscoveryError)
    end

    it 'raises when response is not a hash' do
      stub_request(:get, well_known_url).to_return(
        status: 200, body: '[]', headers: { 'Content-Type' => 'application/json' }
      )
      expect { described_class.new(config).server_metadata }
        .to raise_error(Safire::Errors::DiscoveryError, /response is not a JSON object/)
    end

    it 'handles base_url with or without trailing slash' do
      stub_well_known(base_url: 'https://fhir.example.com/')
      expect do
        described_class.new(Safire::ClientConfig.new(config_attrs.merge(base_url: 'https://fhir.example.com/'))).server_metadata
      end.not_to raise_error

      stub_well_known(base_url: 'https://fhir.example.com')
      expect { described_class.new(config).server_metadata }.not_to raise_error
    end
  end

  # ---------- Endpoint Resolution ----------

  describe 'endpoint resolution' do
    context 'when endpoints are absent from config' do
      it 'resolves both from well-known discovery' do
        stub_well_known
        cfg = Safire::ClientConfig.new(config_attrs.except(:authorization_endpoint, :token_endpoint))
        client = described_class.new(cfg)
        expect(client.authorization_endpoint).to eq(smart_metadata_body['authorization_endpoint'])
        expect(client.token_endpoint).to eq(smart_metadata_body['token_endpoint'])
      end
    end

    context 'when token_endpoint is absent from the discovery response' do
      it 'raises DiscoveryError with a descriptive message' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:token_endpoint))
        stub_well_known(body: smart_metadata_body.except('token_endpoint'))
        expect { described_class.new(cfg).token_endpoint }
          .to raise_error(Safire::Errors::DiscoveryError, /token_endpoint/)
      end
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
          .to eq(['code', config_attrs[:client_id], config_attrs[:redirect_uri], config_attrs[:base_url]])
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
      expect(query_params['scope']).to eq(config_attrs[:scopes].join(' '))
    end

    it 'raises when no scopes configured' do
      expect { described_class.new(Safire::ClientConfig.new(config_attrs.except(:scopes))).authorization_url }
        .to raise_error(Safire::Errors::ConfigurationError, /scopes/)
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

      cfg2 = Safire::ClientConfig.new(config_attrs.merge(redirect_uri: 'https://app.example.com/callback?param=value'))
      data2 = described_class.new(cfg2).authorization_url
      expect(data2[:auth_url]).to include(CGI.escape(cfg2.redirect_uri))
    end

    context 'when method: :post' do
      let(:post_auth_data) { described_class.new(config).authorization_url(method: :post) }

      it 'returns auth_url, params, state, and code_verifier' do
        expect(post_auth_data.keys).to contain_exactly(:auth_url, :params, :state, :code_verifier)
      end

      it 'auth_url is the bare authorization endpoint with no query string' do
        expect(post_auth_data[:auth_url]).to eq(config_attrs[:authorization_endpoint])
        expect(post_auth_data[:auth_url]).not_to include('?')
      end

      it 'params contains all required oauth and pkce fields' do
        p = post_auth_data[:params]
        expect(p).to include(
          response_type: 'code',
          client_id: config_attrs[:client_id],
          redirect_uri: config_attrs[:redirect_uri],
          aud: config_attrs[:base_url],
          code_challenge_method: 'S256'
        )
        expect(p[:code_challenge]).to match(/\A[A-Za-z0-9_-]{43}\z/)
        expect(p[:code_challenge]).to eq(Safire::PKCE.generate_code_challenge(post_auth_data[:code_verifier]))
      end

      it 'state in response matches state in params' do
        expect(post_auth_data[:state]).to eq(post_auth_data[:params][:state])
        expect(post_auth_data[:state]).to match(/\A[a-f0-9]{32}\z/)
      end
    end

    context 'when method is provided as a string' do
      it 'accepts "post" and returns params hash' do
        data = described_class.new(config).authorization_url(method: 'post')
        expect(data[:auth_url]).to eq(config_attrs[:authorization_endpoint])
        expect(data[:params]).to be_a(Hash)
      end

      it 'accepts "get" and returns redirect URL' do
        data = described_class.new(config).authorization_url(method: 'get')
        expect(data[:auth_url]).to include('?')
        expect(data.key?(:params)).to be(false)
      end
    end

    context 'when method is invalid' do
      it 'raises ConfigurationError' do
        expect { described_class.new(config).authorization_url(method: :patch) }
          .to raise_error(Safire::Errors::ConfigurationError, /method/)
      end
    end

    context 'when redirect_uri is not configured' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:redirect_uri))
        expect { described_class.new(cfg).authorization_url }
          .to raise_error(Safire::Errors::ConfigurationError, /redirect_uri/)
      end
    end

    context 'when client_id is not configured' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:client_id))
        expect { described_class.new(cfg).authorization_url }
          .to raise_error(Safire::Errors::ConfigurationError, /client_id/)
      end
    end

    context 'when authorization_endpoint cannot be resolved' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:authorization_endpoint))
        stub_well_known(body: smart_metadata_body.except('authorization_endpoint'))
        expect { described_class.new(cfg).authorization_url }
          .to raise_error(Safire::Errors::ConfigurationError, /authorization_endpoint/)
      end
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

    context 'when public client' do
      subject(:token_response) do
        described_class.new(config, client_type: :public)
                       .request_access_token(code: authorization_code, code_verifier: code_verifier)
      end

      before do
        stub_token_post(body_matcher: public_auth_code_body, status: 200, body: token_response_body)
      end

      it_behaves_like 'returns token response'

      it 'includes client_id in request body' do
        token_response

        expect(WebMock).to have_requested(:post, config_attrs[:token_endpoint])
          .with(body: hash_including('client_id' => config_attrs[:client_id]))
      end

      it 'does not include Authorization header' do
        token_response

        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint])
          .with { |req| !req.headers.key?('Authorization') })
      end
    end

    context 'when confidential_symmetric' do
      subject(:token_response) do
        described_class.new(confidential_config, client_type: :confidential_symmetric)
                       .request_access_token(code: authorization_code, code_verifier: code_verifier)
      end

      let(:auth_header) { basic_auth_header(confidential_config.client_id, confidential_config.client_secret) }

      before do
        stub_token_post(
          body_matcher: confidential_auth_code_body,
          status: 200,
          body: token_response_body,
          headers: { 'Authorization' => auth_header }
        )
      end

      it_behaves_like 'returns token response'

      it 'uses Basic auth and omits client_id' do
        token_response
        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          have_basic_auth(auth_header).matches?(req) && body_excludes_keys(:client_id).matches?(req)
        end)
      end
    end

    context 'when confidential_asymmetric' do
      subject(:token_response) do
        described_class.new(asymmetric_config, client_type: :confidential_asymmetric)
                       .request_access_token(code: authorization_code, code_verifier: code_verifier)
      end

      before do
        stub_token_post(body_matcher: asymmetric_auth_code_body_matcher, status: 200, body: token_response_body)
      end

      it_behaves_like 'returns token response'

      it 'includes client_assertion_type and client_assertion, omits client_id' do
        token_response
        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          body = URI.decode_www_form(req.body).to_h
          body['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            body['client_assertion'].present? &&
            body_excludes_keys(:client_id).matches?(req)
        end)
      end

      it 'sends a valid JWT assertion' do
        token_response
        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          body = URI.decode_www_form(req.body).to_h
          jwt = body['client_assertion']
          decoded = JWT.decode(jwt, rsa_private_key.public_key, true, algorithm: 'RS384')
          decoded[0]['iss'] == config_attrs[:client_id] &&
            decoded[0]['sub'] == config_attrs[:client_id] &&
            decoded[0]['aud'] == config_attrs[:token_endpoint] &&
            decoded[1]['kid'] == asymmetric_config.kid
        end)
      end

      it 'does not include Authorization header' do
        token_response
        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint])
          .with { |req| !req.headers.key?('Authorization') })
      end
    end

    context 'when client_id is not configured' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:client_id))
        expect do
          described_class.new(cfg).request_access_token(code: 'code', code_verifier: 'verifier')
        end.to raise_error(Safire::Errors::ConfigurationError, /client_id/)
      end
    end

    context 'when confidential_asymmetric with missing credentials' do
      it 'raises ConfigurationError when private_key is missing' do
        cfg = Safire::ClientConfig.new(config_attrs.merge(kid: 'key-id'))
        expect do
          described_class.new(cfg, client_type: :confidential_asymmetric)
                         .request_access_token(code: authorization_code, code_verifier: code_verifier)
        end.to raise_error(Safire::Errors::ConfigurationError, /private_key/)
      end

      it 'raises ConfigurationError when kid is missing' do
        cfg = Safire::ClientConfig.new(config_attrs.merge(private_key: rsa_private_key))
        expect do
          described_class.new(cfg, client_type: :confidential_asymmetric)
                         .request_access_token(code: authorization_code, code_verifier: code_verifier)
        end.to raise_error(Safire::Errors::ConfigurationError, /kid/)
      end
    end

    context 'when invalid response (missing access_token)' do
      it 'raises TokenError' do
        stub_token_post(
          body_matcher: {
            'grant_type' => 'authorization_code',
            'code' => 'auth_code_abc123',
            'redirect_uri' => config_attrs[:redirect_uri],
            'code_verifier' => 'test_code_verifier_xyz789',
            'client_id' => config_attrs[:client_id]
          },
          status: 200,
          body: { 'token_type' => 'Bearer', 'expires_in' => 3600 }
        )
        expect do
          described_class.new(config, client_type: :public)
                         .request_access_token(code: 'auth_code_abc123', code_verifier: 'test_code_verifier_xyz789')
        end.to raise_error(Safire::Errors::TokenError, /Missing access token/)
      end
    end

    context 'when server OAuth error' do
      it 'raises TokenError with status and error_code' do
        stub_token_post(
          body_matcher: {
            'grant_type' => 'authorization_code',
            'code' => 'bad',
            'redirect_uri' => config_attrs[:redirect_uri],
            'code_verifier' => 'v',
            'client_id' => config_attrs[:client_id]
          },
          status: 400,
          body: { 'error' => 'invalid_grant' }
        )
        expect do
          described_class.new(config, client_type: :public)
                         .request_access_token(code: 'bad', code_verifier: 'v')
        end.to raise_error(Safire::Errors::TokenError, /Token request failed/)
      end
    end

    context 'when network error' do
      it 'raises NetworkError' do
        stub_request(:post, config_attrs[:token_endpoint]).to_raise(Faraday::ConnectionFailed)
        expect do
          described_class.new(config, client_type: :public)
                         .request_access_token(code: 'x', code_verifier: 'y')
        end.to raise_error(Safire::Errors::NetworkError)
      end
    end
  end

  # ---------- Refresh ----------

  describe '#refresh_token' do
    include_context 'with refresh bodies'

    context 'when public client' do
      before do
        stub_token_post(
          body_matcher: public_refresh_body,
          status: 200,
          body: refreshed_token_response_body
        )
      end

      it 'returns refreshed tokens' do
        res = described_class.new(config, client_type: :public)
                             .refresh_token(refresh_token: refresh_token_value)
        expect(res).to eq(refreshed_token_response_body)
      end
    end

    context 'when public with custom scopes' do
      let(:custom_scopes) { %w[openid profile] }

      before do
        stub_token_post(
          body_matcher: public_refresh_body.merge('scope' => custom_scopes.join(' ')),
          status: 200,
          body: refreshed_token_response_body
        )
      end

      it 'includes scopes in request' do
        res = described_class.new(config, client_type: :public)
                             .refresh_token(refresh_token: refresh_token_value, scopes: custom_scopes)
        expect(res['access_token']).to eq('new_access_token_123ghi')
      end
    end

    context 'when confidential_symmetric' do
      let(:auth_header) { basic_auth_header(confidential_config.client_id, confidential_config.client_secret) }

      before do
        stub_token_post(
          body_matcher: confidential_refresh_body,
          status: 200,
          body: refreshed_token_response_body,
          headers: { 'Authorization' => auth_header }
        )
      end

      it 'uses Basic auth and omits client_id' do
        res = described_class.new(confidential_config, client_type: :confidential_symmetric)
                             .refresh_token(refresh_token: refresh_token_value)
        expect(res).to eq(refreshed_token_response_body)

        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          have_basic_auth(auth_header).matches?(req) && body_excludes_keys(:client_id).matches?(req)
        end)
      end
    end

    context 'when confidential_asymmetric' do
      before do
        stub_token_post(body_matcher: asymmetric_refresh_body_matcher, status: 200, body: refreshed_token_response_body)
      end

      it 'returns refreshed tokens with JWT assertion' do
        res = described_class.new(asymmetric_config, client_type: :confidential_asymmetric)
                             .refresh_token(refresh_token: refresh_token_value)
        expect(res).to eq(refreshed_token_response_body)

        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          body = URI.decode_www_form(req.body).to_h
          body['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            body['client_assertion'].present? &&
            body_excludes_keys(:client_id).matches?(req)
        end)
      end
    end

    context 'when client_id is not configured' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:client_id))
        expect { described_class.new(cfg).refresh_token(refresh_token: 'token') }
          .to raise_error(Safire::Errors::ConfigurationError, /client_id/)
      end
    end

    it 'raises TokenError on invalid refresh token' do
      stub_token_post(
        body_matcher: {
          'grant_type' => 'refresh_token', 'refresh_token' => 'bad', 'client_id' => config_attrs[:client_id]
        },
        status: 400,
        body: { 'error' => 'invalid_grant' }
      )
      expect do
        described_class.new(config, client_type: :public).refresh_token(refresh_token: 'bad')
      end.to raise_error(Safire::Errors::TokenError, /Token request failed/)
    end

    it 'raises TokenError when access_token missing' do
      stub_token_post(
        body_matcher: {
          'grant_type' => 'refresh_token', 'refresh_token' => 'x', 'client_id' => config_attrs[:client_id]
        },
        status: 200,
        body: { 'token_type' => 'Bearer' }
      )
      expect do
        described_class.new(config, client_type: :public).refresh_token(refresh_token: 'x')
      end.to raise_error(Safire::Errors::TokenError, /Missing access token/)
    end

    it 'raises NetworkError on network error' do
      stub_request(:post, config_attrs[:token_endpoint]).to_raise(Faraday::TimeoutError)
      expect do
        described_class.new(config, client_type: :public).refresh_token(refresh_token: 'x')
      end.to raise_error(Safire::Errors::NetworkError)
    end
  end

  # ---------- Backend Token ----------

  describe '#request_backend_token' do
    let(:backend_token_response) do
      { 'access_token' => 'backend_token_abc', 'token_type' => 'Bearer',
        'expires_in' => 300, 'scope' => 'system/Patient.rs system/Observation.rs' }
    end

    let(:backend_assertion_matcher) do
      hash_including(
        'grant_type' => 'client_credentials',
        'scope' => 'system/Patient.rs system/Observation.rs',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => kind_of(String)
      )
    end

    let(:backend_config_attrs) do
      {
        client_id: 'backend_client_id',
        base_url: 'https://fhir.example.com',
        token_endpoint: 'https://fhir.example.com/token',
        private_key: rsa_private_key,
        kid: 'backend-key-id',
        scopes: %w[system/Patient.rs system/Observation.rs]
      }
    end

    let(:backend_config) { Safire::ClientConfig.new(backend_config_attrs) }

    context 'with RSA private key and configured scopes' do
      before do
        stub_token_post(body_matcher: backend_assertion_matcher, status: 200, body: backend_token_response)
      end

      it 'returns the access token response' do
        result = described_class.new(backend_config).request_backend_token
        expect(result['access_token']).to eq('backend_token_abc')
        expect(result['token_type']).to eq('Bearer')
      end

      it 'sends client_credentials grant with scope and JWT assertion' do
        described_class.new(backend_config).request_backend_token

        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          body = URI.decode_www_form(req.body).to_h
          body['grant_type'] == 'client_credentials' &&
            body['scope'] == 'system/Patient.rs system/Observation.rs' &&
            body['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            body['client_assertion'].present?
        end)
      end

      it 'does not include an Authorization header' do
        described_class.new(backend_config).request_backend_token

        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint])
          .with { |req| !req.headers.key?('Authorization') })
      end

      it 'sends a valid JWT assertion with correct claims' do
        described_class.new(backend_config).request_backend_token

        expect(WebMock).to(have_requested(:post, config_attrs[:token_endpoint]).with do |req|
          body    = URI.decode_www_form(req.body).to_h
          decoded = JWT.decode(body['client_assertion'], rsa_private_key.public_key, true, algorithm: 'RS384')
          payload, header = decoded

          payload['iss'] == 'backend_client_id' &&
            payload['sub'] == 'backend_client_id' &&
            payload['aud'] == config_attrs[:token_endpoint] &&
            payload['jti'].present? &&
            payload['exp'].is_a?(Integer) &&
            header['kid'] == 'backend-key-id'
        end)
      end
    end

    context 'with scope override' do
      before do
        stub_token_post(
          body_matcher: hash_including('scope' => 'system/Patient.rs'),
          status: 200,
          body: backend_token_response
        )
      end

      it 'uses the provided scopes instead of configured ones' do
        described_class.new(backend_config).request_backend_token(scopes: %w[system/Patient.rs])

        expect(WebMock).to have_requested(:post, config_attrs[:token_endpoint])
          .with(body: hash_including('scope' => 'system/Patient.rs'))
      end
    end

    context 'when no scopes are configured and none provided' do
      it 'defaults to system/*.rs scope' do
        stub_token_post(
          body_matcher: hash_including('scope' => 'system/*.rs'),
          status: 200,
          body: backend_token_response.merge('scope' => 'system/*.rs')
        )
        cfg = Safire::ClientConfig.new(backend_config_attrs.except(:scopes))
        described_class.new(cfg).request_backend_token

        expect(WebMock).to have_requested(:post, config_attrs[:token_endpoint])
          .with(body: hash_including('scope' => 'system/*.rs'))
      end
    end

    context 'when client_id is not configured' do
      it 'raises ConfigurationError — client_id is required for JWT assertion claims' do
        cfg = Safire::ClientConfig.new(backend_config_attrs.except(:client_id))
        expect { described_class.new(cfg).request_backend_token }
          .to raise_error(Safire::Errors::ConfigurationError, /client_id/)
      end
    end

    context 'when private_key is missing' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(backend_config_attrs.except(:private_key))
        expect { described_class.new(cfg).request_backend_token }
          .to raise_error(Safire::Errors::ConfigurationError, /private_key/)
      end
    end

    context 'when kid is missing' do
      it 'raises ConfigurationError' do
        cfg = Safire::ClientConfig.new(backend_config_attrs.except(:kid))
        expect { described_class.new(cfg).request_backend_token }
          .to raise_error(Safire::Errors::ConfigurationError, /kid/)
      end
    end

    context 'when server returns an error' do
      before do
        stub_request(:post, config_attrs[:token_endpoint]).to_return(
          status: 401,
          body: { 'error' => 'invalid_client', 'error_description' => 'JWT signature invalid' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises TokenError' do
        expect { described_class.new(backend_config).request_backend_token }
          .to raise_error(Safire::Errors::TokenError, /Token request failed/)
      end
    end

    context 'when a network error occurs' do
      it 'raises NetworkError' do
        stub_request(:post, config_attrs[:token_endpoint]).to_raise(Faraday::ConnectionFailed)
        expect { described_class.new(backend_config).request_backend_token }
          .to raise_error(Safire::Errors::NetworkError)
      end
    end
  end

  # ---------- Token Response Validation ----------

  describe '#token_response_valid?' do
    let(:client) { described_class.new(config) }
    let(:valid_response) do
      { 'access_token' => 'abc123', 'token_type' => 'Bearer', 'scope' => 'openid profile' }
    end

    before { allow(Safire.logger).to receive(:warn) }

    context 'when all required fields are present and token_type is "Bearer"' do
      it 'returns true and does not warn' do
        result = client.token_response_valid?(valid_response)
        expect(result).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context 'when token_type is "bearer" (lowercase)' do
      it 'returns true — both "Bearer" and "bearer" are accepted' do
        result = client.token_response_valid?(valid_response.merge('token_type' => 'bearer'))
        expect(result).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context 'when token_type is an unrecognized value' do
      it 'returns false and logs a warning referencing the App Launch spec' do
        result = client.token_response_valid?(valid_response.merge('token_type' => 'BEARER'))
        expect(result).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/token_type.*SMART App Launch spec/)
      end
    end

    %w[access_token scope token_type].each do |field|
      context "when #{field} is missing" do
        it 'returns false and logs a warning' do
          result = client.token_response_valid?(valid_response.except(field))
          expect(result).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/'#{field}' is missing/)
        end
      end
    end

    context 'when multiple required fields are missing' do
      it 'returns false and logs a warning for each missing field' do
        result = client.token_response_valid?({})
        expect(result).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'access_token' is missing/)
        expect(Safire.logger).to have_received(:warn).with(/'scope' is missing/)
        expect(Safire.logger).to have_received(:warn).with(/'token_type' is missing/)
      end
    end

    context 'when response is not a Hash' do
      [nil, 'not a hash'].each do |invalid|
        it "returns false for #{invalid.inspect} and logs a warning" do
          result = client.token_response_valid?(invalid)
          expect(result).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/not a JSON object/)
        end
      end
    end

    context 'with flow: :backend_services' do
      let(:backend_response) { valid_response.merge('expires_in' => 300) }

      context 'when expires_in is present' do
        it 'returns true' do
          result = client.token_response_valid?(backend_response, flow: :backend_services)
          expect(result).to be(true)
          expect(Safire.logger).not_to have_received(:warn)
        end
      end

      context 'when expires_in is missing' do
        it 'returns false and logs a warning' do
          result = client.token_response_valid?(valid_response, flow: :backend_services)
          expect(result).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/'expires_in' is missing/)
        end
      end

      context 'when token_type is an unrecognized value' do
        it 'returns false and logs a warning referencing the Backend Services spec' do
          response = backend_response.merge('token_type' => 'BEARER')
          result = client.token_response_valid?(response, flow: :backend_services)
          expect(result).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/token_type.*SMART App Launch Backend Services/)
        end
      end
    end

    context 'with flow: :app_launch (default)' do
      context 'when expires_in is absent' do
        it 'returns true — expires_in is not required for app launch' do
          result = client.token_response_valid?(valid_response)
          expect(result).to be(true)
          expect(Safire.logger).not_to have_received(:warn)
        end
      end
    end
  end

  # ---------- Dynamic Client Registration ----------

  describe '#register_client' do
    let(:registration_endpoint) { 'https://fhir.example.com/register' }
    let(:client_metadata) do
      {
        client_name: 'My App',
        redirect_uris: ['https://app.example.com/callback'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks_uri: 'https://app.example.com/.well-known/jwks.json'
      }
    end
    let(:registration_response) do
      {
        'client_id' => 'registered_client_id_abc',
        'client_name' => 'My App',
        'redirect_uris' => ['https://app.example.com/callback'],
        'grant_types' => ['authorization_code'],
        'token_endpoint_auth_method' => 'private_key_jwt'
      }
    end
    # Temp-client pattern: no client_id at registration time
    let(:no_client_id_config) { Safire::ClientConfig.new(config_attrs.except(:client_id)) }

    # Captures a raised error of the given class; returns nil if none is raised.
    # Needed because RSpec's `end.to raise_error(Klass) do |e|` is a multi-line block chain
    # (Style/MultilineBlockChain offense), so we capture manually instead.
    def capture_error(klass)
      yield
      nil
    rescue klass => e
      e
    end

    def stub_registration(endpoint: registration_endpoint, status: 200, body: registration_response)
      stub_request(:post, endpoint)
        .to_return(status: status, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
    end

    context 'with explicit registration_endpoint' do
      before { stub_registration }

      it 'returns the registration response as a Hash' do
        result = described_class.new(no_client_id_config)
                                .register_client(client_metadata, registration_endpoint:)
        expect(result).to eq(registration_response)
      end

      it 'does not require client_id to be pre-set (supports the temp-client pattern)' do
        expect do
          described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)
        end.not_to raise_error
      end

      it 'POSTs metadata as JSON with correct Content-Type and Accept headers' do
        described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)

        expect(WebMock).to(have_requested(:post, registration_endpoint).with do |req|
          body = JSON.parse(req.body)
          req.headers['Content-Type'].start_with?('application/json') &&
              req.headers['Accept'] == 'application/json' &&
              body['client_name'] == 'My App' &&
              body['redirect_uris'] == ['https://app.example.com/callback']
        end)
      end

      it 'includes the Authorization header when provided' do
        described_class.new(no_client_id_config).register_client(
          client_metadata,
          registration_endpoint:,
          authorization: 'Bearer initial-access-token'
        )

        expect(WebMock).to have_requested(:post, registration_endpoint)
          .with(headers: { 'Authorization' => 'Bearer initial-access-token' })
      end

      it 'omits the Authorization header when not provided' do
        described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)

        expect(WebMock).to(have_requested(:post, registration_endpoint)
          .with { |req| req.headers.keys.none? { |k| k.casecmp('authorization').zero? } })
      end
    end

    context 'when registration_endpoint falls back to discovery' do
      let(:smart_metadata_with_dcr) do
        smart_metadata_body.merge('registration_endpoint' => registration_endpoint)
      end

      before do
        stub_well_known(body: smart_metadata_with_dcr)
        stub_registration
      end

      it 'uses the registration_endpoint advertised in SMART metadata' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:client_id, :authorization_endpoint, :token_endpoint))
        described_class.new(cfg).register_client(client_metadata)

        expect(WebMock).to have_requested(:post, registration_endpoint)
      end
    end

    context 'when no registration_endpoint is available' do
      before { stub_well_known } # discovery response does NOT include registration_endpoint

      it 'raises DiscoveryError directing the caller to provide the endpoint explicitly' do
        cfg = Safire::ClientConfig.new(config_attrs.except(:client_id, :authorization_endpoint, :token_endpoint))
        expect { described_class.new(cfg).register_client(client_metadata) }
          .to raise_error(Safire::Errors::DiscoveryError, /registration_endpoint/)
      end
    end

    context 'when the server returns an HTTP error with RFC 7591 fields' do
      before do
        stub_request(:post, registration_endpoint).to_return(
          status: 400,
          body: { 'error' => 'invalid_redirect_uri', 'error_description' => 'Must be HTTPS' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises RegistrationError with typed HTTP error attributes' do
        error = capture_error(Safire::Errors::RegistrationError) do
          described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)
        end
        expect(error).to be_a(Safire::Errors::RegistrationError)
        expect(error.status).to eq(400)
        expect(error.error_code).to eq('invalid_redirect_uri')
        expect(error.error_description).to eq('Must be HTTPS')
        expect(error.message).to match(/400/)
        expect(error.message).to match(/invalid_redirect_uri/)
      end
    end

    context 'when 2xx response is missing client_id (structural failure)' do
      before do
        stub_request(:post, registration_endpoint).to_return(
          status: 201,
          body: { 'client_name' => 'My App', 'expires_at' => 9999 }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises RegistrationError with received_fields but no values' do
        error = capture_error(Safire::Errors::RegistrationError) do
          described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)
        end
        expect(error).to be_a(Safire::Errors::RegistrationError)
        expect(error.received_fields).to contain_exactly('client_name', 'expires_at')
        expect(error.message).to match(/client_name/)
        expect(error.message).not_to match(/My App/)
      end
    end

    context 'when the response body is not a JSON object' do
      before do
        stub_request(:post, registration_endpoint).to_return(
          status: 200, body: '["not","a","hash"]', headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises RegistrationError' do
        expect do
          described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)
        end.to raise_error(Safire::Errors::RegistrationError)
      end
    end

    context 'when a network error occurs' do
      before { stub_request(:post, registration_endpoint).to_raise(Faraday::ConnectionFailed) }

      it 'raises NetworkError' do
        expect do
          described_class.new(no_client_id_config).register_client(client_metadata, registration_endpoint:)
        end.to raise_error(Safire::Errors::NetworkError)
      end
    end
  end
end
