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

    # Asymmetric auth code body includes client_assertion_type and client_assertion
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

    # Asymmetric refresh body includes client_assertion_type and client_assertion
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
    it 'creates a public client from a ClientConfig' do
      client = described_class.new(config, auth_type: :public)
      expect(client.auth_type).to eq(:public)
      described_class::ATTRIBUTES.each { |attr| expect(client.send(attr)).to eq(config.send(attr)) }
    end

    it 'creates a confidential symmetric client' do
      client = described_class.new(confidential_config, auth_type: :confidential_symmetric)
      expect(client.auth_type).to eq(:confidential_symmetric)
      expect(client.client_secret).to eq(confidential_config.client_secret)
    end

    it 'creates a confidential asymmetric client' do
      client = described_class.new(asymmetric_config, auth_type: :confidential_asymmetric)
      expect(client.auth_type).to eq(:confidential_asymmetric)
      expect(client.private_key).to eq(asymmetric_config.private_key)
      expect(client.kid).to eq(asymmetric_config.kid)
      expect(client.jwt_algorithm).to eq(asymmetric_config.jwt_algorithm)
      expect(client.jwks_uri).to eq(asymmetric_config.jwks_uri)
    end

    it 'defaults auth_type to public' do
      expect(described_class.new(config).auth_type).to eq(:public)
    end

    it 'symbolizes string auth_type' do
      expect(described_class.new(config, auth_type: 'public').auth_type).to eq(:public)
    end

    it 'allows scopes and client_secret to be optional' do
      client = described_class.new(Safire::ClientConfig.new(config_attrs.except(:scopes, :client_secret)))
      expect(client.scopes).to be_nil
      expect(client.client_secret).to be_nil
    end

    it 'raises ConfigurationError when a required attribute is missing' do
      %i[client_id redirect_uri base_url].each do |attr|
        expect { described_class.new(Safire::ClientConfig.new(config_attrs.except(attr))) }
          .to raise_error(Safire::Errors::ConfigurationError, /#{attr}/)
      end
    end

    it 'gives each instance its own distinct HTTPClient' do
      client1 = described_class.new(config)
      client2 = described_class.new(config)

      expect(client1.instance_variable_get(:@http_client))
        .not_to be(client2.instance_variable_get(:@http_client))
    end

    it 'fetches endpoints from well-known when not provided' do
      stub_well_known
      cfg = Safire::ClientConfig.new(config_attrs.except(:authorization_endpoint, :token_endpoint))
      client = described_class.new(cfg)
      expect(client.authorization_endpoint).to eq(smart_metadata_body['authorization_endpoint'])
      expect(client.token_endpoint).to eq(smart_metadata_body['token_endpoint'])
    end
  end

  # ---------- auth_type writer ----------

  describe '#auth_type=' do
    it 'allows auth_type to be updated after initialization' do
      client = described_class.new(config, auth_type: :public)
      client.auth_type = :confidential_symmetric

      expect(client.auth_type).to eq(:confidential_symmetric)
    end
  end

  # ---------- Well-known Discovery ----------

  describe '#well_known_config' do
    let(:well_known_url) { "#{config_attrs[:base_url]}#{described_class::WELL_KNOWN_PATH}" }

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
        .to raise_error(Safire::Errors::DiscoveryError, /response is not a JSON object/)
    end

    it 'handles base_url with or without trailing slash' do
      stub_well_known(base_url: 'https://fhir.example.com/')
      expect do
        described_class.new(Safire::ClientConfig.new(config_attrs.merge(base_url: 'https://fhir.example.com/'))).well_known_config
      end.not_to raise_error

      stub_well_known(base_url: 'https://fhir.example.com')
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
        described_class.new(config, auth_type: :public)
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
        described_class.new(confidential_config, auth_type: :confidential_symmetric)
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
        described_class.new(asymmetric_config, auth_type: :confidential_asymmetric)
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

    context 'when confidential_asymmetric with missing credentials' do
      it 'raises ConfigurationError when private_key is missing' do
        cfg = Safire::ClientConfig.new(config_attrs.merge(kid: 'key-id'))
        expect do
          described_class.new(cfg, auth_type: :confidential_asymmetric)
                         .request_access_token(code: authorization_code, code_verifier: code_verifier)
        end.to raise_error(Safire::Errors::ConfigurationError, /private_key/)
      end

      it 'raises ConfigurationError when kid is missing' do
        cfg = Safire::ClientConfig.new(config_attrs.merge(private_key: rsa_private_key))
        expect do
          described_class.new(cfg, auth_type: :confidential_asymmetric)
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
          described_class.new(config, auth_type: :public)
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
          described_class.new(config, auth_type: :public)
                         .request_access_token(code: 'bad', code_verifier: 'v')
        end.to raise_error(Safire::Errors::TokenError, /Token request failed/)
      end
    end

    context 'when network error' do
      it 'raises NetworkError' do
        stub_request(:post, config_attrs[:token_endpoint]).to_raise(Faraday::ConnectionFailed)
        expect do
          described_class.new(config, auth_type: :public)
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
        res = described_class.new(config, auth_type: :public)
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
        res = described_class.new(config, auth_type: :public)
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
        res = described_class.new(confidential_config, auth_type: :confidential_symmetric)
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
        res = described_class.new(asymmetric_config, auth_type: :confidential_asymmetric)
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

    it 'raises TokenError on invalid refresh token' do
      stub_token_post(
        body_matcher: {
          'grant_type' => 'refresh_token', 'refresh_token' => 'bad', 'client_id' => config_attrs[:client_id]
        },
        status: 400,
        body: { 'error' => 'invalid_grant' }
      )
      expect do
        described_class.new(config, auth_type: :public).refresh_token(refresh_token: 'bad')
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
        described_class.new(config, auth_type: :public).refresh_token(refresh_token: 'x')
      end.to raise_error(Safire::Errors::TokenError, /Missing access token/)
    end

    it 'raises NetworkError on network error' do
      stub_request(:post, config_attrs[:token_endpoint]).to_raise(Faraday::TimeoutError)
      expect do
        described_class.new(config, auth_type: :public).refresh_token(refresh_token: 'x')
      end.to raise_error(Safire::Errors::NetworkError)
    end
  end
end
