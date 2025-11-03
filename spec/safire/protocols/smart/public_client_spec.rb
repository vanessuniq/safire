require 'spec_helper'

RSpec.describe Safire::Protocols::Smart::PublicClient do
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

  let(:public_client) { described_class.new(config) }
  let(:public_client_no_scopes) { described_class.new(config.except(:scopes)) }

  def parse_query_params(url)
    Addressable::URI.parse(url).query_values
  end

  def stub_token_endpoint(params:, status:, body:)
    stub_request(:post, config[:token_endpoint])
      .with(
        query: hash_including(params),
        headers: { 'Content-Type' => 'application/x-www-form-urlencoded' }
      )
      .to_return(
        status: status,
        body: body.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  describe '#initialize' do
    it 'creates a public client with valid configuration' do
      expect(public_client).to be_a(described_class)
      described_class::ATTRIBUTES.each do |attr|
        expect(public_client.send(attr)).to eq(config[attr])
      end
    end

    it 'allows scopes to be optional' do
      expect(public_client_no_scopes).to be_a(described_class)
      expect(public_client_no_scopes.scopes).to be_nil
    end

    context 'with missing required attributes' do
      required_attributes = %i[client_id redirect_uri issuer authorization_endpoint token_endpoint]

      required_attributes.each do |attr|
        it "raises ConfigurationError when #{attr} is missing" do
          expect { described_class.new(config.except(attr)) }
            .to raise_error(Safire::Errors::ConfigurationError, /#{attr}/)
        end
      end

      it 'raises ConfigurationError with multiple missing attributes' do
        expect { described_class.new(config.except(:client_id, :redirect_uri)) }
          .to raise_error(Safire::Errors::ConfigurationError, /client_id.*redirect_uri/)
      end
    end
  end

  describe '#authorization_url' do
    let(:auth_data) { public_client.authorization_url }
    let(:query_params) { parse_query_params(auth_data[:auth_url]) }

    shared_examples 'valid authorization response' do
      it 'returns a hash with required keys' do
        expect(auth_data.keys).to contain_exactly(:auth_url, :state, :code_verifier)
      end

      it 'generates valid state parameter' do
        expect(auth_data[:state]).to be_present
        expect(auth_data[:state]).to match(/\A[a-f0-9]{32}\z/)
      end

      it 'generates valid code_verifier' do
        expect(auth_data[:code_verifier]).to be_present
        expect(auth_data[:code_verifier]).to match(/\A[A-Za-z0-9_-]+\z/)
        expect(auth_data[:code_verifier].length).to eq(128)
      end
    end

    shared_examples 'includes required OAuth2 parameters' do
      it 'includes correct OAuth2 parameters' do
        expect(query_params['response_type']).to eq('code')
        expect(query_params['client_id']).to eq(config[:client_id])
        expect(query_params['redirect_uri']).to eq(config[:redirect_uri])
        expect(query_params['aud']).to eq(config[:issuer])
      end
    end

    shared_examples 'includes valid PKCE parameters' do
      it 'includes PKCE code_challenge and method' do
        expect(query_params).to have_key('code_challenge')
        expect(query_params['code_challenge_method']).to eq('S256')
      end

      it 'generates valid code_challenge' do
        challenge = query_params['code_challenge']
        expect(challenge).to be_present
        expect(challenge).to match(/\A[A-Za-z0-9_-]+\z/)
        expect(challenge.length).to eq(43)
      end

      it 'code_challenge matches the code_verifier' do
        expected_challenge = Safire::PKCE.generate_code_challenge(auth_data[:code_verifier])
        expect(query_params['code_challenge']).to eq(expected_challenge)
      end
    end

    context 'when scopes are provided in config' do
      it_behaves_like 'valid authorization response'
      it_behaves_like 'includes required OAuth2 parameters'
      it_behaves_like 'includes valid PKCE parameters'

      it 'includes the configured scopes' do
        expect(query_params['scope']).to eq(config[:scopes].join(' '))
      end
    end

    context 'when scopes are not provided' do
      it 'raises a ConfigurationError' do
        expect { public_client_no_scopes.authorization_url }
          .to raise_error(Safire::Errors::ConfigurationError, /requires scopes/)
      end
    end

    context 'when custom scopes are provided' do
      let(:custom_scopes) { ['custom.scope1', 'custom.scope2'] }
      let(:auth_data) { public_client.authorization_url(custom_scopes: custom_scopes) }

      it_behaves_like 'valid authorization response'
      it_behaves_like 'includes required OAuth2 parameters'
      it_behaves_like 'includes valid PKCE parameters'

      it 'uses custom scopes instead of configured scopes' do
        expect(query_params['scope']).to eq(custom_scopes.join(' '))
      end
    end

    context 'with launch parameter' do
      let(:launch_value) { 'launch_token_123' }
      let(:auth_data) { public_client.authorization_url(launch: launch_value) }

      it_behaves_like 'valid authorization response'
      it_behaves_like 'includes required OAuth2 parameters'

      it 'includes the launch parameter' do
        expect(query_params['launch']).to eq(launch_value)
      end
    end

    context 'without launch parameter' do
      let(:auth_data) { public_client.authorization_url(launch: nil) }

      it 'does not include the launch parameter' do
        expect(query_params).not_to have_key('launch')
      end
    end

    context 'when multiple calls' do
      it 'generates unique state on each call' do
        states = 3.times.map { public_client.authorization_url[:state] }
        expect(states.uniq.length).to eq(3)
      end

      it 'generates unique code_verifier on each call' do
        verifiers = 3.times.map { public_client.authorization_url[:code_verifier] }
        expect(verifiers.uniq.length).to eq(3)
      end

      it 'generates unique code_challenge on each call' do
        challenges = 3.times.map do
          auth_data = public_client.authorization_url
          parse_query_params(auth_data[:auth_url])['code_challenge']
        end
        expect(challenges.uniq.length).to eq(3)
      end
    end

    it 'properly encodes special characters in scopes' do
      custom_scopes = ['patient/*.read', 'user/Observation.read']
      auth_data = public_client.authorization_url(custom_scopes: custom_scopes)
      expect(auth_data[:auth_url]).to include('patient%2F%2A.read')
    end

    it 'properly encodes redirect_uri with query parameters' do
      custom_config = config.merge(redirect_uri: 'https://app.example.com/callback?param=value')
      client = described_class.new(custom_config)
      auth_data = client.authorization_url
      expect(auth_data[:auth_url]).to include(CGI.escape(custom_config[:redirect_uri]))
    end
  end

  describe '#request_access_token' do
    let(:authorization_code) { 'auth_code_abc123' }
    let(:code_verifier) { 'test_code_verifier_xyz789' }
    let(:base_token_params) do
      {
        'grant_type' => 'authorization_code',
        'redirect_uri' => config[:redirect_uri],
        'client_id' => config[:client_id]
      }
    end
    let(:token_response_body) do
      {
        'access_token' => 'access_token_xyz789',
        'token_type' => 'Bearer',
        'expires_in' => 3600,
        'scope' => 'openid profile patient/*.read'
      }
    end

    shared_examples 'returns valid token response' do
      it 'returns a hash with access_token' do
        token_response = public_client.request_access_token(
          code: authorization_code,
          code_verifier: code_verifier
        )

        expect(token_response).to be_a(Hash)
        expect(token_response).to eq(token_response_body)
      end
    end

    context 'with valid authorization code and code_verifier' do
      before do
        stub_token_endpoint(
          params: base_token_params.merge('code' => authorization_code, 'code_verifier' => code_verifier),
          status: 200,
          body: token_response_body
        )
      end

      it_behaves_like 'returns valid token response'
    end

    context 'with invalid credentials' do
      shared_examples 'raises AuthError' do |error_message|
        it "raises an AuthError with #{error_message}" do
          expect do
            public_client.request_access_token(
              code: authorization_code,
              code_verifier: code_verifier
            )
          end.to raise_error(Safire::Errors::AuthError, /Failed to obtain access token/)
        end
      end

      context 'when authorization code is invalid' do
        before do
          stub_token_endpoint(
            params: base_token_params.merge('code' => 'invalid_code', 'code_verifier' => code_verifier),
            status: 400,
            body: { 'error' => 'invalid_grant', 'error_description' => 'Invalid authorization code' }
          )
        end

        it 'raises an AuthError' do
          expect do
            public_client.request_access_token(code: 'invalid_code', code_verifier: code_verifier)
          end.to raise_error(Safire::Errors::AuthError)
        end
      end

      context 'when code_verifier is invalid' do
        before do
          stub_token_endpoint(
            params: base_token_params.merge('code' => authorization_code, 'code_verifier' => 'wrong_verifier'),
            status: 400,
            body: { 'error' => 'invalid_grant', 'error_description' => 'Code verifier mismatch' }
          )
        end

        it 'raises an AuthError' do
          expect do
            public_client.request_access_token(code: authorization_code, code_verifier: 'wrong_verifier')
          end.to raise_error(Safire::Errors::AuthError)
        end
      end

      context 'when server returns 401 Unauthorized' do
        before do
          stub_token_endpoint(
            params: base_token_params.merge('code' => authorization_code, 'code_verifier' => code_verifier),
            status: 401,
            body: { 'error' => 'unauthorized_client' }
          )
        end

        it_behaves_like 'raises AuthError', 'unauthorized'
      end
    end

    context 'with invalid response' do
      context 'when access token is missing from response' do
        before do
          stub_token_endpoint(
            params: base_token_params.merge('code' => authorization_code, 'code_verifier' => code_verifier),
            status: 200,
            body: { 'token_type' => 'Bearer' }
          )
        end

        it 'raises AuthError with missing access token message' do
          expect do
            public_client.request_access_token(code: authorization_code, code_verifier: code_verifier)
          end.to raise_error(Safire::Errors::AuthError, /Missing access token/)
        end
      end
    end

    context 'with network errors' do
      before do
        params = base_token_params.merge('code' => authorization_code, 'code_verifier' => code_verifier)
        stub_request(:post, config[:token_endpoint]).with(
          query: hash_including(params),
          headers: { 'Content-Type' => 'application/x-www-form-urlencoded' }
        ).to_raise(Faraday::ConnectionFailed.new('Connection refused'))
      end

      it 'raises an AuthError' do
        expect do
          public_client.request_access_token(code: authorization_code, code_verifier: code_verifier)
        end.to raise_error(Safire::Errors::AuthError)
      end
    end

    context 'with optional response fields' do
      let(:extended_response) do
        token_response_body.merge(
          'refresh_token' => 'refresh_token_abc',
          'patient' => 'patient123',
          'id_token' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
        )
      end

      before do
        stub_token_endpoint(
          params: base_token_params.merge('code' => authorization_code, 'code_verifier' => code_verifier),
          status: 200,
          body: extended_response
        )
      end

      it 'returns all fields including optional ones' do
        token_response = public_client.request_access_token(
          code: authorization_code,
          code_verifier: code_verifier
        )

        expect(token_response['refresh_token']).to eq('refresh_token_abc')
        expect(token_response['patient']).to eq('patient123')
        expect(token_response['id_token']).to be_present
      end
    end
  end

  describe '#refresh_token' do
    let(:refresh_token_value) { 'refresh_token_456def' }
    let(:base_refresh_params) do
      {
        'grant_type' => 'refresh_token',
        'client_id' => config[:client_id]
      }
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

    shared_examples 'returns refreshed token' do
      it 'returns a hash with new tokens' do
        token_response = public_client.refresh_token(refresh_token: refresh_token_value)

        expect(token_response).to be_a(Hash)
        expect(token_response).to eq(refreshed_token_response_body)
      end

      it 'returns new access_token and refresh_token' do
        token_response = public_client.refresh_token(refresh_token: refresh_token_value)

        expect(token_response['access_token']).to eq('new_access_token_123ghi')
        expect(token_response['refresh_token']).to eq('new_refresh_token_789jkl')
      end
    end

    context 'with valid refresh token' do
      before do
        stub_token_endpoint(
          params: base_refresh_params.merge('refresh_token' => refresh_token_value),
          status: 200,
          body: refreshed_token_response_body
        )
      end

      it_behaves_like 'returns refreshed token'
    end

    context 'with custom scopes' do
      let(:custom_scopes) { %w[openid profile] }

      before do
        stub_token_endpoint(
          params: base_refresh_params.merge(
            'refresh_token' => refresh_token_value,
            'scope' => custom_scopes.join(' ')
          ),
          status: 200,
          body: refreshed_token_response_body
        )
      end

      it 'includes scopes in the request' do
        token_response = public_client.refresh_token(
          refresh_token: refresh_token_value,
          scopes: custom_scopes
        )

        expect(token_response).to be_a(Hash)
      end
    end

    context 'with invalid refresh token' do
      shared_examples 'raises AuthError for refresh' do |scenario|
        it "raises an AuthError when #{scenario}" do
          expect do
            public_client.refresh_token(refresh_token: refresh_token_value)
          end.to raise_error(Safire::Errors::AuthError, /Failed to refresh access token/)
        end
      end

      context 'when refresh token is invalid' do
        before do
          stub_token_endpoint(
            params: base_refresh_params.merge('refresh_token' => 'invalid_token'),
            status: 400,
            body: { 'error' => 'invalid_grant', 'error_description' => 'Invalid refresh token' }
          )
        end

        it 'raises an AuthError' do
          expect do
            public_client.refresh_token(refresh_token: 'invalid_token')
          end.to raise_error(Safire::Errors::AuthError)
        end
      end

      context 'when refresh token is expired' do
        before do
          stub_token_endpoint(
            params: base_refresh_params.merge('refresh_token' => refresh_token_value),
            status: 400,
            body: { 'error' => 'invalid_grant', 'error_description' => 'Refresh token expired' }
          )
        end

        it_behaves_like 'raises AuthError for refresh', 'refresh token is expired'
      end
    end

    context 'with network errors' do
      before do
        params = base_refresh_params.merge('refresh_token' => refresh_token_value)
        stub_request(:post, config[:token_endpoint]).with(
          query: hash_including(params),
          headers: { 'Content-Type' => 'application/x-www-form-urlencoded' }
        ).to_raise(Faraday::TimeoutError.new('Request timeout'))
      end

      it 'raises an AuthError' do
        expect do
          public_client.refresh_token(refresh_token: refresh_token_value)
        end.to raise_error(Safire::Errors::AuthError)
      end
    end
  end
end
