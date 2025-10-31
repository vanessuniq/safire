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
  let(:public_client_no_scopes) do
    duplicate_config = config.dup
    duplicate_config.delete(:scopes)
    described_class.new(duplicate_config)
  end

  describe '#authorization_url' do
    context 'when scopes are provided' do
      it 'generates a valid authorization URL' do
        auth_data = public_client.authorization_url

        expect(auth_data).to have_key(:auth_url)
        expect(auth_data).to have_key(:state)

        uri = Addressable::URI.parse(auth_data[:auth_url])
        query_params = uri.query_values

        expect(query_params['response_type']).to eq('code')
        expect(query_params['client_id']).to eq(config[:client_id])
        expect(query_params['redirect_uri']).to eq(config[:redirect_uri])
        expect(query_params['scope']).to eq(config[:scopes].join(' '))
        expect(query_params['aud']).to eq(config[:issuer])
        expect(query_params).to have_key('code_challenge')
        expect(query_params['code_challenge_method']).to eq('S256')
      end
    end

    context 'when scopes are not provided' do
      it 'raises a ConfigurationError' do
        expect do
          public_client_no_scopes.authorization_url
        end.to raise_error(Safire::Errors::ConfigurationError, /requires scopes/)
      end
    end

    context 'when custom scopes are provided' do
      it 'uses the custom scopes in the authorization URL' do
        custom_scopes = ['custom.scope1', 'custom.scope2']
        auth_data = public_client.authorization_url(custom_scopes: custom_scopes)

        uri = Addressable::URI.parse(auth_data[:auth_url])
        query_params = uri.query_values

        expect(query_params['scope']).to eq(custom_scopes.join(' '))
      end
    end

    context 'when launch parameter is provided' do
      it 'includes the launch parameter in the authorization URL' do
        launch_value = 'launch_token_123'
        auth_data = public_client.authorization_url(launch: launch_value)

        uri = Addressable::URI.parse(auth_data[:auth_url])
        query_params = uri.query_values

        expect(query_params['launch']).to eq(launch_value)
      end
    end
  end

  describe '#request_access_token' do
    let(:authorization_code) { 'auth_code_abc123' }
    # let(:token_params) do
    #   {
    #     grant_type: 'authorization_code',
    #     code: authorization_code,
    #     redirect_uri: config[:redirect_uri],
    #     client_id: config[:client_id]
    #   }
    # end
    let(:token_response_body) do
      {
        access_token: 'access_token_xyz789',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'openid profile patient/*.read'
      }
    end

    it 'successfully exchanges authorization code for access token' do
      stub_request(:post, config[:token_endpoint])
        .with(
          query: hash_including(
            'grant_type' => 'authorization_code',
            'code' => authorization_code,
            'redirect_uri' => config[:redirect_uri],
            'client_id' => config[:client_id]
          )
        )
        .to_return(
          status: 200,
          body: token_response_body.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      token_response = public_client.request_access_token(authorization_code)

      expect(token_response).to be_a(Hash)
      expect(token_response).to eq(token_response_body.transform_keys(&:to_s))
    end

    it 'raises an AuthError if the token request fails' do
      stub_request(:post, config[:token_endpoint])
        .with(
          query: hash_including(
            'grant_type' => 'authorization_code',
            'code' => nil,
            'redirect_uri' => config[:redirect_uri],
            'client_id' => config[:client_id]
          )
        )
        .to_return(
          status: 401,
          body: { error: 'Invalid code' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      expect { public_client.request_access_token(nil) }.to raise_error(
        Safire::Errors::AuthError, /HTTP request failed/
      )
    end

    it 'raises AuthError if access token is missing from the response' do
      token_response = token_response_body.dup
      token_response.delete(:access_token)

      stub_request(:post, config[:token_endpoint])
        .with(
          query: hash_including(
            'grant_type' => 'authorization_code',
            'code' => authorization_code,
            'redirect_uri' => config[:redirect_uri],
            'client_id' => config[:client_id]
          )
        ).to_return(
          status: 200,
          body: token_response.to_json
        )

      expect { public_client.request_access_token(authorization_code) }.to raise_error(
        Safire::Errors::AuthError, /Missing access token/
      )
    end
  end
end
