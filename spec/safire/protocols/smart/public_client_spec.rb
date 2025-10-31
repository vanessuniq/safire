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
    described_class.new(config.except(:scopes))
  end

  def parse_query_params(url)
    Addressable::URI.parse(url).query_values
  end

  def stub_token_request(params:, response_status:, response_body:)
    stub_request(:post, config[:token_endpoint])
      .with(query: hash_including(params))
      .to_return(
        status: response_status,
        body: response_body.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  describe '#authorization_url' do
    let(:auth_data) { public_client.authorization_url }
    let(:query_params) { parse_query_params(auth_data[:auth_url]) }

    shared_examples 'includes required parameters' do
      it 'includes response_type, client_id, redirect_uri, aud, and PKCE' do
        expect(query_params['response_type']).to eq('code')
        expect(query_params['client_id']).to eq(config[:client_id])
        expect(query_params['redirect_uri']).to eq(config[:redirect_uri])
        expect(query_params['aud']).to eq(config[:issuer])
        expect(query_params).to have_key('code_challenge')
        expect(query_params['code_challenge_method']).to eq('S256')
      end
    end

    context 'when scopes are provided' do
      it 'generates a valid authorization URL' do
        expect(auth_data).to have_key(:auth_url)
        expect(auth_data).to have_key(:state)
      end

      it 'includes the configured scopes' do
        expect(query_params['scope']).to eq(config[:scopes].join(' '))
      end

      it_behaves_like 'includes required parameters'
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

      it 'uses the custom scopes in the authorization URL' do
        expect(query_params['scope']).to eq(custom_scopes.join(' '))
      end
    end

    context 'when launch parameter is provided' do
      let(:launch_value) { 'launch_token_123' }
      let(:auth_data) { public_client.authorization_url(launch: launch_value) }

      it 'includes the launch parameter in the authorization URL' do
        expect(query_params['launch']).to eq(launch_value)
      end
    end
  end

  describe '#request_access_token' do
    let(:authorization_code) { 'auth_code_abc123' }
    let(:token_response_body) do
      {
        access_token: 'access_token_xyz789',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'openid profile patient/*.read'
      }
    end
    let(:base_token_params) do
      {
        'grant_type' => 'authorization_code',
        'redirect_uri' => config[:redirect_uri],
        'client_id' => config[:client_id]
      }
    end

    context 'with valid authorization code' do
      before do
        stub_token_request(
          params: base_token_params.merge('code' => authorization_code),
          response_status: 200,
          response_body: token_response_body
        )
      end

      it 'successfully exchanges authorization code for access token' do
        token_response = public_client.request_access_token(authorization_code)

        expect(token_response).to be_a(Hash)
        expect(token_response).to eq(token_response_body.transform_keys(&:to_s))
      end
    end

    context 'with invalid authorization code' do
      before do
        stub_token_request(
          params: base_token_params.merge('code' => nil),
          response_status: 401,
          response_body: { error: 'Invalid code' }
        )
      end

      it 'raises an AuthError' do
        expect { public_client.request_access_token(nil) }
          .to raise_error(Safire::Errors::AuthError, /HTTP request failed/)
      end
    end

    context 'when access token is missing from response' do
      before do
        stub_token_request(
          params: base_token_params.merge('code' => authorization_code),
          response_status: 200,
          response_body: token_response_body.except(:access_token)
        )
      end

      it 'raises AuthError' do
        expect { public_client.request_access_token(authorization_code) }
          .to raise_error(Safire::Errors::AuthError, /Missing access token/)
      end
    end
  end

  describe '#refresh_token' do
    let(:refresh_token_value) { 'refresh_token_456def' }
    let(:refreshed_token_response_body) do
      {
        access_token: 'new_access_token_123ghi',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'openid profile patient/*.read',
        refresh_token: 'new_refresh_token_789jkl'
      }
    end
    let(:refresh_params) do
      {
        'grant_type' => 'refresh_token',
        'client_id' => config[:client_id]
      }
    end

    context 'with valid refresh token' do
      before do
        stub_token_request(
          params: refresh_params.merge('refresh_token' => refresh_token_value),
          response_status: 200,
          response_body: refreshed_token_response_body
        )
      end

      it 'successfully refreshes the access token' do
        token_response = public_client.refresh_token(refresh_token: refresh_token_value)

        expect(token_response).to be_a(Hash)
        expect(token_response).to eq(refreshed_token_response_body.transform_keys(&:to_s))
      end
    end

    context 'with invalid refresh token' do
      let(:invalid_token) { 'invalid_refresh_token' }

      before do
        stub_token_request(
          params: refresh_params.merge('refresh_token' => invalid_token),
          response_status: 400,
          response_body: { error: 'Invalid refresh token' }
        )
      end

      it 'raises an AuthError' do
        expect { public_client.refresh_token(refresh_token: invalid_token) }
          .to raise_error(Safire::Errors::AuthError, /HTTP request failed/)
      end
    end
  end
end
