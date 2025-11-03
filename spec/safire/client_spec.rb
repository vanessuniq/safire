require 'spec_helper'

RSpec.describe Safire::Client do
  let(:smart_metadata) do
    root = File.expand_path '../', File.dirname(File.absolute_path(__FILE__))
    JSON.parse(File.read(File.join(root, 'fixtures', 'smart_config.json')))
  end

  let(:config) do
    Safire::ClientConfig.new(
      {
        client_id: 'test_client_id',
        redirect_uri: 'https://app.example.com/callback',
        scopes: ['openid', 'profile', 'patient/*.read'],
        base_url: 'https://fhir.example.com',
        issuer: 'https://fhir.example.com'
      }
    )
  end

  let(:authorization_code) { 'test_authorization_code_abc123' }
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
      'redirect_uri' => config.redirect_uri,
      'client_id' => config.client_id
    }
  end

  let(:client) { described_class.new(config) }

  def stub_token_request(params:, response_status:, response_body:)
    stub_request(:post, smart_metadata['token_endpoint'])
      .with(query: hash_including(params))
      .to_return(
        status: response_status,
        body: response_body.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  before do
    # discovery stub
    stub_request(:get, "#{config.base_url}/.well-known/smart-configuration")
      .to_return(
        status: 200,
        body: smart_metadata.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    # token endpoint stub
    stub_token_request(
      params: base_token_params.merge('code' => authorization_code),
      response_status: 200,
      response_body: token_response_body
    )
  end

  describe 'Public client auth flow' do
    it 'performs disccovery, authorization, and token exchange' do # rubocop:disable RSpec/MultipleExpectations
      # step 1: discovery
      metadata = client.smart_metadata
      smart_metadata.each do |k, v|
        expect(metadata.send(k)).to eq(v)
      end

      # step 2: build authorization URL
      public_client = client.public_client
      public_client.authorization_url => { auth_url:, state:, code_verifier: }
      expect(state).to be_present
      expect(code_verifier).to be_present
      expect(auth_url).to include('response_type=code')
      expect(auth_url).to include("client_id=#{config.client_id}")
      expect(auth_url).to include("redirect_uri=#{CGI.escape(config.redirect_uri)}")
      expect(auth_url).to include('code_challenge=')
      expect(auth_url).to include('code_challenge_method=S256')
      expect(auth_url).to include("aud=#{CGI.escape(config.issuer)}")

      # step 3: Simulate authorization code received from auth server
      # In real app, the app would redirect user to auth_url and handle the callback

      # step 4: exchange authorization code for access token
      token_response = public_client.request_access_token(code: authorization_code, code_verifier:)
      expect(token_response).to be_a(Hash)
      expect(token_response).to eq(token_response_body.transform_keys(&:to_s))
    end
  end
end
