require 'spec_helper'

RSpec.describe Safire::Client do
  let(:config) do
    Safire::ClientConfig.new(
      client_id: 'test_client_id',
      client_secret: 'test_client_secret',
      redirect_uri: 'https://app.example.com/callback',
      scopes: ['openid', 'profile', 'patient/*.read'],
      base_url: 'https://fhir.example.com',
      authorization_endpoint: 'https://fhir.example.com/authorize',
      token_endpoint: 'https://fhir.example.com/token'
    )
  end

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
      stub_request(:post, 'https://fhir.example.com/token')
        .with(headers: { 'Authorization' => /^Basic / })
        .to_return(
          status: 200,
          body: { 'access_token' => 'token123', 'token_type' => 'Bearer', 'expires_in' => 3600 }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      client = described_class.new(config, auth_type: :public)
      client.auth_type = :confidential_symmetric

      # This should use Basic auth now
      tokens = client.request_access_token(code: 'auth_code', code_verifier: 'verifier')
      expect(tokens['access_token']).to eq('token123')

      expect(WebMock).to have_requested(:post, 'https://fhir.example.com/token')
        .with(headers: { 'Authorization' => /^Basic / })
    end
  end
end
