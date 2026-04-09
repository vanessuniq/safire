require 'spec_helper'

RSpec.describe 'SMART Dynamic Client Registration End-to-End Flow', type: :integration do
  #
  # Tests the OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591) flow
  # as encouraged by SMART App Launch 2.2.0.
  #
  # Flow:
  # 1. Discovery: Fetch /.well-known/smart-configuration (optional — endpoint can be passed explicitly)
  # 2. Registration: POST client metadata to the registration endpoint
  # 3. Receive client_id (and optionally client_secret) in the response
  # 4. Build a new configured client with the obtained credentials for subsequent flows
  #

  # ---------- Test Data ----------

  let(:base_url)              { 'https://fhir.example.com' }
  let(:registration_endpoint) { "#{base_url}/register" }
  let(:token_endpoint)        { "#{base_url}/token" }
  let(:auth_endpoint)         { "#{base_url}/authorize" }

  let(:smart_metadata) do
    {
      'issuer' => base_url,
      'authorization_endpoint' => auth_endpoint,
      'token_endpoint' => token_endpoint,
      'registration_endpoint' => registration_endpoint,
      'grant_types_supported' => %w[authorization_code client_credentials],
      'token_endpoint_auth_methods_supported' => %w[private_key_jwt client_secret_basic],
      'capabilities' => %w[launch-standalone client-public client-confidential-asymmetric],
      'code_challenge_methods_supported' => ['S256']
    }
  end

  let(:client_metadata) do
    {
      client_name: 'My SMART App',
      redirect_uris: ['https://myapp.example.com/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'openid profile patient/*.read',
      jwks_uri: 'https://myapp.example.com/.well-known/jwks.json'
    }
  end

  let(:registration_response) do
    {
      'client_id' => 'dyn_client_abc123',
      'client_name' => 'My SMART App',
      'redirect_uris' => ['https://myapp.example.com/callback'],
      'grant_types' => ['authorization_code'],
      'token_endpoint_auth_method' => 'private_key_jwt'
    }
  end

  # ---------- Helpers ----------

  def capture_error(klass)
    yield
    nil
  rescue klass => e
    e
  end

  def stub_discovery
    stub_request(:get, "#{base_url}/.well-known/smart-configuration")
      .to_return(status: 200, body: smart_metadata.to_json,
                 headers: { 'Content-Type' => 'application/json' })
  end

  def stub_registration_post(response_body: registration_response, status: 201)
    stub_request(:post, registration_endpoint)
      .to_return(status: status, body: response_body.to_json,
                 headers: { 'Content-Type' => 'application/json' })
  end

  # ---------- Discovery ----------

  describe 'Discovery' do
    before { stub_discovery }

    it 'exposes the registration_endpoint from SMART metadata' do
      client = Safire::Client.new({ base_url: })
      expect(client.server_metadata.registration_endpoint).to eq(registration_endpoint)
    end
  end

  # ---------- Registration ----------

  describe 'Registration' do
    before { stub_discovery }

    context 'when registration_endpoint is discovered automatically' do
      before { stub_registration_post }

      it 'sends a POST with JSON metadata and returns the registration response' do
        client = Safire::Client.new({ base_url: })
        result = client.register_client(client_metadata)

        expect(result['client_id']).to eq('dyn_client_abc123')
        expect(result['client_name']).to eq('My SMART App')
      end

      it 'POSTs application/json with the correct metadata fields' do
        Safire::Client.new({ base_url: }).register_client(client_metadata)

        expect(WebMock).to(have_requested(:post, registration_endpoint).with do |req|
          body = JSON.parse(req.body)
          req.headers['Content-Type'].start_with?('application/json') &&
            body['client_name'] == 'My SMART App' &&
            body['redirect_uris'] == ['https://myapp.example.com/callback'] &&
            body['token_endpoint_auth_method'] == 'private_key_jwt'
        end)
      end
    end

    context 'when registration_endpoint is passed explicitly' do
      # stub_discovery is inherited from the outer describe but should NOT be called —
      # the explicit endpoint bypasses discovery entirely.
      before { stub_registration_post }

      it 'uses the explicit endpoint instead of discovery' do
        client = Safire::Client.new({ base_url: })
        result = client.register_client(client_metadata, registration_endpoint:)

        expect(result['client_id']).to eq('dyn_client_abc123')
        expect(WebMock).to have_requested(:post, registration_endpoint)
        expect(WebMock).not_to have_requested(:get, "#{base_url}/.well-known/smart-configuration")
      end
    end

    context 'when an initial access token is required (RFC 7591 §3.1)' do
      before { stub_registration_post }

      it 'includes the Authorization header with the provided bearer token' do
        Safire::Client.new({ base_url: }).register_client(
          client_metadata,
          registration_endpoint:,
          authorization: 'Bearer initial-access-token-xyz'
        )

        expect(WebMock).to have_requested(:post, registration_endpoint)
          .with(headers: { 'Authorization' => 'Bearer initial-access-token-xyz' })
      end
    end
  end

  # ---------- Error Handling ----------

  describe 'Error Handling' do
    context 'when the server rejects the registration (RFC 7591 error response)' do
      before do
        stub_discovery
        stub_request(:post, registration_endpoint).to_return(
          status: 400,
          body: { 'error' => 'invalid_client_metadata',
                  'error_description' => 'jwks_uri is not reachable' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises RegistrationError with the RFC 7591 error fields' do
        error = capture_error(Safire::Errors::RegistrationError) do
          Safire::Client.new({ base_url: }).register_client(client_metadata)
        end
        expect(error).to be_a(Safire::Errors::RegistrationError)
        expect(error.status).to eq(400)
        expect(error.error_code).to eq('invalid_client_metadata')
        expect(error.error_description).to eq('jwks_uri is not reachable')
      end
    end

    context 'when the server does not advertise a registration_endpoint' do
      before do
        stub_request(:get, "#{base_url}/.well-known/smart-configuration")
          .to_return(
            status: 200,
            body: smart_metadata.except('registration_endpoint').to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
      end

      it 'raises DiscoveryError directing the caller to provide the endpoint explicitly' do
        expect do
          Safire::Client.new({ base_url: }).register_client(client_metadata)
        end.to raise_error(Safire::Errors::DiscoveryError, /registration_endpoint/)
      end
    end

    context 'when a network error occurs during registration' do
      before do
        stub_discovery
        stub_request(:post, registration_endpoint).to_raise(Faraday::ConnectionFailed)
      end

      it 'raises NetworkError' do
        expect do
          Safire::Client.new({ base_url: }).register_client(client_metadata, registration_endpoint:)
        end.to raise_error(Safire::Errors::NetworkError)
      end
    end
  end
end
