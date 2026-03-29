require 'spec_helper'

#
# Live Integration Tests for SMART Backend Services
#
# These tests validate the Safire gem against a real SMART on FHIR server.
# They are tagged with :live and skipped by default.
#
# To run:
#   bundle exec rspec --tag live spec/integration/backend_services_live_spec.rb
#
# Required environment variables for token exchange tests:
#   SAFIRE_LIVE_BACKEND_BASE_URL        — FHIR server base URL
#   SAFIRE_LIVE_BACKEND_CLIENT_ID       — registered backend client ID
#   SAFIRE_LIVE_BACKEND_KID             — key ID matching the registered JWKS
#   SAFIRE_LIVE_BACKEND_PRIVATE_KEY_PEM — PEM-encoded RSA or EC private key (inline)
#
# Optional:
#   SAFIRE_LIVE_BACKEND_SCOPES          — space-separated scopes (default: 'system/*.rs')
#   SAFIRE_LIVE_BACKEND_ALGORITHM       — JWT algorithm (default: 'RS384')
#
RSpec.describe 'SMART Backend Services Flow (Live Server)', :live, type: :integration do
  let(:base_url)    { ENV.fetch('SAFIRE_LIVE_BACKEND_BASE_URL', nil) }
  let(:client_id)   { ENV.fetch('SAFIRE_LIVE_BACKEND_CLIENT_ID', nil) }
  let(:kid)         { ENV.fetch('SAFIRE_LIVE_BACKEND_KID', nil) }
  let(:algorithm)   { ENV.fetch('SAFIRE_LIVE_BACKEND_ALGORITHM', 'RS384') }
  let(:scopes)      { ENV.fetch('SAFIRE_LIVE_BACKEND_SCOPES', 'system/*.rs').split }
  let(:private_key) do
    pem = ENV.fetch('SAFIRE_LIVE_BACKEND_PRIVATE_KEY_PEM', nil)
    OpenSSL::PKey.read(pem) if pem
  end

  before(:all) do
    unless ENV['SAFIRE_LIVE_BACKEND_BASE_URL']
      skip 'Set SAFIRE_LIVE_BACKEND_BASE_URL to run backend services live tests'
    end

    WebMock.allow_net_connect!
    uri = URI("#{ENV.fetch('SAFIRE_LIVE_BACKEND_BASE_URL', nil)}/.well-known/smart-configuration")
    Net::HTTP.get_response(uri)
  rescue StandardError => e
    skip "Backend services server not reachable: #{e.message}"
  end

  after(:all) { WebMock.disable_net_connect! }

  describe 'SMART Discovery' do
    it 'fetches metadata advertising client_credentials grant and private_key_jwt auth' do
      config   = Safire::ClientConfig.new(base_url:, client_id: 'probe')
      metadata = Safire::Client.new(config).server_metadata

      expect(metadata).to be_a(Safire::Protocols::SmartMetadata)
      expect(metadata.token_endpoint).to be_present
      expect(metadata.token_endpoint).to start_with('https://')
      expect(metadata.grant_types_supported).to include('client_credentials')
      expect(metadata.token_endpoint_auth_methods_supported).to include('private_key_jwt')
    end
  end

  describe 'Token Exchange' do
    let(:config) do
      Safire::ClientConfig.new(
        base_url:,
        client_id:,
        scopes:,
        private_key:,
        kid:,
        jwt_algorithm: algorithm
      )
    end

    before do
      skip 'Set SAFIRE_LIVE_BACKEND_CLIENT_ID to run token exchange tests' unless client_id
      skip 'Set SAFIRE_LIVE_BACKEND_KID to run token exchange tests' unless kid
      skip 'Set SAFIRE_LIVE_BACKEND_PRIVATE_KEY_PEM to run token exchange tests' unless private_key
    end

    it 'exchanges a JWT assertion for an access token on a real server' do
      tokens = Safire::Client.new(config).request_backend_token

      expect(tokens['access_token']).to be_present
      expect(tokens['token_type']).to eq('Bearer')
      expect(tokens['scope']).to be_present
      expect(tokens['expires_in']).to be_a(Integer)
    end

    it 'accepts a scope override at call time' do
      tokens = Safire::Client.new(config).request_backend_token(scopes: scopes.first(1))

      expect(tokens['access_token']).to be_present
    end
  end
end
