require 'rack/mock'
require 'spec_helper'

original_rack_env = ENV.fetch('RACK_ENV', nil)
ENV['RACK_ENV'] = 'test'
require_relative '../../../examples/sinatra_app/app'
original_rack_env.nil? ? ENV.delete('RACK_ENV') : ENV['RACK_ENV'] = original_rack_env

RSpec.describe SafireDemo do
  let(:request) { Rack::MockRequest.new(described_class) }
  let(:smart_server) { build_server('smart-only', protocols: ['smart']) }
  let(:udap_server) { build_server('udap-only', protocols: ['udap'], client_id: nil) }
  let(:smart_metadata) { Safire::Protocols::SmartMetadata.new(smart_metadata_hash) }
  let(:smart_metadata_hash) do
    {
      'authorization_endpoint' => "#{smart_server.base_url}/authorize",
      'token_endpoint' => "#{smart_server.base_url}/token",
      'capabilities' => %w[launch-standalone client-public],
      'grant_types_supported' => ['authorization_code'],
      'response_types_supported' => ['code'],
      'token_endpoint_auth_methods_supported' => ['none']
    }
  end
  let(:udap_trust_policy) { UdapDiscoveryPresenter::TrustPolicy.new({}) }
  let(:udap_metadata) { Safire::Protocols::UdapMetadata.new(udap_metadata_hash) }
  let(:udap_metadata_hash) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => ['system/*.rs'],
      'token_endpoint' => "#{udap_server.base_url}/token",
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{udap_server.base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'header.payload.signature'
    }
  end

  def build_server(id, protocols:, client_id: 'client-123')
    FhirServer.new(
      id: id,
      name: id.tr('-', ' ').split.map(&:capitalize).join(' '),
      base_url: "https://#{id}.example.com/fhir",
      client_id: client_id,
      scopes: %w[openid profile],
      protocols: protocols
    )
  end

  def response_for(method, path)
    request.request(method.to_s.upcase, path)
  end

  before do
    described_class.metadata_cache.clear
    allow(FhirServer).to receive(:find).with('smart-only').and_return(smart_server)
    allow(FhirServer).to receive(:find).with('udap-only').and_return(udap_server)
    allow(FhirServer).to receive(:find_by_base_url).with(udap_server.base_url).and_return(udap_server)
    allow(UdapDiscoveryPresenter::TrustPolicy).to receive(:new).and_return(udap_trust_policy)
  end

  describe 'protocol guards' do
    [
      [:get, '/demo/udap-only/discovery'],
      [:get, '/demo/udap-only/authorize'],
      [:post, '/demo/udap-only/authorize'],
      [:get, '/demo/udap-only/backend-token'],
      [:post, '/demo/udap-only/backend-token'],
      [:get, '/demo/udap-only/refresh']
    ].each do |method, path|
      it "redirects #{method.upcase} #{path} for a UDAP-only server" do
        response = response_for(method, path)

        expect(response.status).to be_between(300, 399)
        expect(response.location).to end_with('/servers/udap-only')
      end
    end

    it 'redirects UDAP discovery for a SMART-only server' do
      response = response_for(:get, '/demo/smart-only/udap-discovery')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end

    it 'redirects EHR launch for a UDAP-only server' do
      response = response_for(:get, '/launch?launch=abc&iss=https%3A%2F%2Fudap-only.example.com%2Ffhir')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/udap-only')
    end
  end

  describe 'SMART discovery' do
    it 'renders discovered metadata for a SMART server' do
      client = instance_double(Safire::Client, server_metadata: smart_metadata)
      allow(Safire::Client).to receive(:new).and_return(client)

      response = response_for(:get, '/demo/smart-only/discovery')

      expect(response.status).to eq(200)
      expect(response.body).to include('SMART Discovery')
      expect(response.body).to include("#{smart_server.base_url}/authorize")
    end
  end

  describe 'UDAP discovery' do
    it 'renders discovered metadata for a UDAP server' do
      client = instance_double(Safire::Client)
      allow(Safire::Client).to receive(:new)
        .with({ base_url: udap_server.base_url }, protocol: :udap)
        .and_return(client)
      allow(client).to receive(:server_metadata)
        .with(community: nil, **udap_trust_policy.server_metadata_kwargs)
        .and_return(udap_metadata)
      allow(udap_metadata).to receive(:signed_metadata_valid?).and_return(true)

      response = response_for(:get, '/demo/udap-only/udap-discovery')

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP Discovery')
      expect(response.body).to include('Validated without chain verification')
      expect(response.body).to include('complete UDAP trust anchors and CRLs are not configured')
    end

    it 'redirects when signed metadata validation fails during discovery' do
      client = instance_double(Safire::Client)
      allow(Safire::Client).to receive(:new).and_return(client)
      allow(client).to receive(:server_metadata).and_raise(
        Safire::Errors::DiscoveryError.new(endpoint: "#{udap_server.base_url}/.well-known/udap")
      )

      response = response_for(:get, '/demo/udap-only/udap-discovery')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/udap-only')
    end
  end
end
