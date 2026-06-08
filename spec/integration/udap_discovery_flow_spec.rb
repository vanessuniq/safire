require 'spec_helper'

RSpec.describe 'UDAP Discovery Flow', type: :integration do
  #
  # Tests UDAP well-known discovery per HL7 UDAP Security STU2.
  # https://hl7.org/fhir/us/udap-security/STU2/discovery.html
  #
  # Flow:
  # 1. GET /.well-known/udap (optionally with ?community=<URI>)
  # 2. Parse and validate UdapMetadata
  #

  # ---------- Test Data ----------

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }

  let(:udap_metadata_body) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_supported' => [],
      'grant_types_supported' => %w[client_credentials authorization_code],
      'scopes_supported' => %w[system/*.rs openid profile],
      'token_endpoint' => "#{base_url}/token",
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => %w[RS256 ES256],
      'registration_endpoint' => "#{base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => %w[RS256 ES256],
      'authorization_endpoint' => "#{base_url}/authorize",
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }
  end

  let(:config) { Safire::ClientConfig.new(base_url: base_url) }
  let(:client) { Safire::Client.new(config, protocol: :udap) }

  let(:signed_claims) do
    {
      'token_endpoint' => "#{base_url}/token",
      'registration_endpoint' => "#{base_url}/register"
    }
  end
  let(:validator_double) do
    instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: signed_claims)
  end

  # ---------- Basic Discovery ----------

  context 'when discovery succeeds' do
    before do
      stub_request(:get, well_known_url)
        .to_return(status: 200, body: udap_metadata_body.to_json, headers: { 'Content-Type' => 'application/json' })
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
    end

    it 'returns a UdapMetadata instance' do
      expect(client.server_metadata).to be_a(Safire::Protocols::UdapMetadata)
    end

    it 'exposes the token endpoint from the response' do
      expect(client.server_metadata.token_endpoint).to eq("#{base_url}/token")
    end

    it 'caches discovery and avoids duplicate HTTP requests' do
      2.times { client.server_metadata }
      expect(a_request(:get, well_known_url)).to have_been_made.once
    end

    it 'passes valid? for a conformant response' do
      expect(client.server_metadata.valid?).to be(true)
    end
  end

  # ---------- Community-Scoped Discovery ----------

  context 'with a community URI' do
    let(:community) { 'https://udap.example.org/community' }

    before do
      stub_request(:get, well_known_url)
        .with(query: { 'community' => community })
        .to_return(status: 200, body: udap_metadata_body.to_json, headers: { 'Content-Type' => 'application/json' })
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
    end

    it 'passes the community as a query parameter' do
      client.server_metadata(community: community)
      expect(a_request(:get, well_known_url).with(query: { 'community' => community })).to have_been_made.once
    end

    it 'returns a UdapMetadata instance scoped to the community' do
      expect(client.server_metadata(community: community)).to be_a(Safire::Protocols::UdapMetadata)
    end
  end

  # ---------- Error Cases ----------

  context 'when server returns 204 (no UDAP support)' do
    before do
      stub_request(:get, well_known_url)
        .to_return(status: 204, body: '', headers: {})
    end

    it 'raises DiscoveryError' do
      expect { client.server_metadata }.to raise_error(Safire::Errors::DiscoveryError)
    end

    it 'reports no UDAP workflows supported' do
      expect { client.server_metadata }
        .to raise_error(Safire::Errors::DiscoveryError, /no UDAP workflows supported/)
    end
  end

  context 'when server returns a 404' do
    before do
      stub_request(:get, well_known_url)
        .to_return(status: 404, body: '{"error":"not_found"}', headers: { 'Content-Type' => 'application/json' })
    end

    it 'raises DiscoveryError with the HTTP status' do
      expect { client.server_metadata }
        .to raise_error(Safire::Errors::DiscoveryError) do |e|
          expect(e.status).to eq(404)
          expect(e.message).to include('UDAP metadata')
        end
    end
  end
end
