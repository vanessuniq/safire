require 'spec_helper'

RSpec.describe Safire::Protocols::Udap do
  subject(:udap) { described_class.new(config) }

  let(:base_url) { 'https://fhir.example.com' }
  let(:config) { instance_double(Safire::ClientConfig, base_url: base_url) }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }

  let(:valid_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => ['system/*.rs'],
      'token_endpoint' => 'https://fhir.example.com/token',
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://fhir.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }
  end

  def stub_udap(url: well_known_url, status: 200, body: valid_metadata, content_type: 'application/json')
    stub_request(:get, url).to_return(
      status: status,
      body: body ? body.to_json : '',
      headers: { 'Content-Type' => content_type }
    )
  end

  # ---------- server_metadata — default (no community) ----------

  describe '#server_metadata' do
    let(:signed_claims) do
      {
        'token_endpoint' => valid_metadata['token_endpoint'],
        'registration_endpoint' => valid_metadata['registration_endpoint']
      }
    end
    let(:validator_double) do
      instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: signed_claims)
    end

    context 'without community parameter' do
      before do
        stub_udap
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
      end

      it 'returns a UdapMetadata instance' do
        expect(udap.server_metadata).to be_a(Safire::Protocols::UdapMetadata)
      end

      it 'populates the metadata from the response body' do
        expect(udap.server_metadata.token_endpoint).to eq('https://fhir.example.com/token')
      end

      it 'caches the result and makes only one HTTP request' do
        2.times { udap.server_metadata }
        expect(a_request(:get, well_known_url)).to have_been_made.once
      end
    end

    # ---------- server_metadata — community-scoped ----------

    context 'with a community parameter' do
      let(:community) { 'https://udap.example.org/community1' }
      let(:success_return) do
        { status: 200, body: valid_metadata.to_json, headers: { 'Content-Type' => 'application/json' } }
      end

      before do
        stub_request(:get, well_known_url)
          .with(query: { 'community' => community })
          .to_return(**success_return)
        stub_request(:get, well_known_url)
          .to_return(**success_return)
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
      end

      it 'appends the community as a query parameter' do
        udap.server_metadata(community: community)
        expect(a_request(:get, well_known_url).with(query: { 'community' => community })).to have_been_made.once
      end

      it 'caches per community independently from the default cache' do
        2.times { udap.server_metadata }
        2.times { udap.server_metadata(community: community) }
        # Each distinct endpoint fetched exactly once; two total HTTP requests
        expect(a_request(:get, %r{\.well-known/udap})).to have_been_made.twice
        expect(a_request(:get, well_known_url).with(query: { 'community' => community })).to have_been_made.once
      end

      it 'normalizes surrounding whitespace before building the request and cache key' do
        udap.server_metadata(community: "  #{community}  ")
        udap.server_metadata(community: community)

        expect(a_request(:get, well_known_url).with(query: { 'community' => community })).to have_been_made.once
      end
    end

    context 'with a blank community parameter' do
      before do
        stub_udap
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
      end

      it 'treats it as the default discovery request' do
        udap.server_metadata(community: '   ')
        udap.server_metadata

        expect(a_request(:get, well_known_url)).to have_been_made.once
      end
    end

    # ---------- trust policy cache isolation ----------

    context 'when called with different trust policies for the same community' do
      before do
        stub_udap
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
      end

      it 'does not serve a lenient-policy cached result to a stricter call' do
        udap.server_metadata(verify_chain: false)
        udap.server_metadata(verify_chain: true)

        expect(a_request(:get, well_known_url)).to have_been_made.twice
      end
    end

    context 'with an invalid community parameter' do
      it 'raises ConfigurationError when the value is not a URI' do
        expect { udap.server_metadata(community: 'not a uri') }
          .to raise_error(Safire::Errors::ConfigurationError, /community/)
      end

      it 'raises ConfigurationError when the value does not identify a community' do
        expect { udap.server_metadata(community: 'https:') }
          .to raise_error(Safire::Errors::ConfigurationError, /community/)
      end

      it 'raises ConfigurationError for a scheme-only URI with no host or path' do
        expect { udap.server_metadata(community: 'foo:') }
          .to raise_error(Safire::Errors::ConfigurationError, /community/)
      end

      it 'raises ConfigurationError when the value is not a string' do
        expect { udap.server_metadata(community: 123) }
          .to raise_error(Safire::Errors::ConfigurationError, /community/)
      end

      it 'does not make an HTTP request' do
        expect { udap.server_metadata(community: 'not a uri') }
          .to raise_error(Safire::Errors::ConfigurationError)

        expect(a_request(:get, %r{\.well-known/udap})).not_to have_been_made
      end
    end

    # ---------- server_metadata — 204 No Content ----------

    context 'when server returns 204 (no community)' do
      before { stub_udap(status: 204, body: nil, content_type: '') }

      it 'raises DiscoveryError' do
        expect { udap.server_metadata }.to raise_error(Safire::Errors::DiscoveryError)
      end

      it 'reports HTTP 204 in the error' do
        expect { udap.server_metadata }
          .to raise_error(Safire::Errors::DiscoveryError, /204/)
      end

      it 'reports no UDAP workflows supported' do
        expect { udap.server_metadata }
          .to raise_error(Safire::Errors::DiscoveryError, /no UDAP workflows supported/)
      end
    end

    context 'when server returns 204 for a community' do
      let(:community) { 'https://udap.example.org/community1' }

      before do
        stub_request(:get, well_known_url)
          .with(query: { 'community' => community })
          .to_return(status: 204, body: '', headers: {})
      end

      it 'includes the community in the error message' do
        expect { udap.server_metadata(community: community) }
          .to raise_error(Safire::Errors::DiscoveryError, /community/)
      end
    end

    # ---------- server_metadata — non-Hash body ----------

    context 'when response body is not a JSON object' do
      before do
        stub_request(:get, well_known_url)
          .to_return(status: 200, body: '"just a string"', headers: { 'Content-Type' => 'application/json' })
      end

      it 'raises DiscoveryError' do
        expect { udap.server_metadata }.to raise_error(Safire::Errors::DiscoveryError, /not a JSON object/)
      end
    end

    # ---------- server_metadata — HTTP errors ----------

    context 'when server returns an HTTP error' do
      before do
        stub_request(:get, well_known_url)
          .to_return(status: 404, body: '{"error":"not_found"}', headers: { 'Content-Type' => 'application/json' })
        allow(Safire.logger).to receive(:error)
      end

      it 'raises DiscoveryError' do
        expect { udap.server_metadata }.to raise_error(Safire::Errors::DiscoveryError)
      end

      it 'includes the HTTP status in the error' do
        expect { udap.server_metadata }
          .to raise_error(Safire::Errors::DiscoveryError) { |e| expect(e.status).to eq(404) }
      end

      it 'logs the failure' do
        expect { udap.server_metadata }.to raise_error(Safire::Errors::DiscoveryError)
        expect(Safire.logger).to have_received(:error).with(/UDAP discovery failed/)
      end

      it 'includes the label UDAP metadata in the error message' do
        expect { udap.server_metadata }
          .to raise_error(Safire::Errors::DiscoveryError) { |e| expect(e.message).to include('UDAP metadata') }
      end
    end

    # ---------- server_metadata — signed_metadata validation ----------

    context 'when signed_metadata validation fails' do
      let(:failing_validator) do
        instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: nil)
      end

      before do
        stub_udap
        allow(Safire.logger).to receive(:warn)
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(failing_validator)
      end

      it 'raises DiscoveryError' do
        expect { udap.server_metadata }.to raise_error(Safire::Errors::DiscoveryError)
      end

      it 'includes signed_metadata in the error description' do
        expect { udap.server_metadata }
          .to raise_error(Safire::Errors::DiscoveryError, /signed_metadata/)
      end

      it 'includes the community in the error when community-scoped' do
        community = 'https://udap.example.org/community1'
        stub_request(:get, well_known_url)
          .with(query: { 'community' => community })
          .to_return(status: 200, body: valid_metadata.to_json, headers: { 'Content-Type' => 'application/json' })

        expect { udap.server_metadata(community: community) }
          .to raise_error(Safire::Errors::DiscoveryError, /community/)
      end
    end

    context 'when signed endpoint claims differ from the unsigned values' do
      let(:signed_claims) do
        {
          'token_endpoint' => 'https://fhir.example.com/signed-token',
          'registration_endpoint' => valid_metadata['registration_endpoint']
        }
      end

      before do
        stub_udap
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator_double)
      end

      it 'returns metadata with the authoritative signed token_endpoint' do
        expect(udap.server_metadata.token_endpoint).to eq('https://fhir.example.com/signed-token')
      end

      it 'passes the raw discovery hash as unsigned_metadata to the validator' do
        udap.server_metadata

        expect(Safire::Protocols::UdapSignedMetadataValidator).to have_received(:new).with(
          valid_metadata['signed_metadata'],
          hash_including('token_endpoint' => valid_metadata['token_endpoint'])
        )
      end
    end
  end

  # ---------- Unimplemented Behaviours ----------

  describe '#authorization_url' do
    it 'raises NotImplementedError' do
      expect { udap.authorization_url }.to raise_error(NotImplementedError)
    end
  end

  describe '#request_access_token' do
    it 'raises NotImplementedError' do
      expect { udap.request_access_token }.to raise_error(NotImplementedError)
    end
  end

  describe '#refresh_token' do
    it 'raises NotImplementedError' do
      expect { udap.refresh_token }.to raise_error(NotImplementedError)
    end
  end

  describe '#token_response_valid?' do
    it 'raises NotImplementedError' do
      expect { udap.token_response_valid?({}) }.to raise_error(NotImplementedError)
    end
  end

  describe '#request_backend_token' do
    it 'raises NotImplementedError' do
      expect { udap.request_backend_token }.to raise_error(NotImplementedError)
    end
  end

  describe '#register_client' do
    it 'raises NotImplementedError' do
      expect { udap.register_client({}) }.to raise_error(NotImplementedError)
    end
  end
end
