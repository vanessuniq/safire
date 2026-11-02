require 'spec_helper'

RSpec.describe Safire::Protocols::Udap, '#authorization_url' do
  subject(:udap) { described_class.new(config) }

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:signed_authorization_endpoint) { 'https://auth.example.com/signed/authorize' }
  let(:unsigned_authorization_endpoint) { 'https://auth.example.com/unsigned/authorize' }
  let(:client_id) { 'udap-client-123' }
  let(:redirect_uri) { 'https://app.example.com/callback' }
  let(:configured_scopes) { %w[openid fhirUser patient/Patient.rs] }
  let(:allow_insecure_localhost) { false }
  let(:config) do
    instance_double(
      Safire::ClientConfig,
      base_url:,
      client_id:,
      redirect_uri:,
      scopes: configured_scopes,
      allow_insecure_localhost:,
      private_key: nil,
      certificate_chain: nil,
      jwt_algorithm: nil
    )
  end
  let(:metadata_overrides) { {} }
  let(:udap_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => %w[authorization_code refresh_token],
      'scopes_supported' => %w[openid fhirUser patient/*.rs],
      'authorization_endpoint' => unsigned_authorization_endpoint,
      'token_endpoint' => 'https://auth.example.com/token',
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://auth.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }.merge(metadata_overrides)
  end
  let(:signed_claims) do
    {
      'token_endpoint' => 'https://auth.example.com/token',
      'registration_endpoint' => 'https://auth.example.com/register',
      'authorization_endpoint' => signed_authorization_endpoint
    }
  end
  let(:warnings) { [] }

  def stub_discovery(query: nil)
    request = stub_request(:get, well_known_url)
    request = request.with(query:) if query
    request.to_return(status: 200, body: udap_metadata.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def query_params(result)
    Addressable::URI.parse(result[:auth_url]).query_values
  end

  before do
    validator = instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: signed_claims)
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
    allow(Safire.logger).to receive(:warn) { |message| warnings << message }
  end

  describe 'successful request' do
    before { stub_discovery }

    it 'returns auth_url, state, and code_verifier like the SMART contract' do
      result = udap.authorization_url

      expect(result.keys).to contain_exactly(:auth_url, :state, :code_verifier)
      expect(result[:state]).to eq(query_params(result)['state'])
    end

    it 'targets the authoritative signed authorization endpoint' do
      result = udap.authorization_url
      uri = Addressable::URI.parse(result[:auth_url])

      expect("#{uri.scheme}://#{uri.host}#{uri.path}").to eq(signed_authorization_endpoint)
      expect(result[:auth_url]).not_to include('unsigned')
    end

    it 'adds exactly the STU2 §7.2 authorization request parameters' do
      params = query_params(udap.authorization_url)

      expect(params.keys).to contain_exactly(
        'response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method'
      )
      expect(params).to include(
        'response_type' => 'code',
        'client_id' => client_id,
        'redirect_uri' => redirect_uri,
        'scope' => 'openid fhirUser patient/Patient.rs',
        'code_challenge_method' => 'S256'
      )
    end

    it 'does not add SMART-only aud or launch parameters' do
      expect(query_params(udap.authorization_url)).not_to include('aud', 'launch')
    end

    it 'percent-encodes the space-delimited scope' do
      expect(udap.authorization_url[:auth_url]).to include('scope=openid%20fhirUser%20patient%2FPatient.rs')
    end

    it 'derives code_challenge as BASE64URL(SHA256(code_verifier)) without padding' do
      result = udap.authorization_url
      expected = Base64.urlsafe_encode64(Digest::SHA256.digest(result[:code_verifier]), padding: false)

      expect(query_params(result)['code_challenge']).to eq(expected)
      expect(result[:code_verifier]).to match(/\A[A-Za-z0-9\-._~]{43,128}\z/)
    end

    it 'generates a high-entropy URL-safe state' do
      state = udap.authorization_url[:state]

      expect(state).to match(/\A[A-Za-z0-9_-]{43}\z/)
    end

    it 'generates a fresh state and code_verifier per call' do
      results = Array.new(5) { udap.authorization_url }

      expect(results.map { |r| r[:state] }.uniq.size).to eq(5)
      expect(results.map { |r| r[:code_verifier] }.uniq.size).to eq(5)
    end

    it 'discovers once and reuses the cached metadata' do
      2.times { udap.authorization_url }

      expect(WebMock).to have_requested(:get, well_known_url).once
    end

    it 'logs an info line without request values' do
      allow(Safire.logger).to receive(:info)

      udap.authorization_url

      expect(Safire.logger).to have_received(:info)
        .with('Generating UDAP authorization URL (authorization_code grant)...')
    end

    it 'emits no warnings for advertised scopes' do
      udap.authorization_url

      expect(warnings).to be_empty
    end
  end

  describe 'endpoint query preservation' do
    let(:signed_authorization_endpoint) { 'https://auth.example.com/authorize?tenant=a%20b' }

    it 'keeps the endpoint query component and appends the request parameters' do
      stub_discovery

      result = udap.authorization_url

      expect(result[:auth_url]).to start_with('https://auth.example.com/authorize?tenant=a%20b&')
      expect(query_params(result)).to include('tenant' => 'a b', 'response_type' => 'code')
    end
  end

  describe 'scopes' do
    before { stub_discovery }

    it 'uses per-call scopes over configured scopes' do
      params = query_params(udap.authorization_url(scopes: ['openid', 'patient/Observation.rs']))

      expect(params['scope']).to eq('openid patient/Observation.rs')
    end

    it 'accepts a space-delimited String and removes duplicates and blanks' do
      params = query_params(udap.authorization_url(scopes: ' openid  openid patient/Patient.rs '))

      expect(params['scope']).to eq('openid patient/Patient.rs')
    end

    it 'falls back to configured scopes when per-call scopes are blank' do
      expect(query_params(udap.authorization_url(scopes: [' ']))['scope']).to eq('openid fhirUser patient/Patient.rs')
    end

    context 'without per-call or configured scopes' do
      let(:configured_scopes) { nil }

      it 'raises ConfigurationError before discovery' do
        expect { udap.authorization_url }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq([:scopes])
        }
        expect(WebMock).not_to have_requested(:get, well_known_url)
      end
    end

    it 'rejects a scope with characters outside the RFC 6749 scope-token set' do
      expect { udap.authorization_url(scopes: ['patient/Patient.rs"']) }
        .to raise_error(Safire::Errors::ValidationError, /RFC 6749 scope-token characters/)
    end

    it 'rejects a non-String scope entry' do
      expect { udap.authorization_url(scopes: [42]) }.to raise_error(Safire::Errors::ConfigurationError)
    end

    it 'warns but proceeds for an unadvertised wildcard scope (value-free)' do
      result = udap.authorization_url(scopes: ['openid', 'user/*.rs'])

      expect(query_params(result)['scope']).to eq('openid user/*.rs')
      expect(warnings).to contain_exactly(
        a_string_starting_with('[UDAP] requested wildcard scope count=1; no exact advertisement in scopes_supported')
      )
      expect(warnings.join).not_to include('user/')
    end

    context 'when scopes_supported is unusable' do
      let(:metadata_overrides) { { 'scopes_supported' => [] } }

      it 'warns but proceeds for a requested wildcard' do
        expect { udap.authorization_url(scopes: ['patient/*.rs']) }.not_to raise_error
        expect(warnings.first).to include('exact advertisement cannot be confirmed')
      end
    end
  end

  describe 'configuration' do
    context 'without client_id or redirect_uri' do
      let(:client_id) { nil }
      let(:redirect_uri) { '' }

      it 'raises ConfigurationError naming both before discovery' do
        expect { udap.authorization_url }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq(%i[client_id redirect_uri])
        }
        expect(WebMock).not_to have_requested(:get, well_known_url)
      end
    end

    it 'rejects a malformed community before discovery' do
      expect { udap.authorization_url(community: 'not a uri') }.to raise_error(Safire::Errors::ConfigurationError)
      expect(WebMock).not_to have_requested(:get, well_known_url)
    end

    it 'scopes discovery to the community' do
      stub_discovery(query: { 'community' => 'urn:example:community' })

      udap.authorization_url(community: 'urn:example:community')

      expect(WebMock).to have_requested(:get, well_known_url).with(query: { 'community' => 'urn:example:community' })
    end

    it 'passes the trust policy to signed metadata validation' do
      stub_discovery
      anchor = instance_double(OpenSSL::X509::Certificate, to_der: 'der')
      validator = instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: signed_claims)
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)

      udap.authorization_url(trusted_anchors: [anchor], verify_chain: false)

      expect(validator).to have_received(:signed_endpoint_claims)
        .with(hash_including(trusted_anchors: [anchor], verify_chain: false))
    end
  end

  describe 'readiness failures' do
    it 'raises DiscoveryError when signed metadata validation fails' do
      stub_discovery
      validator = instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: nil)
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)

      expect { udap.authorization_url }
        .to raise_error(Safire::Errors::DiscoveryError, /signed_metadata validation failed/)
    end

    context 'when authorization_code is not advertised' do
      let(:metadata_overrides) { { 'grant_types_supported' => ['client_credentials'] } }

      it 'raises DiscoveryError' do
        stub_discovery

        expect { udap.authorization_url }.to raise_error(Safire::Errors::DiscoveryError) { |error|
          expect(error.endpoint).to eq(well_known_url)
          expect(error.error_description).to match(/does not advertise the authorization_code grant/)
        }
      end
    end

    context 'when no authorization endpoint is published' do
      let(:metadata_overrides) { { 'authorization_endpoint' => nil } }
      let(:signed_claims) { { 'token_endpoint' => 'https://auth.example.com/token' } }

      it 'raises DiscoveryError' do
        stub_discovery

        expect { udap.authorization_url }
          .to raise_error(Safire::Errors::DiscoveryError, /missing required field 'authorization_endpoint'/)
      end
    end

    context 'when the signed authorization endpoint has a fragment' do
      let(:signed_authorization_endpoint) { 'https://auth.example.com/authorize#x' }

      it 'raises DiscoveryError' do
        stub_discovery

        expect { udap.authorization_url }.to raise_error(Safire::Errors::DiscoveryError, /must not include a fragment/)
      end
    end

    context 'when the signed authorization endpoint uses HTTP' do
      let(:signed_authorization_endpoint) { 'http://auth.example.com/authorize' }

      it 'raises DiscoveryError' do
        stub_discovery

        expect { udap.authorization_url }.to raise_error(Safire::Errors::DiscoveryError, /must use HTTPS/)
      end
    end

    it 'raises DiscoveryError when discovery returns an HTTP error' do
      stub_request(:get, well_known_url).to_return(status: 500)

      expect { udap.authorization_url }.to raise_error(Safire::Errors::DiscoveryError)
    end
  end
end
