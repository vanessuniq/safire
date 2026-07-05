require 'spec_helper'

RSpec.describe Safire::Protocols::Udap do
  subject(:udap) { described_class.new(config) }

  let(:base_url) { 'https://fhir.example.com' }
  let(:allow_insecure_localhost) { false }
  let(:config) do
    instance_double(
      Safire::ClientConfig,
      base_url:,
      allow_insecure_localhost:,
      private_key: configured_private_key,
      certificate_chain: configured_certificate_chain,
      jwt_algorithm: configured_jwt_algorithm
    )
  end
  let(:configured_private_key) { 'configured-private-key' }
  let(:configured_certificate_chain) { ['configured-certificate'] }
  let(:configured_jwt_algorithm) { nil }
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

    it 'passes the insecure-localhost policy to the HTTP client' do
      allow(Safire::HTTPClient).to receive(:new).and_call_original

      udap

      expect(Safire::HTTPClient).to have_received(:new).with(allow_insecure_localhost: false)
    end

    context 'when insecure localhost is enabled in config' do
      let(:allow_insecure_localhost) { true }

      it 'passes the opt-in to the HTTP client' do
        allow(Safire::HTTPClient).to receive(:new).and_call_original

        udap

        expect(Safire::HTTPClient).to have_received(:new).with(allow_insecure_localhost: true)
      end
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

      it 'revalidates cached signed_metadata before returning cached metadata' do
        2.times { udap.server_metadata }

        expect(validator_double).to have_received(:signed_endpoint_claims).twice
      end

      it 'refetches metadata when cached signed_metadata no longer validates' do
        stale_validator = instance_double(
          Safire::Protocols::UdapSignedMetadataValidator,
          signed_endpoint_claims: nil
        )
        fresh_validator = instance_double(
          Safire::Protocols::UdapSignedMetadataValidator,
          signed_endpoint_claims: signed_claims
        )
        allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(
          validator_double,
          stale_validator,
          fresh_validator
        )

        2.times { udap.server_metadata }

        expect(a_request(:get, well_known_url)).to have_been_made.twice
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

      it 'passes trust anchors, CRLs, and revocation checker to the validator' do
        anchor = instance_double(OpenSSL::X509::Certificate, to_der: 'anchor')
        crl = instance_double(OpenSSL::X509::CRL, to_der: 'crl')
        checker = ->(**_kwargs) { true }

        udap.server_metadata(trusted_anchors: [anchor], crls: [crl], revocation_checker: checker)

        expect(validator_double).to have_received(:signed_endpoint_claims).with(
          base_url: base_url,
          trusted_anchors: [anchor],
          crls: [crl],
          revocation_checker: checker,
          verify_chain: true,
          allow_insecure_localhost: false
        )
      end

      context 'when insecure localhost is enabled in config' do
        let(:allow_insecure_localhost) { true }

        it 'passes the opt-in to signed metadata validation' do
          udap.server_metadata

          expect(validator_double).to have_received(:signed_endpoint_claims).with(
            base_url: base_url,
            trusted_anchors: [],
            crls: [],
            revocation_checker: nil,
            verify_chain: true,
            allow_insecure_localhost: true
          )
        end

        it 'returns metadata that applies the same opt-in to capability checks' do
          allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(
            instance_double(
              Safire::Protocols::UdapSignedMetadataValidator,
              signed_endpoint_claims: {
                'token_endpoint' => 'http://localhost:3000/token',
                'registration_endpoint' => 'http://127.0.0.1:3000/register'
              }
            )
          )

          metadata = udap.server_metadata

          expect(metadata.supports_dynamic_registration?).to be(true)
          expect(metadata.supports_jwt_client_auth?).to be(true)
        end
      end

      it 'does not share cached metadata across different CRL sets' do
        anchor = instance_double(OpenSSL::X509::Certificate, to_der: 'anchor')
        crl1 = instance_double(OpenSSL::X509::CRL, to_der: 'crl-1')
        crl2 = instance_double(OpenSSL::X509::CRL, to_der: 'crl-2')

        udap.server_metadata(trusted_anchors: [anchor], crls: [crl1])
        udap.server_metadata(trusted_anchors: [anchor], crls: [crl2])

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
    let(:registration_endpoint) { 'https://fhir.example.com/signed-register' }
    let(:client_uri) { 'https://client.example.com/app' }
    let(:client_metadata) do
      {
        client_name: 'Example Backend Service',
        contacts: ['mailto:security@example.com'],
        grant_types: ['client_credentials'],
        scope: 'system/Patient.rs'
      }
    end
    let(:registration_response) do
      {
        'client_id' => 'udap-client-123',
        'client_name' => 'Example Backend Service'
      }
    end
    let(:registration_discovery_body) do
      valid_metadata.merge(
        'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
        'registration_endpoint' => 'https://fhir.example.com/unsigned-register',
        'registration_endpoint_jwt_signing_alg_values_supported' => %w[RS256 RS384]
      )
    end
    let(:registration_signed_claims) do
      {
        'token_endpoint' => valid_metadata['token_endpoint'],
        'registration_endpoint' => registration_endpoint
      }
    end
    let(:registration_validator) do
      instance_double(
        Safire::Protocols::UdapSignedMetadataValidator,
        signed_endpoint_claims: registration_signed_claims
      )
    end
    let(:registration_metadata) { instance_double(Safire::Protocols::UdapRegistrationMetadata) }
    let(:software_statement) { instance_double(Safire::Protocols::UdapSoftwareStatement, to_jwt: 'header.payload.sig') }

    def stub_registration_discovery_for_community(community)
      stub_request(:get, well_known_url)
        .with(query: { 'community' => community })
        .to_return(
          status: 200,
          body: registration_discovery_body.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
    end

    before do
      stub_udap(body: registration_discovery_body)
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(registration_validator)
      allow(Safire::Protocols::UdapRegistrationMetadata).to receive(:new).and_return(registration_metadata)
      allow(Safire::Protocols::UdapSoftwareStatement).to receive(:new).and_return(software_statement)
      stub_request(:post, registration_endpoint)
        .to_return(status: 201, body: registration_response.to_json, headers: { 'Content-Type' => 'application/json' })
    end

    it 'returns the parsed registration response' do
      expect(udap.register_client(client_metadata, client_uri:)).to eq(registration_response)
    end

    it 'scopes discovery by community' do
      community = 'https://community.example.com/udap'

      stub_registration_discovery_for_community(community)
      udap.register_client(client_metadata, client_uri:, community:)

      expect(WebMock).to have_requested(:get, well_known_url).with(query: { 'community' => community })
    end

    it 'passes the server trust policy to signed metadata validation' do
      anchor = instance_double(OpenSSL::X509::Certificate, to_der: 'anchor')
      crl = instance_double(OpenSSL::X509::CRL, to_der: 'crl')
      checker = ->(**_kwargs) { true }

      udap.register_client(
        client_metadata,
        client_uri:,
        trusted_anchors: [anchor],
        crls: [crl],
        revocation_checker: checker,
        verify_chain: false
      )

      expect(registration_validator).to have_received(:signed_endpoint_claims).with(
        base_url: base_url,
        trusted_anchors: [anchor],
        crls: [crl],
        revocation_checker: checker,
        verify_chain: false,
        allow_insecure_localhost: false
      )
    end

    it 'builds validated registration metadata with the configured localhost policy' do
      udap.register_client(client_metadata, client_uri:)

      expect(Safire::Protocols::UdapRegistrationMetadata).to have_received(:new).with(
        client_metadata,
        operation: :register,
        allow_insecure_localhost: false
      )
    end

    context 'when insecure localhost is enabled in config' do
      let(:allow_insecure_localhost) { true }

      it 'passes the development policy to the registration metadata builder' do
        udap.register_client(client_metadata, client_uri:)

        expect(Safire::Protocols::UdapRegistrationMetadata).to have_received(:new).with(
          client_metadata,
          operation: :register,
          allow_insecure_localhost: true
        )
      end
    end

    it 'builds a software statement from configured signing defaults and discovered algorithms' do
      udap.register_client(client_metadata, client_uri:)

      expect(Safire::Protocols::UdapSoftwareStatement).to have_received(:new).with(
        metadata: registration_metadata,
        client_uri:,
        registration_endpoint:,
        private_key: configured_private_key,
        certificate_chain: configured_certificate_chain,
        supported_algorithms: %w[RS256 RS384],
        algorithm: nil,
        allow_insecure_localhost: false
      )
    end

    it 'allows per-call signing credential overrides' do
      udap.register_client(
        client_metadata,
        client_uri:,
        private_key: 'override-key',
        certificate_chain: ['override-cert'],
        jwt_algorithm: 'RS384'
      )

      expect(Safire::Protocols::UdapSoftwareStatement).to have_received(:new).with(
        hash_including(
          private_key: 'override-key',
          certificate_chain: ['override-cert'],
          algorithm: 'RS384'
        )
      )
    end

    it 'POSTs the UDAP registration envelope as JSON without certifications when omitted' do
      udap.register_client(client_metadata, client_uri:)

      expect(WebMock).to(have_requested(:post, registration_endpoint).with do |request|
        body = JSON.parse(request.body)
        request.headers['Content-Type'].start_with?('application/json') &&
          body == {
            'software_statement' => 'header.payload.sig',
            'udap' => '1'
          }
      end)
    end

    it 'preserves an explicit empty certifications array in the request envelope' do
      udap.register_client(client_metadata, client_uri:, certifications: [])

      expect(WebMock).to(have_requested(:post, registration_endpoint).with do |request|
        JSON.parse(request.body)['certifications'] == []
      end)
    end

    it 'includes caller-supplied certification JWTs without decoding or verifying them' do
      certifications = ['eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjZXJ0In0.c2ln']

      udap.register_client(client_metadata, client_uri:, certifications:)

      expect(WebMock).to(have_requested(:post, registration_endpoint).with do |request|
        JSON.parse(request.body)['certifications'] == certifications
      end)
    end

    it 'raises DiscoveryError when discovered metadata is structurally non-conformant' do
      stub_udap(
        body: registration_discovery_body.merge(
          'registration_endpoint_jwt_signing_alg_values_supported' => []
        )
      )

      expect { udap.register_client(client_metadata, client_uri:) }
        .to raise_error(Safire::Errors::DiscoveryError, /structurally conformant/)
      expect(WebMock).not_to have_requested(:post, registration_endpoint)
    end

    it 'raises DiscoveryError when the server does not advertise UDAP DCR capability' do
      stub_udap(
        body: registration_discovery_body.merge(
          'udap_profiles_supported' => %w[udap_authn udap_authz]
        )
      )

      expect { udap.register_client(client_metadata, client_uri:) }
        .to raise_error(Safire::Errors::DiscoveryError, /Dynamic Client Registration/)
      expect(WebMock).not_to have_requested(:post, registration_endpoint)
    end

    it 'raises DiscoveryError when the server omits mandatory RS256 registration signing support' do
      stub_udap(
        body: registration_discovery_body.merge(
          'registration_endpoint_jwt_signing_alg_values_supported' => ['ES384']
        )
      )

      expect { udap.register_client(client_metadata, client_uri:) }
        .to raise_error(Safire::Errors::DiscoveryError, /RS256/)
      expect(Safire::Protocols::UdapSoftwareStatement).not_to have_received(:new)
      expect(WebMock).not_to have_requested(:post, registration_endpoint)
    end

    context 'when the community requires certifications' do
      let(:registration_discovery_body) do
        super().merge(
          'udap_certifications_supported' => ['https://policy.example/cert'],
          'udap_certifications_required' => ['https://policy.example/cert']
        )
      end

      it 'raises ValidationError when certifications are omitted' do
        expect { udap.register_client(client_metadata, client_uri:) }
          .to raise_error(Safire::Errors::ValidationError, /certifications/)
        expect(Safire::Protocols::UdapSoftwareStatement).not_to have_received(:new)
      end

      it 'raises ValidationError when certifications are explicitly empty' do
        expect { udap.register_client(client_metadata, client_uri:, certifications: []) }
          .to raise_error(Safire::Errors::ValidationError, /certifications/)
        expect(Safire::Protocols::UdapSoftwareStatement).not_to have_received(:new)
      end

      it 'accepts a compact-JWS certification value' do
        udap.register_client(
          client_metadata,
          client_uri:,
          certifications: ['eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjZXJ0In0.c2ln']
        )

        expect(Safire::Protocols::UdapSoftwareStatement).to have_received(:new)
      end
    end

    it 'raises ValidationError for malformed certification collections' do
      expect { udap.register_client(client_metadata, client_uri:, certifications: ['not-a-jwt']) }
        .to raise_error(Safire::Errors::ValidationError, /compact JWS/)
      expect(Safire::Protocols::UdapSoftwareStatement).not_to have_received(:new)
    end

    context 'when the server returns an update-style 200 response' do
      before do
        stub_request(:post, registration_endpoint)
          .to_return(
            status: 200,
            body: registration_response.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
      end

      it 'accepts the response when client_id is present' do
        expect(udap.register_client(client_metadata, client_uri:)).to eq(registration_response)
      end
    end

    context 'when the server returns an unsupported 2xx response' do
      before do
        stub_request(:post, registration_endpoint)
          .to_return(
            status: 202,
            body: registration_response.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )
      end

      it 'raises RegistrationError before parsing the body as a successful registration' do
        expect { udap.register_client(client_metadata, client_uri:) }
          .to raise_error(Safire::Errors::RegistrationError, /unexpected registration response status/)
      end
    end

    context 'when the server returns a UDAP registration error' do
      before do
        stub_request(:post, registration_endpoint).to_return(
          status: 400,
          body: {
            'error' => 'invalid_software_statement',
            'error_description' => 'signature failed'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises RegistrationError with the UDAP error code' do
        error = capture_error(Safire::Errors::RegistrationError) do
          udap.register_client(client_metadata, client_uri:)
        end

        expect(error.error_code).to eq('invalid_software_statement')
        expect(error.error_description).to eq('signature failed')
      end
    end

    context 'when the server returns unapproved_software_statement' do
      before do
        stub_request(:post, registration_endpoint).to_return(
          status: 401,
          body: { 'error' => 'unapproved_software_statement' }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'preserves the UDAP error code' do
        error = capture_error(Safire::Errors::RegistrationError) do
          udap.register_client(client_metadata, client_uri:)
        end

        expect(error.error_code).to eq('unapproved_software_statement')
      end
    end

    context 'when the success response is malformed' do
      before do
        stub_request(:post, registration_endpoint)
          .to_return(status: 201, body: { 'client_name' => 'Example' }.to_json,
                     headers: { 'Content-Type' => 'application/json' })
      end

      it 'raises RegistrationError before returning the response' do
        expect { udap.register_client(client_metadata, client_uri:) }
          .to raise_error(Safire::Errors::RegistrationError, /missing client_id/)
      end
    end

    context 'when a network error occurs during registration' do
      before { stub_request(:post, registration_endpoint).to_raise(Faraday::ConnectionFailed) }

      it 'raises NetworkError' do
        expect { udap.register_client(client_metadata, client_uri:) }
          .to raise_error(Safire::Errors::NetworkError)
      end
    end

    it 'does not accept a client_type keyword' do
      expect { described_class.new(config, client_type: nil) }.to raise_error(ArgumentError)
    end
  end

  describe '#cancel_registration' do
    let(:registration_endpoint) { 'https://fhir.example.com/signed-register' }
    let(:client_uri) { 'https://client.example.com/app' }
    let(:client_metadata) do
      {
        client_name: 'Example Backend Service',
        contacts: ['mailto:security@example.com'],
        scope: 'system/Patient.rs'
      }
    end
    let(:cancellation_response) do
      {
        'client_id' => 'udap-client-123',
        'grant_types' => []
      }
    end
    let(:registration_discovery_body) do
      valid_metadata.merge(
        'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
        'registration_endpoint' => 'https://fhir.example.com/unsigned-register',
        'registration_endpoint_jwt_signing_alg_values_supported' => %w[RS256 RS384]
      )
    end
    let(:registration_signed_claims) do
      {
        'token_endpoint' => valid_metadata['token_endpoint'],
        'registration_endpoint' => registration_endpoint
      }
    end
    let(:registration_validator) do
      instance_double(
        Safire::Protocols::UdapSignedMetadataValidator,
        signed_endpoint_claims: registration_signed_claims
      )
    end
    let(:registration_metadata) { instance_double(Safire::Protocols::UdapRegistrationMetadata) }
    let(:software_statement) { instance_double(Safire::Protocols::UdapSoftwareStatement, to_jwt: 'header.payload.sig') }

    before do
      stub_udap(body: registration_discovery_body)
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(registration_validator)
      allow(Safire::Protocols::UdapRegistrationMetadata).to receive(:new).and_return(registration_metadata)
      allow(Safire::Protocols::UdapSoftwareStatement).to receive(:new).and_return(software_statement)
      stub_request(:post, registration_endpoint)
        .to_return(status: 202, body: cancellation_response.to_json, headers: { 'Content-Type' => 'application/json' })
    end

    it 'returns a body-confirmed cancellation response without requiring status 200' do
      expect(udap.cancel_registration(client_metadata, client_uri:)).to eq(cancellation_response)
    end

    it 'builds cancellation metadata with an empty grant set' do
      udap.cancel_registration(client_metadata, client_uri:)

      expect(Safire::Protocols::UdapRegistrationMetadata).to have_received(:new).with(
        client_metadata,
        operation: :cancel,
        allow_insecure_localhost: false
      )
    end

    it 'uses the same discovered registration endpoint and UDAP request envelope' do
      udap.cancel_registration(client_metadata, client_uri:)

      expect(WebMock).to(have_requested(:post, registration_endpoint).with do |request|
        body = JSON.parse(request.body)
        request.headers['Content-Type'].start_with?('application/json') &&
          body == {
            'software_statement' => 'header.payload.sig',
            'udap' => '1'
          }
      end)
    end

    it 'scopes cancellation discovery by community' do
      community = 'https://community.example.com/udap'
      stub_request(:get, well_known_url)
        .with(query: { 'community' => community })
        .to_return(
          status: 200,
          body: registration_discovery_body.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      udap.cancel_registration(
        client_metadata,
        client_uri:,
        community:
      )

      expect(WebMock).to have_requested(:get, well_known_url).with(query: { 'community' => community })
    end

    it 'passes trust policy through discovery' do
      anchor = instance_double(OpenSSL::X509::Certificate, to_der: 'anchor')
      crl = instance_double(OpenSSL::X509::CRL, to_der: 'crl')
      checker = ->(**_kwargs) { true }

      udap.cancel_registration(
        client_metadata,
        client_uri:,
        trusted_anchors: [anchor],
        crls: [crl],
        revocation_checker: checker,
        verify_chain: false
      )

      expect(registration_validator).to have_received(:signed_endpoint_claims).with(
        base_url: base_url,
        trusted_anchors: [anchor],
        crls: [crl],
        revocation_checker: checker,
        verify_chain: false,
        allow_insecure_localhost: false
      )
    end

    it 'preserves cancellation certifications in the UDAP request envelope' do
      certifications = ['eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjZXJ0In0.c2ln']

      udap.cancel_registration(client_metadata, client_uri:, certifications:)

      expect(WebMock).to(have_requested(:post, registration_endpoint).with do |request|
        JSON.parse(request.body)['certifications'] == certifications
      end)
    end

    [
      ['missing grant_types', { 'client_id' => 'udap-client-123' }],
      ['non-array grant_types', { 'client_id' => 'udap-client-123', 'grant_types' => 'client_credentials' }],
      ['non-empty grant_types', { 'client_id' => 'udap-client-123', 'grant_types' => ['client_credentials'] }]
    ].each do |description, response_body|
      context "when the cancellation response has #{description}" do
        before do
          stub_request(:post, registration_endpoint)
            .to_return(
              status: 200,
              body: response_body.to_json,
              headers: { 'Content-Type' => 'application/json' }
            )
        end

        it 'raises RegistrationError' do
          expect { udap.cancel_registration(client_metadata, client_uri:) }
            .to raise_error(Safire::Errors::RegistrationError, /empty grant_types/)
        end
      end
    end

    context 'when the cancellation response is missing client_id' do
      before do
        stub_request(:post, registration_endpoint)
          .to_return(status: 200, body: { 'grant_types' => [] }.to_json,
                     headers: { 'Content-Type' => 'application/json' })
      end

      it 'raises RegistrationError through the RFC 7591 response parser' do
        expect { udap.cancel_registration(client_metadata, client_uri:) }
          .to raise_error(Safire::Errors::RegistrationError, /missing client_id/)
      end
    end

    context 'when the server rejects the cancellation request' do
      before do
        stub_request(:post, registration_endpoint).to_return(
          status: 400,
          body: {
            'error' => 'invalid_software_statement',
            'error_description' => 'signature failed'
          }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
      end

      it 'raises RegistrationError with the server error code' do
        error = capture_error(Safire::Errors::RegistrationError) do
          udap.cancel_registration(client_metadata, client_uri:)
        end

        expect(error.status).to eq(400)
        expect(error.error_code).to eq('invalid_software_statement')
        expect(error.error_description).to eq('signature failed')
      end
    end
  end
end
