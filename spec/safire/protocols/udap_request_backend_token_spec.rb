require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

RSpec.describe Safire::Protocols::Udap, '#request_backend_token' do
  include UdapCertificateHelpers

  subject(:udap) { described_class.new(config) }

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:signed_token_endpoint) { 'https://auth.example.com/signed/token' }
  let(:unsigned_token_endpoint) { 'https://auth.example.com/unsigned/token' }
  let(:client_id) { 'udap-client-123' }
  let(:configured_scopes) { nil }
  let(:allow_insecure_localhost) { false }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: 'https://client.example.com/app') }
  let(:config) do
    instance_double(
      Safire::ClientConfig,
      base_url:,
      client_id:,
      scopes: configured_scopes,
      allow_insecure_localhost:,
      private_key:,
      certificate_chain: [certificate],
      jwt_algorithm: nil
    )
  end
  let(:metadata_overrides) { {} }
  let(:udap_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => %w[system/*.rs],
      'token_endpoint' => unsigned_token_endpoint,
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://auth.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }.merge(metadata_overrides)
  end
  let(:signed_claims) do
    { 'token_endpoint' => signed_token_endpoint, 'registration_endpoint' => 'https://auth.example.com/register' }
  end
  let(:b2b) do
    {
      organization_id: 'https://fhir.example.com/Organization/123',
      organization_name: 'Example Clinic',
      purpose_of_use: ['urn:oid:2.16.840.1.113883.5.8#TREAT']
    }
  end
  let(:token_response) { { 'access_token' => 'token-abc', 'token_type' => 'Bearer', 'expires_in' => 300 } }
  let(:token_requests) { [] }
  let(:warnings) { [] }

  def stub_discovery(query: nil)
    request = stub_request(:get, well_known_url)
    request = request.with(query:) if query
    request.to_return(status: 200, body: udap_metadata.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token(status: 200, body: token_response, endpoint: signed_token_endpoint)
    stub_request(:post, endpoint)
      .with { |request| token_requests << request }
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def form_params(request = token_requests.last)
    URI.decode_www_form(request.body).to_h
  end

  def decoded_assertion(request = token_requests.last)
    JWT.decode(form_params(request)['client_assertion'], certificate.public_key, true, algorithms: ['RS256'])
  end

  def request_token(**)
    udap.request_backend_token(scopes: ['system/Patient.rs'], b2b:, **)
  end

  before do
    validator = instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: signed_claims)
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
    allow(Safire.logger).to receive(:warn) { |message| warnings << message }
  end

  describe 'successful request' do
    before do
      stub_discovery
      stub_token
    end

    it 'returns the parsed token response' do
      expect(request_token).to eq(token_response)
    end

    it 'posts exactly the STU2 client_credentials form parameters' do
      request_token

      expect(form_params.keys).to contain_exactly(
        'grant_type', 'scope', 'client_assertion_type', 'client_assertion', 'udap'
      )
      expect(form_params).to include(
        'grant_type' => 'client_credentials',
        'scope' => 'system/Patient.rs',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'udap' => '1'
      )
    end

    it 'sends a form-encoded body without an Authorization header' do
      request_token

      request = token_requests.last
      expect(request.headers['Content-Type']).to start_with('application/x-www-form-urlencoded')
      expect(request.headers.keys.map(&:downcase)).not_to include('authorization')
      expect(form_params).not_to include('client_id', 'client_secret')
    end

    it 'signs an Authentication Token with STU2 claims and the hl7-b2b extension' do
      request_token

      payload, header = decoded_assertion
      expect(payload).to include('iss' => client_id, 'sub' => client_id, 'aud' => signed_token_endpoint)
      expect(payload['exp'] - payload['iat']).to eq(300)
      expect(payload['jti']).to be_a(String).and(be_present)
      expect(payload['extensions']).to eq(
        'hl7-b2b' => {
          'version' => '1',
          'organization_name' => 'Example Clinic',
          'organization_id' => 'https://fhir.example.com/Organization/123',
          'purpose_of_use' => ['urn:oid:2.16.840.1.113883.5.8#TREAT']
        }
      )
      expect(header.keys).to contain_exactly('alg', 'x5c')
      expect(header['alg']).to eq('RS256')
      expect(header['x5c']).to eq([Base64.strict_encode64(certificate.to_der)])
    end

    it 'uses the signed token endpoint as aud and POST target, not the unsigned value' do
      request_token

      expect(WebMock).to have_requested(:post, signed_token_endpoint).once
      expect(WebMock).not_to have_requested(:post, unsigned_token_endpoint)
      expect(decoded_assertion.first['aud']).to eq(signed_token_endpoint)
    end

    it 'uses a fresh jti for each request' do
      2.times { request_token }

      expect(decoded_assertion(token_requests[0]).first['jti'])
        .not_to eq(decoded_assertion(token_requests[1]).first['jti'])
    end

    it 'merges additional extensions after hl7-b2b' do
      request_token(extensions: { 'acme-ext' => { 'tenant' => 'a' }, other: { flag: true } })

      expect(decoded_assertion.first['extensions'].keys).to eq(%w[hl7-b2b acme-ext other])
      expect(decoded_assertion.first['extensions']['other']).to eq('flag' => true)
    end

    it 'normalizes space-delimited, duplicate, and blank scopes' do
      udap.request_backend_token(scopes: ['  system/Patient.rs system/Observation.rs ', '', 'system/Patient.rs'], b2b:)

      expect(form_params['scope']).to eq('system/Patient.rs system/Observation.rs')
    end

    it 'accepts a space-delimited scope String' do
      udap.request_backend_token(scopes: 'system/Patient.rs  system/*.rs', b2b:)

      expect(form_params['scope']).to eq('system/Patient.rs system/*.rs')
    end

    it 'logs an info line without request values' do
      allow(Safire.logger).to receive(:info)

      request_token

      expect(Safire.logger).to have_received(:info)
        .with('Requesting UDAP B2B access token (client_credentials grant)...')
    end

    it 'emits no warnings for conformant metadata' do
      request_token

      expect(warnings).to be_empty
    end

    context 'with configured scopes' do
      let(:configured_scopes) { ['system/Observation.rs'] }

      it 'falls back to configured scopes when none are passed' do
        udap.request_backend_token(b2b:)

        expect(form_params['scope']).to eq('system/Observation.rs')
      end

      it 'prefers per-call scopes' do
        request_token

        expect(form_params['scope']).to eq('system/Patient.rs')
      end

      it 'falls back when per-call scopes are blank' do
        udap.request_backend_token(scopes: [' '], b2b:)

        expect(form_params['scope']).to eq('system/Observation.rs')
      end
    end
  end

  describe 'community discovery' do
    let(:community) { 'https://community.example.org/udap' }

    it 'scopes discovery by community and reports it in readiness errors' do
      metadata_overrides['grant_types_supported'] = ['authorization_code']
      stub_discovery(query: { 'community' => community })
      stub_token

      expect { request_token(community:) }.to raise_error(Safire::Errors::DiscoveryError) { |error|
        expect(error.endpoint).to eq("#{well_known_url}?community=#{CGI.escape(community)}")
      }
      expect(token_requests).to be_empty
    end

    it 'requests the token after community discovery' do
      stub_discovery(query: { 'community' => community })
      stub_token

      request_token(community:)

      expect(WebMock).to have_requested(:get, well_known_url).with(query: { 'community' => community })
      expect(token_requests.length).to eq(1)
    end
  end

  # No HTTP stubs are registered here, so any request would raise
  # WebMock::NetConnectNotAllowedError instead of the expected Safire error.
  describe 'input validation before any HTTP request' do
    context 'without client_id' do
      let(:client_id) { nil }

      it 'raises ConfigurationError' do
        expect { request_token }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq([:client_id])
        }
      end
    end

    it 'raises ConfigurationError for missing signing credentials' do
      expect { request_token(private_key: nil, certificate_chain: []) }
        .to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq(%i[private_key certificate_chain])
        }
    end

    [nil, [], '', ['  ', nil]].each do |scopes|
      it "raises ConfigurationError for scopes #{scopes.inspect} without configured scopes" do
        expect { udap.request_backend_token(scopes:, b2b:) }
          .to raise_error(Safire::Errors::ConfigurationError) { |error|
            expect(error.missing_attributes).to eq([:scopes])
          }
      end
    end

    it 'raises ConfigurationError for non-String scope entries' do
      expect { udap.request_backend_token(scopes: [:'system/Patient.rs'], b2b:) }
        .to raise_error(Safire::Errors::ConfigurationError, /scopes/)
    end

    it 'raises ValidationError for scope tokens with invalid characters, without the value' do
      expect { udap.request_backend_token(scopes: ['system/Patient.rs?name="x"'], b2b:) }
        .to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.attribute).to eq(:scope)
          expect(error.message).not_to include('Patient')
        }
    end

    it 'raises ValidationError when b2b is missing' do
      expect { udap.request_backend_token(scopes: ['system/Patient.rs']) }
        .to raise_error(Safire::Errors::ValidationError, /client_credentials/) { |error|
          expect(error.attribute).to eq(:b2b)
        }
    end

    it 'raises ValidationError for an invalid b2b object' do
      expect { request_token(b2b: { organization_id: 'https://example.org/1' }) }
        .to raise_error(Safire::Errors::ValidationError) { |error| expect(error.attribute).to eq(:purpose_of_use) }
    end

    [{ 'hl7-b2b' => { 'version' => '1' } }, { 'hl7-b2b': { a: 1 } }].each do |extensions|
      it "rejects hl7-b2b inside extensions: #{extensions.keys.inspect}" do
        expect { request_token(extensions:) }
          .to raise_error(Safire::Errors::ValidationError, /use|b2b:/) { |error|
            expect(error.attribute).to eq(:extensions)
          }
      end
    end

    [
      ['not a Hash', 'x', /must be a Hash/],
      ['an empty extension object', { 'acme' => {} }, /non-empty Hash/],
      ['a non-Hash extension value', { 'acme' => 'x' }, /non-empty Hash/],
      ['a blank key', { '' => { 'a' => 1 } }, /non-blank/],
      ['a non-String key', { 1 => { 'a' => 1 } }, /non-blank Strings or Symbols/],
      ['a key in both String and Symbol form', { 'acme' => { 'a' => 1 }, acme: { 'a' => 2 } }, /more than once/]
    ].each do |description, extensions, message|
      it "rejects extensions with #{description}" do
        expect { request_token(extensions:) }.to raise_error(Safire::Errors::ValidationError, message)
      end
    end

    it 'rejects an invalid community' do
      expect { request_token(community: 'not a uri') }.to raise_error(Safire::Errors::ConfigurationError, /community/)
    end
  end

  describe 'readiness failures' do
    before { stub_token }

    def expect_rejected_before_post(*error_args)
      expect { request_token }.to raise_error(*error_args)
      expect(token_requests).to be_empty
    end

    {
      'udap_authn not advertised' => [{ 'udap_profiles_supported' => %w[udap_dcr udap_authz] }, /udap_authn/],
      'client_credentials not advertised' => [{ 'grant_types_supported' => [] }, /client_credentials grant/],
      'private_key_jwt not advertised' => [{ 'token_endpoint_auth_methods_supported' => [] }, /private_key_jwt/],
      'unusable signing algorithms' => [
        { 'token_endpoint_auth_signing_alg_values_supported' => [] }, /signing algorithm metadata/
      ],
      'malformed required extensions' => [
        { 'udap_authorization_extensions_required' => 'hl7-b2b' }, /udap_authorization_extensions_required/
      ]
    }.each do |description, (overrides, message)|
      it "raises DiscoveryError when #{description}" do
        metadata_overrides.merge!(overrides)
        stub_discovery

        expect_rejected_before_post(Safire::Errors::DiscoveryError, message)
      end
    end

    {
      'has a fragment' => ['https://auth.example.com/token#frag', /fragment/],
      'uses HTTP' => ['http://auth.example.com/token', /HTTPS/]
    }.each do |description, (endpoint, message)|
      it "raises DiscoveryError when the signed token endpoint #{description}" do
        signed_claims['token_endpoint'] = endpoint
        stub_discovery

        expect_rejected_before_post(Safire::Errors::DiscoveryError, message)
      end
    end

    it 'raises DiscoveryError when signed metadata does not validate' do
      validator = instance_double(Safire::Protocols::UdapSignedMetadataValidator, signed_endpoint_claims: nil)
      allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
      stub_discovery

      expect_rejected_before_post(Safire::Errors::DiscoveryError, /signed_metadata validation failed/)
    end

    it 'raises ValidationError for a missing required extension' do
      metadata_overrides['udap_authorization_extensions_supported'] = %w[hl7-b2b tefca-ias]
      metadata_overrides['udap_authorization_extensions_required'] = %w[hl7-b2b tefca-ias]
      stub_discovery

      expect_rejected_before_post(Safire::Errors::ValidationError, /missing: tefca-ias/)
    end

    it 'raises ValidationError for an unadvertised wildcard scope before any token POST' do
      stub_discovery

      expect { udap.request_backend_token(scopes: ['patient/*.rs'], b2b:) }
        .to raise_error(Safire::Errors::ValidationError, /wildcard scope count=1/)
      expect(token_requests).to be_empty
    end

    it 'raises ConfigurationError when no advertised algorithm fits the signing key' do
      metadata_overrides['token_endpoint_auth_signing_alg_values_supported'] = ['ES256']
      stub_discovery

      expect_rejected_before_post(Safire::Errors::ConfigurationError)
    end
  end

  describe 'readiness warnings' do
    it 'sends hl7-b2b with a value-free warning when the server does not list it' do
      metadata_overrides['udap_authorization_extensions_supported'] = []
      metadata_overrides['udap_authorization_extensions_required'] = nil
      metadata_overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn]
      stub_discovery
      stub_token

      request_token

      expect(decoded_assertion.first['extensions']).to have_key('hl7-b2b')
      expect(warnings.length).to eq(2)
      expect(warnings.join).not_to include('system/Patient.rs', 'Organization/123', 'TREAT')
    end
  end

  describe 'token response handling' do
    before { stub_discovery }

    it 'raises TokenError preserving the OAuth error code' do
      stub_token(status: 400, body: { 'error' => 'invalid_scope', 'error_description' => 'nope' })

      expect { request_token }.to raise_error(Safire::Errors::TokenError) { |error|
        expect(error.status).to eq(400)
        expect(error.error_code).to eq('invalid_scope')
      }
      expect(token_requests.length).to eq(1)
    end

    it 'raises TokenError for invalid_client' do
      stub_token(status: 401, body: { 'error' => 'invalid_client' })

      expect { request_token }.to raise_error(Safire::Errors::TokenError) { |error|
        expect(error.error_code).to eq('invalid_client')
      }
    end

    it 'raises TokenError for a 200 response without access_token' do
      stub_token(body: { 'token_type' => 'Bearer' })

      expect { request_token }.to raise_error(Safire::Errors::TokenError, /token_type/)
    end

    it 'raises TokenError for a non-Hash body' do
      stub_token(body: ['access_token'])

      expect { request_token }.to raise_error(Safire::Errors::TokenError, /not a JSON object/)
    end

    it 'raises NetworkError on connection failure without retrying' do
      stub_request(:post, signed_token_endpoint).to_raise(Faraday::ConnectionFailed.new('refused'))

      expect { request_token }.to raise_error(Safire::Errors::NetworkError)
      expect(WebMock).to have_requested(:post, signed_token_endpoint).once
    end
  end

  context 'with allow_insecure_localhost and a loopback token endpoint' do
    let(:allow_insecure_localhost) { true }
    let(:signed_token_endpoint) { 'http://localhost:8080/token' }

    it 'posts to the loopback endpoint' do
      stub_discovery
      stub_token

      expect(request_token['access_token']).to eq('token-abc')
    end
  end
end
