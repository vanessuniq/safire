require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

RSpec.describe Safire::Protocols::Udap, '#request_access_token' do
  include UdapCertificateHelpers

  subject(:udap) { described_class.new(config) }

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:signed_token_endpoint) { 'https://auth.example.com/signed/token' }
  let(:unsigned_token_endpoint) { 'https://auth.example.com/unsigned/token' }
  let(:client_id) { 'udap-client-123' }
  let(:redirect_uri) { 'https://app.example.com/callback' }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: 'https://client.example.com/app') }
  let(:config) do
    instance_double(
      Safire::ClientConfig,
      base_url:,
      client_id:,
      redirect_uri:,
      scopes: %w[openid patient/*.rs],
      allow_insecure_localhost: false,
      private_key:,
      certificate_chain: [certificate],
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
      'scopes_supported' => %w[openid patient/*.rs],
      'authorization_endpoint' => 'https://auth.example.com/authorize',
      'token_endpoint' => unsigned_token_endpoint,
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://auth.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }.merge(metadata_overrides)
  end
  let(:signed_claims) do
    {
      'token_endpoint' => signed_token_endpoint,
      'registration_endpoint' => 'https://auth.example.com/register',
      'authorization_endpoint' => 'https://auth.example.com/authorize'
    }
  end
  let(:code) { 'auth-code-xyz' }
  let(:code_verifier) { Safire::PKCE.generate_code_verifier }
  let(:token_response) do
    { 'access_token' => 'token-abc', 'token_type' => 'Bearer', 'expires_in' => 3600,
      'refresh_token' => 'refresh-abc', 'scope' => 'openid patient/*.rs' }
  end
  let(:token_requests) { [] }
  let(:warnings) { [] }

  def stub_discovery
    stub_request(:get, well_known_url)
      .to_return(status: 200, body: udap_metadata.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token(status: 200, body: token_response)
    stub_request(:post, signed_token_endpoint)
      .with { |request| token_requests << request }
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def form_params(request = token_requests.last)
    URI.decode_www_form(request.body).to_h
  end

  def decoded_assertion(request = token_requests.last)
    JWT.decode(form_params(request)['client_assertion'], certificate.public_key, true, algorithms: ['RS256'])
  end

  def exchange(**)
    udap.request_access_token(code:, code_verifier:, **)
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

    it 'returns the parsed token response unchanged' do
      expect(exchange).to eq(token_response)
    end

    it 'posts exactly the STU2 authorization_code form parameters' do
      exchange

      expect(form_params.keys).to contain_exactly(
        'grant_type', 'code', 'redirect_uri', 'code_verifier', 'client_assertion_type', 'client_assertion', 'udap'
      )
      expect(form_params).to include(
        'grant_type' => 'authorization_code',
        'code' => code,
        'redirect_uri' => redirect_uri,
        'code_verifier' => code_verifier,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'udap' => '1'
      )
    end

    it 'sends a form-encoded body without an Authorization header, client_id, client_secret, or scope' do
      exchange

      request = token_requests.last
      expect(request.headers['Content-Type']).to start_with('application/x-www-form-urlencoded')
      expect(request.headers.keys.map(&:downcase)).not_to include('authorization')
      expect(form_params).not_to include('client_id', 'client_secret', 'scope')
    end

    it 'signs an Authentication Token with STU2 claims and no extensions claim' do
      exchange

      payload, header = decoded_assertion
      expect(payload.keys).to contain_exactly('iss', 'sub', 'aud', 'iat', 'exp', 'jti')
      expect(payload).to include('iss' => client_id, 'sub' => client_id, 'aud' => signed_token_endpoint)
      expect(payload['exp'] - payload['iat']).to eq(300)
      expect(header.keys).to contain_exactly('alg', 'x5c')
      expect(header['x5c']).to eq([Base64.strict_encode64(certificate.to_der)])
    end

    it 'uses the signed token endpoint as aud and POST target, not the unsigned value' do
      exchange

      expect(WebMock).to have_requested(:post, signed_token_endpoint).once
      expect(WebMock).not_to have_requested(:post, unsigned_token_endpoint)
    end

    it 'uses a fresh jti for each request' do
      2.times { exchange }

      expect(decoded_assertion(token_requests[0]).first['jti'])
        .not_to eq(decoded_assertion(token_requests[1]).first['jti'])
    end

    it 'logs an info line without request values' do
      allow(Safire.logger).to receive(:info)

      exchange

      expect(Safire.logger).to have_received(:info).with('Requesting UDAP access token (authorization_code grant)...')
      expect(Safire.logger).not_to have_received(:info).with(a_string_including(code))
    end

    it 'emits no warnings for conformant metadata' do
      exchange

      expect(warnings).to be_empty
    end

    it 'sends caller-supplied non-B2B extensions in the Authentication Token' do
      exchange(extensions: { 'acme-ext' => { 'tenant' => 'a' } })

      expect(decoded_assertion.first['extensions']).to eq('acme-ext' => { 'tenant' => 'a' })
    end

    it 'accepts code_verifier boundary lengths 43 and 128' do
      ['a' * 43, 'b' * 128].each { |verifier| udap.request_access_token(code:, code_verifier: verifier) }

      expect(token_requests.map { |r| form_params(r)['code_verifier'].length }).to eq([43, 128])
    end

    it 'omits the extensions claim for an empty extensions Hash' do
      exchange(extensions: {})

      expect(decoded_assertion.first).not_to have_key('extensions')
    end
  end

  describe 'redirect_uri identity with authorization_url' do
    it 'sends the same redirect_uri that authorization_url put in the authorization request' do
      stub_discovery
      stub_token

      auth = udap.authorization_url
      sent_redirect_uri = Addressable::URI.parse(auth[:auth_url]).query_values['redirect_uri']
      udap.request_access_token(code:, code_verifier: auth[:code_verifier])

      expect(form_params['redirect_uri']).to eq(sent_redirect_uri)
      expect(Base64.urlsafe_encode64(Digest::SHA256.digest(form_params['code_verifier']), padding: false))
        .to eq(Addressable::URI.parse(auth[:auth_url]).query_values['code_challenge'])
    end
  end

  describe 'input validation before network activity' do
    it 'validates code, code_verifier, and extensions before discovery' do
      [
        -> { udap.request_access_token(code: '', code_verifier:) },
        -> { udap.request_access_token(code:, code_verifier: 'short') },
        -> { exchange(extensions: { 'hl7-b2b' => { 'a' => 1 } }) }
      ].each { |call| expect(&call).to raise_error(Safire::Errors::ValidationError) }

      expect(WebMock).not_to have_requested(:get, well_known_url)
    end

    [nil, '', '  ', 42].each do |value|
      it "rejects code #{value.inspect} without echoing it" do
        expect { udap.request_access_token(code: value, code_verifier:) }
          .to raise_error(Safire::Errors::ValidationError) { |error|
            expect(error.attribute).to eq(:code)
            expect(error.reason).to eq('must be a non-blank String')
          }
      end
    end

    {
      'nil' => nil,
      'too short' => 'a' * 42,
      'too long' => 'a' * 129,
      'invalid characters' => "#{'a' * 42}+"
    }.each do |label, value|
      it "rejects a #{label} code_verifier" do
        expect { udap.request_access_token(code:, code_verifier: value) }
          .to raise_error(Safire::Errors::ValidationError) { |error|
            expect(error.attribute).to eq(:code_verifier)
            expect(error.message).not_to include('aaaaaaaaaa')
          }
      end
    end

    it 'rejects an hl7-b2b extension for the authorization_code grant' do
      expect { exchange(extensions: { 'hl7-b2b' => { 'version' => '1' } }) }
        .to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.attribute).to eq(:extensions)
          expect(error.reason).to include('authorization_code grant')
        }
    end

    it 'rejects a symbol hl7-b2b key and malformed extensions' do
      expect { exchange(extensions: { 'hl7-b2b': { a: 1 } }) }.to raise_error(Safire::Errors::ValidationError)
      expect { exchange(extensions: []) }.to raise_error(Safire::Errors::ValidationError, /Hash or nil/)
      expect { exchange(extensions: { 'x' => {} }) }.to raise_error(Safire::Errors::ValidationError, /non-empty/)
    end

    context 'without client_id, redirect_uri, or signing identity' do
      let(:client_id) { nil }
      let(:redirect_uri) { nil }
      let(:config) do
        instance_double(
          Safire::ClientConfig,
          base_url:, client_id:, redirect_uri:, scopes: nil, allow_insecure_localhost: false,
          private_key: nil, certificate_chain: nil, jwt_algorithm: nil
        )
      end

      it 'raises ConfigurationError naming every missing attribute' do
        expect { exchange }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq(%i[client_id redirect_uri private_key certificate_chain])
        }
      end
    end
  end

  describe 'readiness' do
    context 'when authorization_code is not advertised' do
      let(:metadata_overrides) { { 'grant_types_supported' => ['client_credentials'] } }

      it 'raises DiscoveryError before signing or posting' do
        stub_discovery

        expect { exchange }.to raise_error(Safire::Errors::DiscoveryError, /authorization_code grant/)
        expect(WebMock).not_to have_requested(:post, signed_token_endpoint)
      end
    end

    context 'when udap_authn is not advertised' do
      let(:metadata_overrides) { { 'udap_profiles_supported' => ['udap_dcr'] } }

      it 'raises DiscoveryError' do
        stub_discovery

        expect { exchange }.to raise_error(Safire::Errors::DiscoveryError, /udap_authn/)
      end
    end

    context 'when the server lists required extensions (D-20)' do
      let(:metadata_overrides) do
        {
          'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
          'udap_authorization_extensions_supported' => ['hl7-b2b'],
          'udap_authorization_extensions_required' => ['hl7-b2b']
        }
      end

      it 'warns without key names and still sends no extensions claim' do
        stub_discovery
        stub_token

        exchange

        expect(decoded_assertion.first).not_to have_key('extensions')
        expect(warnings).to contain_exactly(
          a_string_starting_with('[UDAP] udap_authorization_extensions_required lists extension count=1')
        )
      end
    end

    it 'does not run scope negotiation (the code exchange carries no scope)' do
      udap_metadata['scopes_supported'] = []
      stub_discovery
      stub_token

      expect { exchange }.not_to raise_error
      expect(warnings).to be_empty
    end
  end

  describe 'error responses' do
    before { stub_discovery }

    it 'maps an OAuth error to TokenError preserving the error code' do
      stub_token(status: 400, body: { 'error' => 'invalid_grant', 'error_description' => 'code expired' })

      expect { exchange }.to raise_error(Safire::Errors::TokenError) { |error|
        expect(error.status).to eq(400)
        expect(error.error_code).to eq('invalid_grant')
        expect(error.error_description).to eq('code expired')
      }
    end

    it 'maps invalid_client (401) to TokenError' do
      stub_token(status: 401, body: { 'error' => 'invalid_client' })

      expect { exchange }.to raise_error(Safire::Errors::TokenError) { |error|
        expect(error.error_code).to eq('invalid_client')
      }
    end

    it 'raises TokenError for a success body without access_token' do
      stub_token(body: { 'token_type' => 'Bearer' })

      expect { exchange }.to raise_error(Safire::Errors::TokenError, /Missing access token/)
    end

    it 'never retries' do
      stub_token(status: 500, body: { 'error' => 'server_error' })

      expect { exchange }.to raise_error(Safire::Errors::TokenError)
      expect(WebMock).to have_requested(:post, signed_token_endpoint).once
    end
  end
end
