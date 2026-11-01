require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

RSpec.describe Safire::Protocols::Udap, '#refresh_token' do
  include UdapCertificateHelpers

  subject(:udap) { described_class.new(config) }

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:token_endpoint) { 'https://auth.example.com/signed/token' }
  let(:client_id) { 'udap-client-123' }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate_chain) { [certificate] }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: 'https://client.example.com/app') }
  let(:config) do
    instance_double(
      Safire::ClientConfig,
      base_url:,
      client_id:,
      redirect_uri: 'https://app.example.com/callback',
      scopes: %w[openid patient/*.rs],
      allow_insecure_localhost: false,
      private_key:,
      certificate_chain:,
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
      'token_endpoint' => 'https://auth.example.com/unsigned/token',
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://auth.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }.merge(metadata_overrides)
  end
  let(:signed_claims) do
    { 'token_endpoint' => token_endpoint, 'registration_endpoint' => 'https://auth.example.com/register' }
  end
  let(:stored_refresh_token) { 'refresh-secret-123' }
  let(:token_response) { { 'access_token' => 'new-token', 'token_type' => 'Bearer', 'refresh_token' => 'rotated' } }
  let(:token_requests) { [] }
  let(:warnings) { [] }

  def stub_discovery
    stub_request(:get, well_known_url)
      .to_return(status: 200, body: udap_metadata.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token(status: 200, body: token_response)
    stub_request(:post, token_endpoint)
      .with { |request| token_requests << request }
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def form_params(request = token_requests.last)
    URI.decode_www_form(request.body).to_h
  end

  def decoded_assertion
    JWT.decode(form_params['client_assertion'], certificate.public_key, true, algorithms: ['RS256'])
  end

  def refresh(**)
    udap.refresh_token(refresh_token: stored_refresh_token, **)
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
      expect(refresh).to eq(token_response)
    end

    it 'posts exactly the RFC 6749 §6 refresh parameters plus UDAP client authentication' do
      refresh

      expect(form_params.keys).to contain_exactly(
        'grant_type', 'refresh_token', 'client_assertion_type', 'client_assertion', 'udap'
      )
      expect(form_params).to include(
        'grant_type' => 'refresh_token',
        'refresh_token' => stored_refresh_token,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'udap' => '1'
      )
    end

    it 'does not fall back to configured scopes' do
      refresh(scopes: [' '])

      expect(form_params).not_to have_key('scope')
    end

    it 'sends a reduced scope when requested' do
      refresh(scopes: 'openid  patient/Patient.rs openid')

      expect(form_params['scope']).to eq('openid patient/Patient.rs')
    end

    it 'sends no Authorization header, client_id, client_secret, or redirect_uri' do
      refresh

      expect(token_requests.last.headers.keys.map(&:downcase)).not_to include('authorization')
      expect(form_params).not_to include('client_id', 'client_secret', 'redirect_uri', 'code_verifier')
    end

    it 'authenticates with an Authentication Token built as for initial token requests' do
      refresh

      payload, header = decoded_assertion
      expect(payload.keys).to contain_exactly('iss', 'sub', 'aud', 'iat', 'exp', 'jti')
      expect(payload).to include('iss' => client_id, 'sub' => client_id, 'aud' => token_endpoint)
      expect(payload['exp'] - payload['iat']).to eq(300)
      expect(header.keys).to contain_exactly('alg', 'x5c')
    end

    it 'logs an info line without the refresh token' do
      allow(Safire.logger).to receive(:info)

      refresh

      expect(Safire.logger).to have_received(:info).with('Refreshing UDAP access token (refresh_token grant)...')
      expect(Safire.logger).not_to have_received(:info).with(a_string_including(stored_refresh_token))
      expect(warnings).to be_empty
    end
  end

  describe 'scope negotiation (token-request rule)' do
    before { stub_discovery }

    it 'raises ValidationError for an unadvertised wildcard before signing or posting' do
      expect { refresh(scopes: ['user/*.rs']) }.to raise_error(Safire::Errors::ValidationError) { |error|
        expect(error.attribute).to eq(:scope)
        expect(error.message).not_to include('user/')
      }
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'accepts an advertised wildcard' do
      stub_token

      refresh(scopes: ['patient/*.rs'])

      expect(form_params['scope']).to eq('patient/*.rs')
    end

    context 'when scopes_supported is unusable' do
      let(:metadata_overrides) { { 'scopes_supported' => nil } }

      it 'raises DiscoveryError for a requested wildcard' do
        expect { refresh(scopes: ['patient/*.rs']) }.to raise_error(Safire::Errors::DiscoveryError, /scopes_supported/)
      end

      it 'skips negotiation when no scope is sent' do
        stub_token

        expect { refresh }.not_to raise_error
      end
    end

    it 'rejects malformed scope characters before discovery' do
      expect { refresh(scopes: ['bad"scope']) }.to raise_error(Safire::Errors::ValidationError)
    end
  end

  describe 'readiness' do
    context 'when refresh_token is not in grant_types_supported' do
      let(:metadata_overrides) { { 'grant_types_supported' => ['authorization_code'] } }

      it 'warns without values and proceeds' do
        stub_discovery
        stub_token

        refresh

        expect(token_requests.size).to eq(1)
        expect(warnings).to contain_exactly(a_string_starting_with('[UDAP] grant_types_supported does not advertise'))
        expect(warnings.join).not_to include(stored_refresh_token)
      end
    end

    context 'when the server lists required extensions' do
      let(:metadata_overrides) do
        {
          'udap_authorization_extensions_supported' => ['hl7-b2b'],
          'udap_authorization_extensions_required' => ['hl7-b2b']
        }
      end

      it 'warns and sends no extensions claim' do
        stub_discovery
        stub_token

        refresh

        expect(decoded_assertion.first).not_to have_key('extensions')
        expect(warnings).to contain_exactly(a_string_including('extension count=1 not sent with the refresh_token'))
      end
    end

    context 'when udap_authn is not advertised' do
      let(:metadata_overrides) { { 'udap_profiles_supported' => ['udap_dcr'] } }

      it 'raises DiscoveryError' do
        stub_discovery

        expect { refresh }.to raise_error(Safire::Errors::DiscoveryError, /udap_authn/)
      end
    end
  end

  describe 'input validation' do
    [nil, '', ' ', 123].each do |value|
      it "rejects refresh_token #{value.inspect} before discovery" do
        expect { udap.refresh_token(refresh_token: value) }.to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.attribute).to eq(:refresh_token)
        }
        expect(WebMock).not_to have_requested(:get, well_known_url)
      end
    end

    it 'rejects an hl7-b2b extension for the refresh_token grant' do
      expect { refresh(extensions: { 'hl7-b2b' => { 'version' => '1' } }) }
        .to raise_error(Safire::Errors::ValidationError, /refresh_token grant/)
    end

    context 'without signing identity' do
      let(:private_key) { nil }
      let(:certificate_chain) { nil }

      it 'raises ConfigurationError without requiring redirect_uri' do
        expect { refresh }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq(%i[private_key certificate_chain])
        }
      end
    end
  end

  describe 'error responses' do
    before { stub_discovery }

    it 'maps invalid_grant to TokenError' do
      stub_token(status: 400, body: { 'error' => 'invalid_grant', 'error_description' => 'refresh token revoked' })

      expect { refresh }.to raise_error(Safire::Errors::TokenError) { |error|
        expect(error.error_code).to eq('invalid_grant')
        expect(error.message).not_to include(stored_refresh_token)
      }
    end

    it 'raises TokenError for a success body without access_token' do
      stub_token(body: { 'refresh_token' => 'x' })

      expect { refresh }.to raise_error(Safire::Errors::TokenError, /Missing access token/)
    end
  end
end
