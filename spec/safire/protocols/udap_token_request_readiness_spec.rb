require 'spec_helper'

RSpec.describe Safire::Protocols::UdapTokenRequestReadiness do
  let(:discovery_endpoint) { 'https://fhir.example.com/.well-known/udap?community=urn%3Aexample%3Acommunity' }
  let(:token_endpoint) { 'https://auth.example.com/token' }
  let(:allow_insecure_localhost) { false }
  let(:grant_type) { 'client_credentials' }
  let(:overrides) { {} }
  let(:metadata_hash) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_supported' => [],
      'grant_types_supported' => %w[authorization_code refresh_token client_credentials],
      'scopes_supported' => %w[openid system/*.rs],
      'token_endpoint' => token_endpoint,
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => %w[RS256 ES256],
      'registration_endpoint' => 'https://auth.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256']
    }.merge(overrides)
  end
  let(:metadata) do
    Safire::Protocols::UdapMetadata.new(metadata_hash, allow_insecure_localhost:)
  end
  let(:readiness) do
    described_class.new(metadata:, grant_type:, discovery_endpoint:, allow_insecure_localhost:)
  end
  let(:scopes) { %w[system/Patient.rs] }
  let(:extension_keys) { ['hl7-b2b'] }
  let(:messages) { [] }

  before do
    allow(Safire.logger).to receive(:warn) { |message| messages << message }
  end

  def evaluate
    readiness.evaluate!(scopes:, extension_keys:)
  end

  def expect_discovery_error(description)
    expect { evaluate }.to raise_error(Safire::Errors::DiscoveryError) { |error|
      expect(error.endpoint).to eq(discovery_endpoint)
      expect(error.label).to eq('UDAP metadata')
      expect(error.error_description).to match(description)
    }
  end

  describe '.new' do
    it 'rejects an unsupported grant type' do
      expect { described_class.new(metadata:, grant_type: 'password', discovery_endpoint:) }
        .to raise_error(ArgumentError, /unsupported UDAP token grant type/)
    end

    it 'rejects a non-boolean localhost policy' do
      expect do
        described_class.new(metadata:, grant_type:, discovery_endpoint:, allow_insecure_localhost: 'yes')
      end.to raise_error(Safire::Errors::ConfigurationError)
    end
  end

  describe '#evaluate!' do
    it 'returns the authoritative token endpoint unchanged and the signing algorithms' do
      result = evaluate

      expect(result.token_endpoint).to eq(token_endpoint)
      expect(result.signing_algorithms).to eq(%w[RS256 ES256])
      expect(result).to be_frozen
      expect(messages).to be_empty
    end

    it 'returns the token endpoint exactly, without normalization' do
      overrides['token_endpoint'] = 'https://Auth.Example.com:443/oauth/../token'

      expect(evaluate.token_endpoint).to eq('https://Auth.Example.com:443/oauth/../token')
    end

    describe 'argument validation' do
      it 'requires a non-empty scopes array for client_credentials' do
        [nil, [], 'system/Patient.rs'].each do |value|
          expect { readiness.evaluate!(scopes: value, extension_keys:) }
            .to raise_error(ArgumentError, /non-empty scopes array/)
        end
      end

      it 'rejects extension keys that are not an array of strings' do
        [nil, 'hl7-b2b', [:'hl7-b2b']].each do |value|
          expect { readiness.evaluate!(scopes:, extension_keys: value) }
            .to raise_error(ArgumentError, /extension_keys/)
        end
      end
    end

    describe 'udap_authn profile' do
      [%w[udap_dcr udap_authz], [], nil, 'udap_authn'].each do |profiles|
        it "raises DiscoveryError when udap_profiles_supported is #{profiles.inspect}" do
          overrides['udap_profiles_supported'] = profiles

          expect_discovery_error(/udap_authn profile/)
        end
      end
    end

    describe 'grant_types_supported' do
      [%w[authorization_code refresh_token], [], nil, 'client_credentials'].each do |grants|
        it "raises DiscoveryError when grant_types_supported is #{grants.inspect}" do
          overrides['grant_types_supported'] = grants

          expect_discovery_error(/client_credentials grant in grant_types_supported/)
        end
      end

      it 'checks the requested grant type' do
        overrides['grant_types_supported'] = ['client_credentials']
        auth_code = described_class.new(metadata:, grant_type: 'authorization_code', discovery_endpoint:)

        expect { auth_code.evaluate!(extension_keys: ['hl7-b2b']) }
          .to raise_error(Safire::Errors::DiscoveryError, /authorization_code grant/)
      end
    end

    describe 'token_endpoint' do
      {
        nil => /missing required field 'token_endpoint'/,
        42 => /must be an absolute URI/,
        '' => /must be an absolute URI/,
        '/token' => /must be an absolute URI/,
        'https:///token' => /must be an absolute URI/,
        'http://auth.example.com/token' => /must use HTTPS/,
        'http://localhost:8080/token' => /must use HTTPS/,
        'ftp://auth.example.com/token' => /must use HTTPS/,
        'https://auth.example.com/token#frag' => /must not include a fragment/,
        'https://auth.example.com/token#' => /must not include a fragment/
      }.each do |endpoint, description|
        it "raises DiscoveryError for #{endpoint.inspect}" do
          overrides['token_endpoint'] = endpoint

          expect_discovery_error(description)
        end
      end

      context 'with allow_insecure_localhost' do
        let(:allow_insecure_localhost) { true }

        %w[http://localhost:8080/token http://127.0.0.1/token].each do |endpoint|
          it "accepts the HTTP loopback endpoint #{endpoint}" do
            overrides['token_endpoint'] = endpoint

            expect(evaluate.token_endpoint).to eq(endpoint)
          end
        end

        it 'still rejects a non-loopback HTTP endpoint' do
          overrides['token_endpoint'] = 'http://auth.example.com/token'

          expect_discovery_error(/must use HTTPS/)
        end
      end
    end

    describe 'token_endpoint_auth_methods_supported' do
      [['client_secret_basic'], [], nil, 'private_key_jwt'].each do |methods|
        it "raises DiscoveryError when the value is #{methods.inspect}" do
          overrides['token_endpoint_auth_methods_supported'] = methods

          expect_discovery_error(/array including private_key_jwt/)
        end
      end

      it 'accepts private_key_jwt alongside other methods' do
        overrides['token_endpoint_auth_methods_supported'] = %w[client_secret_basic private_key_jwt]

        expect { evaluate }.not_to raise_error
      end
    end

    describe 'token_endpoint_auth_signing_alg_values_supported' do
      [[], nil, 'RS256', ['RS256', 256]].each do |algorithms|
        it "raises DiscoveryError when the value is #{algorithms.inspect}" do
          overrides['token_endpoint_auth_signing_alg_values_supported'] = algorithms

          expect_discovery_error(/non-empty array of strings/)
        end
      end

      it 'warns without values when RS256 is not advertised' do
        overrides['token_endpoint_auth_signing_alg_values_supported'] = ['ES384']

        expect(evaluate.signing_algorithms).to eq(['ES384'])
        expect(messages).to contain_exactly(
          '[UDAP] token endpoint metadata does not advertise the required RS256 baseline; ' \
          'the token request may proceed only with another advertised, supported, key-compatible algorithm'
        )
      end
    end

    describe 'udap_authz profile' do
      before { overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn] }

      it 'warns for client_credentials and proceeds' do
        expect(evaluate.token_endpoint).to eq(token_endpoint)
        expect(messages).to contain_exactly(
          '[UDAP] udap_profiles_supported does not include udap_authz, which UDAP Security STU2 requires ' \
          'when client_credentials is supported; proceeding with the client_credentials token request'
        )
      end

      it 'does not warn for authorization_code' do
        overrides['udap_authorization_extensions_required'] = []
        auth_code = described_class.new(metadata:, grant_type: 'authorization_code', discovery_endpoint:)

        auth_code.evaluate!(extension_keys: [])

        expect(messages).to be_empty
      end
    end

    describe 'udap_authorization_extensions_required' do
      ['hl7-b2b', [nil], ['hl7-b2b', 1], { 'hl7-b2b' => true }].each do |required|
        it "raises DiscoveryError when the value is #{required.inspect}" do
          overrides['udap_authorization_extensions_required'] = required

          expect_discovery_error(/udap_authorization_extensions_required must be an array of strings/)
        end
      end

      [nil, []].each do |required|
        it "accepts #{required.inspect}" do
          overrides['udap_authorization_extensions_required'] = required

          expect { evaluate }.not_to raise_error
        end
      end

      it 'raises ValidationError naming every missing required key' do
        overrides['udap_authorization_extensions_supported'] = %w[hl7-b2b tefca-ias acme]
        overrides['udap_authorization_extensions_required'] = %w[hl7-b2b tefca-ias acme tefca-ias]

        expect { evaluate }.to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.attribute).to eq(:extensions)
          expect(error.reason).to end_with('missing: tefca-ias, acme')
        }
      end

      it 'raises before scope negotiation and without warnings' do
        overrides['udap_authorization_extensions_required'] = ['tefca-ias']
        overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn]

        expect { readiness.evaluate!(scopes: ['patient/*.rs'], extension_keys:) }
          .to raise_error(Safire::Errors::ValidationError, /tefca-ias/)
        expect(messages).to be_empty
      end
    end

    describe 'udap_authorization_extensions_supported' do
      let(:sensitive_key) { 'acme-tenant-12345' }

      [[], nil, 'hl7-b2b', [nil, 1], ['tefca-ias']].each do |supported|
        it "warns once without values when sent keys are not listed in #{supported.inspect}" do
          overrides['udap_authorization_extensions_supported'] = supported
          overrides['udap_authorization_extensions_required'] = nil

          expect(evaluate.token_endpoint).to eq(token_endpoint)
          expect(messages).to contain_exactly(
            '[UDAP] token request extension count=1 not listed in udap_authorization_extensions_supported; ' \
            'the authorization server MAY ignore unrecognized claims'
          )
        end
      end

      it 'counts only unlisted, deduplicated keys and never logs key names' do
        readiness.evaluate!(scopes:, extension_keys: ['hl7-b2b', sensitive_key, 'other', sensitive_key])

        expect(messages.length).to eq(1)
        expect(messages.first).to include('count=2')
        expect(messages.join).not_to include(sensitive_key)
        expect(messages.join).not_to include('hl7-b2b')
      end

      it 'does not warn when no extension keys are sent and none are required' do
        overrides['udap_authorization_extensions_supported'] = []
        overrides['udap_authorization_extensions_required'] = nil

        readiness.evaluate!(scopes:, extension_keys: [])

        expect(messages).to be_empty
      end
    end

    describe 'scope negotiation' do
      let(:sensitive_scope) { 'system/Observation.rs?patient=mrn-777' }

      it 'raises ValidationError for an unadvertised wildcard' do
        expect { readiness.evaluate!(scopes: ['patient/*.rs'], extension_keys:) }
          .to raise_error(Safire::Errors::ValidationError) { |error| expect(error.attribute).to eq(:scope) }
      end

      it 'raises DiscoveryError for a wildcard when scopes_supported is unusable' do
        overrides['scopes_supported'] = []

        expect { readiness.evaluate!(scopes: ['system/*.rs'], extension_keys:) }
          .to raise_error(Safire::Errors::DiscoveryError, /scopes_supported/) { |error|
            expect(error.endpoint).to eq(discovery_endpoint)
          }
      end

      it 'accepts an advertised wildcard' do
        expect { readiness.evaluate!(scopes: ['system/*.rs'], extension_keys:) }.not_to raise_error
      end

      it 'warns without scope values for uncovered non-wildcard scopes' do
        overrides['scopes_supported'] = ['openid']

        readiness.evaluate!(scopes: [sensitive_scope], extension_keys:)

        expect(messages).to contain_exactly(a_string_including('requested non-wildcard scope count=1'))
        expect(messages.join).not_to include(sensitive_scope)
      end

      it 'skips scope negotiation when scopes are nil for other grants' do
        overrides['scopes_supported'] = []
        overrides['udap_authorization_extensions_required'] = nil
        refresh = described_class.new(metadata:, grant_type: 'refresh_token', discovery_endpoint:)

        expect { refresh.evaluate!(extension_keys: []) }.not_to raise_error
      end
    end

    it 'reports the first hard failure before emitting any readiness warning' do
      overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn]
      overrides['token_endpoint_auth_signing_alg_values_supported'] = ['ES256']
      overrides['token_endpoint'] = 'https://auth.example.com/token#x'

      expect_discovery_error(/fragment/)
      expect(messages).to be_empty
    end

    it 'emits all applicable warnings when the request can proceed' do
      overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn]
      overrides['token_endpoint_auth_signing_alg_values_supported'] = ['ES256']
      overrides['udap_authorization_extensions_supported'] = []
      overrides['udap_authorization_extensions_required'] = nil

      evaluate

      expect(messages.length).to eq(3)
      expect(messages).to all(start_with('[UDAP] '))
      expect(messages.join).not_to include('system/Patient.rs')
    end
  end
end
