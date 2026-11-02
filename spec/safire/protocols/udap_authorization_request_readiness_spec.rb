require 'spec_helper'

RSpec.describe Safire::Protocols::UdapAuthorizationRequestReadiness do
  let(:discovery_endpoint) { 'https://fhir.example.com/.well-known/udap?community=urn%3Aexample%3Acommunity' }
  let(:authorization_endpoint) { 'https://auth.example.com/authorize' }
  let(:allow_insecure_localhost) { false }
  let(:overrides) { {} }
  let(:metadata_hash) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => %w[authorization_code refresh_token],
      'scopes_supported' => %w[openid patient/*.rs],
      'authorization_endpoint' => authorization_endpoint,
      'token_endpoint' => 'https://auth.example.com/token',
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://auth.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256']
    }.merge(overrides)
  end
  let(:metadata) { Safire::Protocols::UdapMetadata.new(metadata_hash, allow_insecure_localhost:) }
  let(:readiness) { described_class.new(metadata:, discovery_endpoint:, allow_insecure_localhost:) }
  let(:scopes) { %w[openid patient/Patient.rs] }
  let(:messages) { [] }

  before do
    allow(Safire.logger).to receive(:warn) { |message| messages << message }
  end

  def evaluate
    readiness.evaluate!(scopes:)
  end

  def expect_discovery_error(description)
    expect { evaluate }.to raise_error(Safire::Errors::DiscoveryError) { |error|
      expect(error.endpoint).to eq(discovery_endpoint)
      expect(error.label).to eq('UDAP metadata')
      expect(error.error_description).to match(description)
    }
  end

  describe '.new' do
    it 'rejects a non-boolean localhost policy' do
      expect { described_class.new(metadata:, discovery_endpoint:, allow_insecure_localhost: 'yes') }
        .to raise_error(Safire::Errors::ConfigurationError)
    end
  end

  describe '#evaluate!' do
    it 'returns the authoritative authorization endpoint unchanged and frozen' do
      overrides['authorization_endpoint'] = 'https://Auth.Example.com:443/oauth/../authorize?tenant=a'

      endpoint = evaluate

      expect(endpoint).to eq('https://Auth.Example.com:443/oauth/../authorize?tenant=a')
      expect(endpoint).to be_frozen
      expect(messages).to be_empty
    end

    it 'does not require token-endpoint readiness metadata' do
      overrides['udap_profiles_supported'] = ['udap_dcr']
      overrides['token_endpoint_auth_methods_supported'] = []

      expect(evaluate).to eq(authorization_endpoint)
    end

    [nil, [], 'patient/*.rs'].each do |value|
      it "rejects scopes #{value.inspect} with ArgumentError" do
        expect { readiness.evaluate!(scopes: value) }
          .to raise_error(ArgumentError, /non-empty scopes array/)
      end
    end

    describe 'grant advertisement' do
      [
        ['omits authorization_code', ['client_credentials']],
        ['is empty', []],
        ['is not an array', 'authorization_code'],
        ['is nil', nil]
      ].each do |label, value|
        it "raises DiscoveryError when grant_types_supported #{label}" do
          overrides['grant_types_supported'] = value

          expect_discovery_error(/does not advertise the authorization_code grant/)
        end
      end
    end

    describe 'authorization endpoint' do
      it 'raises DiscoveryError when missing' do
        overrides.merge!('authorization_endpoint' => nil)

        expect_discovery_error("response missing required field 'authorization_endpoint'")
      end

      [
        ['is not a string', 42, /must be an absolute URI/],
        ['is relative', '/authorize', /must be an absolute URI/],
        ['has no host', 'https:///authorize', /must be an absolute URI/],
        ['uses HTTP', 'http://auth.example.com/authorize', /must use HTTPS/],
        ['uses another scheme', 'ftp://auth.example.com/authorize', /must use HTTPS/],
        ['has a fragment', 'https://auth.example.com/authorize#frag', /must not include a fragment/],
        ['has an empty fragment', 'https://auth.example.com/authorize#', /must not include a fragment/],
        ['uses HTTP loopback without the development policy', 'http://localhost:3000/authorize', /must use HTTPS/]
      ].each do |label, value, description|
        it "raises DiscoveryError when it #{label}" do
          overrides['authorization_endpoint'] = value

          expect_discovery_error(description)
        end
      end

      context 'with allow_insecure_localhost' do
        let(:allow_insecure_localhost) { true }

        it 'accepts an HTTP loopback endpoint' do
          overrides['authorization_endpoint'] = 'http://127.0.0.1:3000/authorize'

          expect(evaluate).to eq('http://127.0.0.1:3000/authorize')
        end

        it 'still rejects a non-loopback HTTP endpoint' do
          overrides['authorization_endpoint'] = 'http://auth.example.com/authorize'

          expect_discovery_error(/must use HTTPS/)
        end
      end
    end

    describe 'Tiered OAuth advertisement' do
      let(:scopes) { %w[openid patient/Patient.rs udap] }

      before do
        overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn udap_to]
        overrides['scopes_supported'] = %w[openid udap patient/*.rs]
      end

      def evaluate_tiered
        readiness.evaluate!(scopes:, tiered_oauth: true)
      end

      it 'returns the endpoint when udap_to and the udap scope are advertised' do
        expect(evaluate_tiered).to eq(authorization_endpoint)
        expect(messages).to be_empty
      end

      [
        ['omits udap_to', %w[udap_dcr udap_authn]],
        ['is empty', []],
        ['is not an array', 'udap_to'],
        ['is nil', nil]
      ].each do |label, value|
        it "raises DiscoveryError when udap_profiles_supported #{label}" do
          overrides['udap_profiles_supported'] = value

          expect { evaluate_tiered }.to raise_error(Safire::Errors::DiscoveryError) { |error|
            expect(error.endpoint).to eq(discovery_endpoint)
            expect(error.error_description)
              .to eq('server does not advertise the udap_to profile in udap_profiles_supported')
          }
        end
      end

      [
        ['omits udap', %w[openid patient/*.rs]],
        ['is empty', []],
        ['is not an array', 'udap'],
        ['is nil', nil],
        ['holds udap only as a prefix', %w[openid udap_scope]]
      ].each do |label, value|
        it "raises DiscoveryError when scopes_supported #{label}" do
          overrides['scopes_supported'] = value

          expect { evaluate_tiered }.to raise_error(Safire::Errors::DiscoveryError) { |error|
            expect(error.endpoint).to eq(discovery_endpoint)
            expect(error.error_description).to eq('server does not advertise the udap scope in scopes_supported')
          }
        end
      end

      it 'checks the authorization grant before Tiered OAuth advertisement' do
        overrides['grant_types_supported'] = ['client_credentials']
        overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn]

        expect { evaluate_tiered }.to raise_error(Safire::Errors::DiscoveryError, /authorization_code grant/)
      end

      it 'does not check Tiered OAuth advertisement for a standard request' do
        overrides['udap_profiles_supported'] = %w[udap_dcr udap_authn]
        overrides['scopes_supported'] = %w[openid patient/*.rs]

        expect(readiness.evaluate!(scopes: %w[openid patient/Patient.rs])).to eq(authorization_endpoint)
      end
    end

    describe 'scope negotiation (warning-only)' do
      let(:lifecycle) do
        'the authorization request proceeds because UDAP Security STU2 scope negotiation ' \
          'names registration and token requests only; the authorization server decides'
      end

      it 'warns without raising for an unadvertised wildcard' do
        expect(readiness.evaluate!(scopes: %w[user/*.rs patient/*.rs])).to eq(authorization_endpoint)

        expect(messages).to contain_exactly(
          "[UDAP] requested wildcard scope count=1; no exact advertisement in scopes_supported; #{lifecycle}"
        )
        expect(messages.join).not_to include('user/')
      end

      it 'warns without raising when scopes_supported is unusable and a wildcard is requested' do
        overrides['scopes_supported'] = nil

        expect(readiness.evaluate!(scopes: %w[patient/*.rs])).to eq(authorization_endpoint)
        expect(messages.first).to start_with('[UDAP] requested wildcard scope count=1; exact advertisement cannot')
      end

      it 'checks discovery readiness before scope negotiation' do
        overrides['grant_types_supported'] = ['client_credentials']

        expect { readiness.evaluate!(scopes: %w[user/*.rs]) }.to raise_error(Safire::Errors::DiscoveryError)
        expect(messages).to be_empty
      end
    end
  end
end
